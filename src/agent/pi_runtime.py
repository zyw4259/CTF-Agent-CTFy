"""Local JSONL bridge to the bundled Pi Agent Core, with host-owned CTF tools."""
import json
import os
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
import model_service

BASE=Path(__file__).resolve().parent
RUNTIME=BASE/'runtime'/'pi'
VERSION='0.74.2'
SESSIONS={}
LOCK=threading.Lock()

def node_path():
    bundled=RUNTIME/('node.exe' if os.name=='nt' else 'node')
    return bundled if bundled.is_file() else Path(shutil.which('node')) if shutil.which('node') else None


def status():
    core=RUNTIME/'node_modules'/'@earendil-works'/'pi-agent-core'/'dist'/'index.js'
    return {'name':'Pi Agent Core','version':VERSION,'ready':node_path() is not None and core.is_file() and (RUNTIME/'runner.mjs').is_file()}


def check():
    if not status()['ready']:
        raise RuntimeError('Pi 运行时缺失，请完整复制 runtime/pi 目录')
    result=subprocess.run([str(node_path()),str(RUNTIME/'runner.mjs'),'--check'],
                          capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:
        raise RuntimeError('Pi 无法启动：'+result.stderr.decode('utf-8',errors='replace')[-1200:])
    return json.loads(result.stdout)


def cancel(case_id):
    with LOCK:session=SESSIONS.get(case_id)
    if session:session.close('cancelled')


def close_all():
    with LOCK:sessions=list(SESSIONS.values())
    for session in sessions:session.close('cancelled')


class Session:
    def __init__(self,case_id,max_steps,cancelled,on_event):
        self.case_id=case_id
        self.max_steps=max_steps
        self.cancelled=cancelled
        self.on_event=on_event
        self.process=None
        self.reader=None
        self.pending=None
        self.step_count=0
        self.events=queue.Queue()
        self.closed=False
        self.log=None
        self.write_lock=threading.Lock()
        with LOCK:SESSIONS[case_id]=self

    def send(self,value):
        if self.closed or not self.process or self.process.poll() is not None:
            raise RuntimeError('Pi 进程已停止')
        with self.write_lock:
            self.process.stdin.write(json.dumps(value,ensure_ascii=False)+'\n')
            self.process.stdin.flush()

    def read(self):
        try:
            while True:
                line=self.process.stdout.readline(4*1024*1024)
                if not line:break
                if not line.endswith('\n'):
                    raise RuntimeError('Pi 消息超出长度限制')
                value=json.loads(line)
                if value.get('type')=='session':
                    (BASE/'logs'/'pi'/f'{self.case_id}.json').write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8')
                else:self.events.put(value)
        except Exception as error:
            self.events.put({'type':'error','error':str(error)})
        finally:self.events.put({'type':'eof'})

    def next(self,instruction,context,actions,steps,max_tokens,timeout):
        # These are the old planner's format instructions; Pi uses a native tool call.
        for lead in ('Choose ONE action and return ONLY a JSON object:','Return exactly one JSON action:'):
            start=instruction.find(lead)
            if start>=0:
                end=instruction.find('}.',start)
                instruction=instruction[:start]+'Call the ctf_action tool with exactly one action.'+instruction[end+2:]
        instruction=instruction.replace('Keep the response minimal: one JSON object,','Keep the ctf_action arguments minimal:')
        instruction+='\nUse native ctf_action tool calls, never print action JSON as text. To finish, call ctf_action with action=finish and an answer string. The host supplies actual_results and current_context after each call. Only actual_results are execution evidence; retrieved WP/skills are references. Do not repeat a completed action. Reason <=80 Chinese characters.'
        config={'instruction':instruction,'actions':actions,'max_tokens':max(1200,max_tokens)}
        if self.process is None:
            if not status()['ready']:raise RuntimeError('Pi 运行时缺失，请完整复制 runtime/pi 目录')
            model=json.loads((BASE/'local_model.json').read_text(encoding='utf-8'))
            logs=BASE/'logs'/'pi';logs.mkdir(parents=True,exist_ok=True)
            self.log=(logs/f'{self.case_id}.log').open('w',encoding='utf-8')
            self.process=subprocess.Popen([str(node_path()),str(RUNTIME/'runner.mjs')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,encoding='utf-8',bufsize=1,
                cwd=RUNTIME,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            self.reader=threading.Thread(target=self.read,daemon=True)
            self.reader.start()
            self.send({'type':'start',**config,'model':model['alias'],'base_url':model_service.base_url(),
                       'context_window':model['context'],'max_turns':self.max_steps*2+2,'context':context})
        elif self.pending:
            self.send({'type':'tool_result','id':self.pending,'config':config,'context':context,'results':steps[self.step_count:]})
            self.pending=None
        else:
            self.send({'type':'prompt','config':config,'context':context})
        self.step_count=len(steps)
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if self.cancelled():raise RuntimeError('分析已停止')
            try:value=self.events.get(timeout=.2)
            except queue.Empty:continue
            kind=value.get('type')
            if kind=='tool_call':
                self.pending=value['id']
                choice=value['choice']
                if not isinstance(choice,dict) or choice.get('action') not in actions or not isinstance(choice.get('args',{}),dict):
                    raise RuntimeError('Pi 返回了当前不可用的工具动作')
                choice.setdefault('args',{})
                return choice
            if kind=='final':return {'action':'finish','answer':value.get('answer',''),'args':{}}
            if kind=='event':self.on_event(value)
            if kind=='error':raise RuntimeError('Pi 模型调用失败：'+str(value.get('error',''))[:1200])
            if kind=='eof':raise RuntimeError(f'Pi 进程退出，请查看 logs/pi/{self.case_id}.log')
        raise RuntimeError('Pi 模型规划超时，请查看本题工具记录后重试')

    def close(self,status='stopped'):
        if self.closed:return
        try:
            if self.process and self.process.poll() is None:
                self.send({'type':'stop','status':status})
                try:self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill();self.process.wait(timeout=2)
        except (OSError,RuntimeError):pass
        finally:
            self.closed=True
            if self.reader:self.reader.join(timeout=2)
            if self.process:
                self.process.stdin.close();self.process.stdout.close()
            if self.log:self.log.close()
            with LOCK:
                if SESSIONS.get(self.case_id) is self:SESSIONS.pop(self.case_id,None)
