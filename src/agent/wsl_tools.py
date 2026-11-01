"""Fixed-argument WSL tools; no arbitrary shell or uploaded program execution."""
import functools
import json
import re
import shutil
import subprocess
import uuid
import urllib.parse
import urllib.request
from pathlib import Path

TOOLS = {'file', 'strings', 'readelf', 'objdump', 'nm', 'tshark', 'python3', 'gdb', 'bwrap', 'mmls', 'fls', 'icat', 'vol'}
TOOLS.update({'exiftool','ffmpeg','ffprobe','foremost','steghide','testdisk','pcapfix','zsteg','qrencode','hashcat','john','zip2john','hashid','hash_extender','radare2','rabin2','apktool','upx','strace','ltrace','qemu-x86_64','qemu-system-x86_64','yara','ROPgadget','ropper','one_gadget','seccomp-tools','pycdc','pycdas','ffuf','frida','RsaCtfTool','java'})
MODULES=('angr','pwn','torch','volatility3','sympy','z3','Crypto','gmpy2','fpylll','py_ecc','cysignals','numpy','scipy','PIL','safetensors','sklearn','transformers','matplotlib','yara','pefile','capstone','oletools','unicorn','dissect.cobaltstrike','dnslib','shodan','ropper','frida','uncompyle6','lief','flask_unsign')
TOOLS.update({'jadx','pngcheck','zbarimg','fcrackzip','stegseek','magick'})
NATIVE_PATH='/opt/ctf-agent/venv/bin:/opt/ctf-agent/rsa-venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/bin:/opt/ctf-agent/sage/bin:/opt/ctf-agent/image-tools/bin'
SANDBOX_ACTIONS = {'wsl_tshark','wsl_gdb_run','wsl_angr_cfg','wsl_pwn_checksec','wsl_torch_summary','wsl_vol_info','wsl_vol_pslist','wsl_vol_pstree','wsl_vol_cmdline','wsl_vol_netscan','wsl_mmls','wsl_fls','wsl_icat'}
MATH_MODULES=('sympy','z3','Crypto')
SANDBOX_ACTIONS.add('wsl_vol_envars')
SANDBOX_PYTHON = '/opt/ctf-agent/venv/bin/python'

def decode(data):
    sample=data[:512]
    if sample and sample.count(b'\x00')>len(sample)//8:
        return data.decode('utf-16le', errors='replace').replace('\ufeff','')
    for encoding in ('utf-8', 'utf-16le', 'gb18030'):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode('utf-8', errors='replace')

def linux_path(path):
    value=str(Path(path).resolve()).replace('\\','/')
    if not re.match(r'^[A-Za-z]:/',value):
        raise ValueError('WSL 桥接只支持 Windows 本地磁盘路径')
    return '/mnt/'+value[0].lower()+value[2:]

def _probe(distro=None):
    probe='''import importlib.util,json,os,shutil,subprocess
def has(name):
 try: return bool(importlib.util.find_spec(name))
 except (ImportError,ValueError): return False
tools={x:shutil.which(x,path='''+repr(NATIVE_PATH)+''') for x in '''+repr(sorted(TOOLS))+'''}
modules={x:has(x) for x in '''+repr(MODULES)+'''}
venv='''+repr(SANDBOX_PYTHON)+'''
if os.path.isfile(venv):
 try:
  code="import importlib.util,json\\ndef has(n):\\n try:return bool(importlib.util.find_spec(n))\\n except (ImportError,ValueError):return False\\nprint(json.dumps({n:has(n) for n in "+repr('''+repr(MODULES)+''')+"}))"
  raw=subprocess.check_output([venv,'-c',code],stderr=subprocess.DEVNULL,timeout=8)
  modules.update(json.loads(raw))
 except Exception: pass
runtimes={name:path for name,path in {'sage':'/opt/ctf-agent/sage/bin/python','qiling':'/opt/ctf-agent/qiling-venv/bin/python','qiling_rootfs':'/opt/ctf-agent/qiling-rootfs/x8664_linux','ghidra':'/usr/share/ghidra/support/analyzeHeadless'}.items() if os.path.exists(path)}
print(json.dumps({'tools':tools,'modules':modules,'runtimes':runtimes}))'''
    command=['wsl.exe']
    if distro:
        command+=['--distribution',distro]
    command+=['--exec','python3','-c',probe]
    try:
        r=subprocess.run(command,capture_output=True,timeout=12)
        if r.returncode:
            return {'ready':False,'distro':distro,'message':decode(r.stdout+r.stderr)[:500],'tools':[],'modules':{}}
        found=json.loads(decode(r.stdout))
        return {'ready':True,'distro':distro or '默认WSL','message':'WSL 已连接',
                'tools':[x for x,p in found['tools'].items() if p],'modules':found['modules'],'runtimes':found.get('runtimes',{})}
    except (OSError,subprocess.TimeoutExpired,ValueError,KeyError) as e:
        return {'ready':False,'distro':distro,'message':str(e)[:500],'tools':[],'modules':{}}

@functools.lru_cache(maxsize=1)
def status():
    if not shutil.which('wsl'):
        return {'ready':False,'message':'未找到 wsl.exe','tools':[],'sandbox_ready':False,'sandbox_tools':[],'modules':{}}
    default=_probe()
    kali=_probe('kali-linux')
    candidates=[default,kali]
    sandbox=next((entry for entry in candidates if entry['ready'] and {'gdb','bwrap'}<=set(entry['tools'])),None)
    return {'ready':default['ready'],'message':default['message'],'distro':default['distro'],'tools':default['tools'],
            'sandbox_ready':sandbox is not None,'sandbox_distro':sandbox['distro'] if sandbox else None,
            'sandbox_tools':sandbox['tools'] if sandbox else [],'modules':sandbox['modules'] if sandbox else {},
            'runtimes':sandbox.get('runtimes',{}) if sandbox else {},
            'sandbox_message':sandbox['message'] if sandbox else '需要同一 WSL 发行版安装 gdb 与 bubblewrap'}

def _sandbox_prefix(root,cache=None,share_network=False):
    input_dir=linux_path(root/'input')
    output_dir=linux_path(root/'output')
    argv=['bwrap','--unshare-all']
    if share_network:
        argv+=['--share-net']
    argv+=['--die-with-parent','--new-session','--cap-drop','ALL','--ro-bind','/','/',
          '--tmpfs','/tmp','--dir','/tmp/input','--ro-bind',input_dir,'/tmp/input',
          '--dir','/tmp/output','--bind',output_dir,'/tmp/output']
    if cache:
        cache.mkdir(parents=True,exist_ok=True)
        argv+=['--dir','/tmp/cache','--bind',linux_path(cache),'/tmp/cache']
    argv+=['--tmpfs','/mnt','--tmpfs','/home','--tmpfs','/root']
    argv+=['--tmpfs','/run','--tmpfs','/sys',
           '--proc','/proc','--dev','/dev','--chdir','/tmp/input','--clearenv','--setenv','PATH',NATIVE_PATH,
           '--setenv','HOME','/root','--setenv','LANG','C.UTF-8','--setenv','TERM','xterm','--']
    return argv

def _run_supervised(distro,root,argv,stdin=b'',timeout=60,memory_mb=2048,output_limit=64000,output_file=None,cwd=None,open_files=128):
    supervisor='''import os,resource,signal,subprocess,sys
seconds=int(sys.argv[1]); memory=int(sys.argv[2]); limit=int(sys.argv[3]); feed=sys.argv[4]=='1'; target=sys.argv[5]; files=int(sys.argv[6]); argv=sys.argv[7:]
resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
resource.setrlimit(resource.RLIMIT_CPU,(seconds+5,seconds+5))
resource.setrlimit(resource.RLIMIT_FSIZE,(1073741824,1073741824))
resource.setrlimit(resource.RLIMIT_NOFILE,(files,files))
sink=open(target,'wb') if target!='-' else None
p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=sink or subprocess.PIPE,stderr=subprocess.DEVNULL if sink else subprocess.STDOUT,start_new_session=True)
def stop(*a):
 try: os.killpg(p.pid,signal.SIGKILL)
 except ProcessLookupError: pass
signal.signal(signal.SIGALRM,stop); signal.alarm(seconds)
if feed:
 p.stdin.write(sys.stdin.buffer.read())
p.stdin.close()
if sink:
 code=p.wait()
 sink.close()
 print(os.stat(target).st_size)
else:
 data=p.stdout.read(limit+1)
 if len(data)>limit: stop()
 code=p.wait()
 sys.stdout.buffer.write(data[:limit]); sys.stdout.buffer.flush()
signal.alarm(0)
sys.exit(code)
'''
    command=['wsl.exe']
    if distro and distro!='默认WSL':
        command+=['--distribution',distro]
    command+=['--cd',linux_path(cwd) if cwd else '/', '--exec','python3','-I','-c',supervisor,str(timeout),str(memory_mb*1024*1024),str(output_limit),
              '1' if stdin else '0',linux_path(output_file) if output_file else '-',str(open_files),*argv]
    try:
        response=subprocess.run(command,input=stdin,capture_output=True,timeout=timeout+15)
        text=(decode(response.stdout)+decode(response.stderr))[:16000]
        return {'exit_code':response.returncode,'output':text,'backend':f'WSL {distro or "default"}',
                'timeout':response.returncode in {-9,247},'command':argv}
    except subprocess.TimeoutExpired as e:
        return {'exit_code':None,'output':(decode(e.stdout or b'')+decode(e.stderr or b''))[:16000],
                'backend':f'WSL {distro or "default"}','timeout':True,'command':argv}

def _cache_vol_symbols(distro,root,cache,output):
    # WSL may not share the Windows proxy. Fetch only the named public Microsoft PDB.
    match=re.search(r'https://msdl\.microsoft\.com/download/symbols/([A-Za-z0-9_.-]+\.pdb)/([A-Fa-f0-9]{32})([0-9]{1,8})/',output)
    if not match:
        return None
    name,guid,age=match.groups()
    url=f'https://msdl.microsoft.com/download/symbols/{name}/{guid}{age}/{name}'
    pdb=cache/f'{guid}-{age}.pdb'
    target=cache/'symbols'/'windows'/name/f'{guid}-{age}.json.xz'
    target.parent.mkdir(parents=True,exist_ok=True)
    try:
        with urllib.request.urlopen(url,timeout=45) as response:
            destination=urllib.parse.urlsplit(response.geturl())
            if destination.scheme!='https' or not re.fullmatch(r'msdl\.microsoft\.com|vsblobprod[a-z0-9]+\.blob\.core\.windows\.net',destination.hostname or ''):
                raise ValueError('符号下载重定向离开微软官方HTTPS服务')
            data=response.read(64*1024*1024+1)
        if len(data)>64*1024*1024 or not data.startswith(b'Microsoft C/C++ MSF'):
            raise ValueError('PDB格式无效或超过64MB限制')
        pdb.write_bytes(data)
        code='import sys,json,lzma; from pathlib import Path; from volatility3.framework import contexts; from volatility3.framework.symbols.windows.pdbconv import PdbReader; data=PdbReader(contexts.Context(),Path(sys.argv[1]).as_uri(),sys.argv[3]).get_json(); f=lzma.open(sys.argv[2],"wt",encoding="utf-8"); json.dump(data,f); f.close(); print(json.dumps(data["metadata"]))'
        argv=_sandbox_prefix(root,cache)+[SANDBOX_PYTHON,'-I','-c',code,
              '/tmp/cache/'+pdb.name,'/tmp/cache/symbols/windows/'+name+'/'+target.name,name]
        result=_run_supervised(distro,root,argv,timeout=240,memory_mb=4096)
        return {'url':url,'pdb_bytes':len(data),'converted':result['exit_code']==0 and target.is_file(),
                'output':result.get('output','')[-1600:]}
    except Exception as e:
        return {'url':url,'converted':False,'error':str(e)[:500]}


def run_math(case_id,args,action='wsl_math'):
    import attachment_tools as tools
    env=status()
    missing=[name for name in MATH_MODULES if not env.get('modules',{}).get(name)] if action!='wsl_sage' else ([] if env.get('runtimes',{}).get('sage') else ['SageMath'])
    if not env.get('sandbox_ready') or missing:
        raise ValueError('隔离数学环境未就绪；缺少库：'+', '.join(missing))
    code=args.get('code','')
    if not isinstance(code,str) or not code.strip() or len(code)>12000:
        raise ValueError('数学脚本应为1到12000字符')
    root=tools.case_dir(case_id)
    token=uuid.uuid4().hex[:8]
    script=root/'output'/f'math_analysis_{token}.py'
    worker=root/'output'/f'.math-worker-{token}.py'
    script.write_text(code,encoding='utf-8')
    worker.write_bytes((tools.BASE/'python_worker.py').read_bytes())
    argv=_sandbox_prefix(root)
    argv[argv.index('--chdir')+1]='/tmp'
    for name,value in {'TMPDIR':'/tmp/output','SAGE_DOT_SAGE':'/tmp/output/.sage','DOT_SAGE':'/tmp/output/.sage','MPLCONFIGDIR':'/tmp/output/.mpl','HF_HOME':'/tmp/output/.hf','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','OPENBLAS_NUM_THREADS':'2','OMP_NUM_THREADS':'2','SAGE_NUM_THREADS':'2'}.items():
        argv[-1:-1]=['--setenv',name,value]
    python=env['runtimes']['sage'] if action=='wsl_sage' else SANDBOX_PYTHON
    mode={'wsl_math':'--math-sandbox','wsl_sage':'--sage-sandbox','wsl_analysis':'--analysis-sandbox'}[action]
    argv += [python,'-I','/tmp/output/'+worker.name,'/tmp','/tmp/output/'+script.name,mode]
    result=_run_supervised(env['sandbox_distro'],root,argv,stdin=b'RUN\n',timeout=180 if action=='wsl_sage' else 120 if action=='wsl_analysis' else 90,memory_mb=4096 if action!='wsl_math' else 2048)
    result['script']=script.relative_to(root).as_posix()
    result['math_modules']=['sage'] if action=='wsl_sage' else list(MATH_MODULES)
    result['runtime']=action
    result['sandboxed']=True
    result['files']=tools.manifest(case_id)
    return result


def execute(case_id, action, file, args, allow_execution=False, allow_symbol_download=False):
    import attachment_tools as tools
    import wsl_extended
    if action in wsl_extended.ACTIONS:
        return wsl_extended.execute(case_id,action,file,args,allow_execution)
    if action in {'wsl_math','wsl_sage','wsl_analysis'}:
        return run_math(case_id,args,action)
    allow_execution=allow_execution is True
    allow_symbol_download=allow_symbol_download is True
    env=status()
    if not env['ready']:
        raise ValueError('WSL 尚不可用，请安装发行版及 python3，参见 WSL-SETUP.md。'+env['message'])
    root=tools.case_dir(case_id)
    args=args or {}
    script=None
    output_file=None
    cache=None
    stdin=b''
    sandboxed=action in SANDBOX_ACTIONS
    readonly_mount=None
    if sandboxed and not env.get('sandbox_ready',False):
        raise ValueError('需要在同一 WSL 发行版安装 gdb 与 bubblewrap；参见 WSL-SETUP.md。'+env.get('sandbox_message',''))
    if action=='wsl_gdb_run' and 'gdb' not in env.get('sandbox_tools',[]):
        raise ValueError('隔离发行版未找到 GDB；运行 WSL-SETUP.md 的基础工具安装命令')
    distro=env.get('sandbox_distro') if sandboxed else env.get('distro','默认WSL')
    available=set(env.get('sandbox_tools',[]) if sandboxed else env.get('tools',[]))
    sandbox_prefix=None
    if action=='wsl_python':
        code=args.get('code','')
        if not isinstance(code,str) or len(code)>12000:
            raise ValueError('脚本过长')
        script=root/'output'/('wsl_analysis_'+uuid.uuid4().hex[:8]+'.py')
        script.write_text(code,encoding='utf-8')
        argv=['python3','-I','-S',linux_path(tools.BASE/'python_worker.py'),linux_path(root),linux_path(script)]
        stdin=b'RUN\n'
    else:
        target=tools.resolve_file(case_id,file)
        if sandboxed and target.is_relative_to(root/'input'):
            path='/tmp/input/'+target.relative_to(root/'input').as_posix()
        elif sandboxed and action!='wsl_gdb_run' and target.is_relative_to(root/'output'):
            relative=target.relative_to(root/'output')
            if not relative.parts or not relative.parts[0].startswith('extracted_'):
                raise ValueError('隔离静态工具只接受 input/附件或 ZIP 解压成员')
            mounted_name='extracted-'+uuid.uuid4().hex[:12]+(target.suffix or '.bin')
            path='/tmp/extracted/'+mounted_name
            readonly_mount=(linux_path(target),path)
        elif sandboxed:
            raise ValueError('隔离工具只接受 input/附件；静态分析也可读取 ZIP 解压成员')
        else:
            path=linux_path(target)
        disasm_address=max(0,int(str(args.get('address',0)),0)) if action=='wsl_objdump' else 0
        disasm_size=min(max(int(args.get('size',2048)),64),4096) if action=='wsl_objdump' else 2048
        mapping={
            'wsl_file':['file','--',path],
            'wsl_strings':['strings','-t','x','-n',str(min(max(int(args.get('minimum',4)),4),16)),'--',path],
            'wsl_readelf':['readelf','-h','-S','-s','-W','--',path],
            'wsl_objdump':['objdump','-d','--start-address='+str(disasm_address), '--stop-address='+str(disasm_address+disasm_size),'--',path],
            'wsl_nm':['nm','-C','--',path],
            'wsl_tshark':['tshark','-r',path,'-c',str(min(max(int(args.get('packets',100)),1),1000)),'-T','fields','-e','frame.number','-e','ip.src','-e','ip.dst','-e','_ws.col.Protocol','-e','_ws.col.Info'],
            'wsl_mmls':['mmls',path],
        }
        if action=='wsl_fls':
            offset=max(0,min(int(args.get('offset',0)),2**31-1))
            argv=['fls','-r','-p','-o',str(offset),path]
        elif action=='wsl_icat':
            offset=max(0,min(int(args.get('offset',0)),2**31-1))
            inode=str(args.get('inode',''))
            if not re.fullmatch(r'\d+(?:-\d+)?',inode):
                raise ValueError('icat 需要 fls 输出中的纯数字 inode')
            out_name='icat_'+uuid.uuid4().hex[:8]+'.bin'
            output_file=root/'output'/out_name
            argv=['icat','-r','-o',str(offset),path,inode]
        elif action=='wsl_gdb_run':
            if not allow_execution:
                raise ValueError('请先勾选“允许隔离运行上传程序”')
            argv_args=args.get('argv',[])
            if not isinstance(argv_args,list) or len(argv_args)>32 or any(not isinstance(x,str) or len(x)>512 or '\x00' in x for x in argv_args):
                raise ValueError('程序参数需为最多32个、每个不超过512字符的文本')
            stdin_file=args.get('stdin_file')
            run_cmd='run'
            if stdin_file:
                input_path=tools.resolve_file(case_id,str(stdin_file))
                if not input_path.is_relative_to(root/'input'):
                    raise ValueError('GDB 标准输入只能选择 input/ 中的附件')
                run_cmd+=' < /tmp/input/'+input_path.name
            script=root/'output'/('gdb_'+uuid.uuid4().hex[:8]+'.cmd')
            script.write_text('set pagination off\nset confirm off\nset disable-randomization off\n'+run_cmd+
                              '\nif $_isvoid($_exitcode)\n  bt\n  info registers\nend\n',encoding='utf-8')
            argv=['gdb','--quiet','--batch','--nx','-x','/tmp/output/'+script.name,'--args',path,*argv_args]
        elif action=='wsl_pwn_checksec':
            if not env['modules'].get('pwn'):
                raise ValueError('WSL sandbox 尚未安装 pwntools；运行 WSL-SETUP.md 的扩展工具安装命令')
            code='import json,sys; from pwn import context,ELF; context.log_level="error"; print(json.dumps(ELF(sys.argv[1],checksec=False).checksec()))'
            argv=[SANDBOX_PYTHON,'-I','-c',code,path]
        elif action=='wsl_angr_cfg':
            if not env['modules'].get('angr'):
                raise ValueError('WSL sandbox 尚未安装 angr；运行 WSL-SETUP.md 的扩展工具安装命令')
            code='import angr,json,sys; p=angr.Project(sys.argv[1],auto_load_libs=False); c=p.analyses.CFGFast(normalize=True); f=sorted(p.kb.functions.values(),key=lambda x:x.addr); print(json.dumps({"functions":len(f),"blocks":c.graph.number_of_nodes(),"functions_preview":[{"address":hex(x.addr),"name":x.name} for x in f[:300]]}))'
            argv=[SANDBOX_PYTHON,'-I','-c',code,path]
        elif action.startswith('wsl_vol_'):
            if not env['modules'].get('volatility3'):
                raise ValueError('WSL sandbox 尚未安装 Volatility 3；运行 WSL-SETUP.md 的扩展工具安装命令')
            plugins={'wsl_vol_info':'windows.info','wsl_vol_pslist':'windows.pslist','wsl_vol_pstree':'windows.pstree','wsl_vol_cmdline':'windows.cmdline','wsl_vol_netscan':'windows.netscan','wsl_vol_envars':'windows.envars'}
            plugin=plugins.get(action)
            if not plugin:
                raise ValueError('不支持的 Volatility 插件')
            cache=tools.CASES/'_shared'/'volatility3'
            (cache/'symbols').mkdir(parents=True,exist_ok=True)
            code='import sys; sys.argv[0]="vol"; from volatility3.framework import constants; constants.SYMBOL_SERVER_URL="https://msdl.microsoft.com/download/symbols"; import volatility3.cli; volatility3.cli.main()'
            argv=[SANDBOX_PYTHON,'-I','-c',code,'-f',path,'--cache-path','/tmp/cache','--symbol-dirs','/tmp/cache/symbols']
            if not allow_symbol_download:
                argv+=['--offline']
            if action=='wsl_vol_envars':
                argv+=['-r','json']
                output_file=root/'output'/f'environment-{uuid.uuid4().hex[:8]}.json'
            argv.append(plugin)
            if action=='wsl_vol_envars' and args.get('pid') is not None:
                pids=args['pid'] if isinstance(args['pid'],list) else [args['pid']]
                if not 1<=len(pids)<=32 or any(not str(pid).isdigit() or not 1<=int(pid)<=2**31-1 for pid in pids):
                    raise ValueError('环境变量PID需要1到32个有效正整数')
                argv+=['--pid',*[str(pid) for pid in pids]]
        elif action=='wsl_torch_summary':
            if not env['modules'].get('torch'):
                raise ValueError('WSL sandbox 尚未安装 PyTorch；请按 WSL-SETUP.md 的 AI 扩展说明配置')
            code='''import json,sys,torch,numpy as np
p=sys.argv[1]
unsafe=torch.serialization.get_unsafe_globals_in_checkpoint(p)
allowed={'numpy.dtype':np.dtype,'numpy._core.multiarray.scalar':np._core.multiarray.scalar,'numpy.core.multiarray.scalar':np._core.multiarray.scalar}
unknown=sorted(set(unsafe)-set(allowed))
if unknown: raise ValueError('checkpoint contains unsupported globals: '+json.dumps(unknown))
safe=[allowed[x] for x in unsafe]+[np.dtypes.Float64DType]
with torch.serialization.safe_globals(safe):
 x=torch.load(p,map_location='cpu',weights_only=True)
def s(v,d=0):
 if d>8: return {'type':'truncated'}
 if isinstance(v,torch.Tensor): return {'type':'Tensor','shape':list(v.shape),'dtype':str(v.dtype),'elements':v.numel()}
 if isinstance(v,dict): return {'type':'dict','count':len(v),'items':{str(k)[:160]:s(y,d+1) for k,y in list(v.items())[:200]}}
 if isinstance(v,(list,tuple)): return {'type':type(v).__name__,'count':len(v),'items':[s(y,d+1) for y in v[:100]]}
 if isinstance(v,(str,int,float,bool)) or v is None: return v if not isinstance(v,str) else v[:200]
 return {'type':type(v).__name__}
print(json.dumps({'unsafe_globals':unsafe,'summary':s(x)},ensure_ascii=False))'''
            argv=[SANDBOX_PYTHON,'-I','-c',code,path]
        elif action not in mapping:
            raise ValueError('不支持的 WSL 工具')
        else:
            argv=mapping[action]
        if sandboxed:
            sandbox_prefix=_sandbox_prefix(root,cache,share_network=allow_symbol_download and action.startswith('wsl_vol_'))
            if readonly_mount:
                mount_index=sandbox_prefix.index('/mnt')-1
                sandbox_prefix[mount_index:mount_index]=['--dir','/tmp/extracted','--ro-bind',readonly_mount[0],readonly_mount[1]]
            argv=sandbox_prefix+argv
    executable=argv[0]
    if not sandboxed and action!='wsl_python' and executable not in available:
        raise ValueError('WSL 内未安装 '+executable+'；可在 WSL-SETUP.md 查看安装方法')
    if sandboxed and action in {'wsl_tshark','wsl_mmls','wsl_fls','wsl_icat'} and executable not in set(env.get('sandbox_tools',[])):
        raise ValueError('WSL 隔离发行版未安装 '+executable+'；运行 WSL-SETUP.md 的基础工具安装命令')
    timeout=600 if action.startswith('wsl_vol_') else 240 if action=='wsl_angr_cfg' else 120 if action=='wsl_gdb_run' else 300 if action in {'wsl_mmls','wsl_fls','wsl_icat','wsl_strings','wsl_tshark'} else 60
    memory=4096 if action.startswith('wsl_vol_') or action=='wsl_angr_cfg' else 2048 if action in {'wsl_gdb_run','wsl_torch_summary'} else 1024
    result=_run_supervised(distro,root,argv,stdin=stdin,timeout=timeout,memory_mb=memory,output_file=output_file,
                           cwd=root if action=='wsl_python' else None)
    if action=='wsl_vol_info' and allow_symbol_download and result['exit_code']!=0:
        prepared=_cache_vol_symbols(distro,root,cache,result.get('output',''))
        if prepared:
            if prepared.get('converted'):
                result=_run_supervised(distro,root,argv,timeout=timeout,memory_mb=memory)
            result['symbol_setup']=prepared
    result['sandboxed']=sandboxed
    if script:
        result['script']=script.relative_to(root).as_posix()
    if output_file:
        if result['exit_code']==0:
            result['artifact']=output_file.relative_to(root).as_posix()
            result['bytes']=output_file.stat().st_size
            if action=='wsl_vol_envars' and output_file.stat().st_size<=16*1024*1024:
                try:
                    pending=json.loads(output_file.read_text(encoding='utf-8'))
                    if isinstance(pending,dict):pending=[pending]
                    rows=[]
                    while pending:
                        row=pending.pop()
                        if not isinstance(row,dict):continue
                        pending.extend(row.get('__children',[]))
                        rows.append({k:v for k,v in row.items() if k!='__children'})
                    interesting=[row for row in rows if re.search(r'(?i)flag|ctf|secret|password',str(row))]
                    result['rows']=interesting[:80] if interesting else rows[:40]
                    result['total_rows']=len(rows)
                    result['output']=json.dumps(result['rows'],ensure_ascii=False)
                    if not rows:result['hint']='未提取到环境变量；不能据此判定题目已解。请检查进程链、镜像采集情况，或用search_bytes分块搜索原始UTF-16LE文本。'
                except (ValueError,UnicodeDecodeError):
                    result['parse_error']='环境变量JSON解析失败，请查看产物文件'
        else:
            output_file.unlink(missing_ok=True)
            if action=='wsl_vol_envars':result['hint']='请先用wsl_vol_info检查符号表与镜像识别情况。'
    result['files']=tools.manifest(case_id)
    return result
