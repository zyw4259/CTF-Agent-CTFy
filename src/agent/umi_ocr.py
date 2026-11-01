"""Bounded local pipe adapter for the installed Umi-OCR/PaddleOCR-json v1.2 engine."""
import json
import re
import subprocess
import threading
import uuid
from pathlib import Path

ROOT=Path(r'D:\6.Tools\Umi-OCR - 多国语言整合版')/'PaddleOCR-json'
if (Path(__file__).resolve().parent.parent/'tools'/'umi-ocr'/'PaddleOCR_json.exe').is_file():
    ROOT=Path(__file__).resolve().parent.parent/'tools'/'umi-ocr'
ENGINE=ROOT/'PaddleOCR_json.exe'
LANGUAGES={'en':'en','ch':'ch','cht':'chinese_cht','ja':'japan','ko':'korean',
           'ru':'cyrillic','fr':'french(v2)','de':'german(v2)'}
LOCK=threading.Lock()


def status():
    languages=[key for key,value in LANGUAGES.items() if (ROOT/f'PaddleOCR_json_config_{value}.txt').is_file()]
    return {'available':ENGINE.is_file() and 'en' in languages and 'ch' in languages,'languages':languages,'backend':'Umi-OCR / PaddleOCR-json'}


def _recognize(language,targets):
    config=ROOT/f'PaddleOCR_json_config_{LANGUAGES[language]}.txt'
    command=[str(ENGINE),f'--config_path={config.name}','--cpu_threads=2','--enable_mkldnn=false',
             '--use_gpu=false','--use_debug=false','--use_system_pause=false','--ensure_ascii=true','--limit_side_len=1920']
    process=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess,'CREATE_NO_WINDOW') else 0)
    timer=threading.Timer(90,process.kill);timer.daemon=True;timer.start()
    def line():
        raw=process.stdout.readline(512001)
        if not raw:raise ValueError('Umi-OCR引擎退出或超时')
        if len(raw)>512000:raise ValueError('Umi-OCR单行输出超过512KB')
        return raw.decode('utf-8',errors='replace')
    try:
        for _ in range(100):
            if 'OCR init completed.' in line():break
        else:raise ValueError('Umi-OCR未报告初始化完成')
        results=[]
        for label,target in targets:
            # This installed v1.2 build uses image_dir; newer builds use image_path.
            process.stdin.write((json.dumps({'image_dir':str(target)},ensure_ascii=True)+'\n').encode())
            process.stdin.flush()
            result=json.loads(line());code=result.get('code')
            if code not in (100,101):raise ValueError('Umi-OCR识别失败：'+str(result.get('data',''))[:400])
            boxes=[{'text':str(row.get('text',''))[:2000],'score':row.get('score'),'box':row.get('box')}
                   for row in (result.get('data') or [])[:200] if isinstance(row,dict)] if code==100 else []
            text='\n'.join(row['text'] for row in boxes)[:12000]
            results.append({'variant':label,'file':str(target),'language':language,'code':code,'text':text,'boxes':boxes})
            if re.search(r'[A-Za-z][A-Za-z0-9_-]{1,31}\{[^\s{}]{4,128}\}',text):break
        return results
    finally:
        timer.cancel()
        if process.poll() is None:process.kill()
        process.wait(timeout=5)
        process.stdin.close();process.stdout.close()


def image_ocr(case_id,file,args):
    from attachment_tools import case_dir,resolve_file
    from PIL import Image,ImageOps
    source=resolve_file(case_id,file);root=case_dir(case_id)
    language={'zh':'ch','eng':'en'}.get(str(args.get('language','auto')),str(args.get('language','auto')))
    if language!='auto' and language not in status()['languages']:raise ValueError('Umi-OCR不支持此语言配置')
    with Image.open(source) as image:
        if image.width*image.height>20_000_000:raise ValueError('OCR图像像素上限2000万')
        rgb=image.convert('RGB')
    targets=[('original',source)]
    footer=ImageOps.autocontrast(rgb.crop((0,rgb.height*4//5,rgb.width,rgb.height)).getchannel('R'))
    if footer.width*footer.height<=2_000_000:footer=footer.resize((footer.width*2,footer.height*2))
    artifact=root/'output'/f'umi-footer-{uuid.uuid4().hex[:8]}.png';footer.save(artifact)
    targets.append(('footer-red-contrast',artifact))
    results=[]
    with LOCK:
        for selected in (['en','ch'] if language=='auto' else [language]):
            current=_recognize(selected,targets);results.extend(current)
            if any(re.search(r'[A-Za-z][A-Za-z0-9_-]{1,31}\{[^\s{}]{4,128}\}',item['text']) for item in current):break
    for item in results:item['file']=Path(item['file']).relative_to(root).as_posix()
    output='\n'.join(dict.fromkeys(item['text'] for item in results if item['text']))[:16000]
    return {'exit_code':0,'backend':'Umi-OCR / PaddleOCR-json','language':language,'output':output,'variants':results,
            'hint':'文字、置信度和文字框来自本机OCR；相似字符、空格和下划线仍需结合原图核对。'}
