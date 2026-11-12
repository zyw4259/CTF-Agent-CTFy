"""Small allowlisted adapters for installed, non-interactive CTF utilities."""
import shutil
import subprocess
import sys
import uuid
import re
import importlib.util
from pathlib import Path
from attachment_tools import BASE

TOOLS_ROOT = BASE.parent.parent.parent
BINWALK = TOOLS_ROOT / '3.Misc-tools' / 'binwalk.exe'
STEGOVERITAS = TOOLS_ROOT / '3.Misc-tools' / '[随波逐流]CTF编码工具_V8.0.0_Release_20261010' / '[随波逐流]CTF编码工具_V8.0.0_Release_20261010.exe'
MAX_STEGOVERITAS_FILE = 128 * 1024 * 1024
YAFU = TOOLS_ROOT / '2.Crypto-tools' / 'RSA_分解N_工具' / 'yafu' / 'yafu-x64.exe'
TESSERACT = TOOLS_ROOT / '3.Misc-tools' / 'Autopsy' / 'autopsy' / 'Tesseract-OCR' / 'tesseract.exe'
PYZBAR_PACKAGE = TOOLS_ROOT / '免授权' / 'RAG检索增强' / '_internal' / 'pyzbar'
PORTABLE_TOOLS=BASE.parent/'tools'
if (PORTABLE_TOOLS/'binwalk.exe').is_file():BINWALK=PORTABLE_TOOLS/'binwalk.exe'
if (PORTABLE_TOOLS/'stegoveritas'/STEGOVERITAS.name).is_file():STEGOVERITAS=PORTABLE_TOOLS/'stegoveritas'/STEGOVERITAS.name
if (PORTABLE_TOOLS/'yafu'/'yafu-x64.exe').is_file():YAFU=PORTABLE_TOOLS/'yafu'/'yafu-x64.exe'
if (PORTABLE_TOOLS/'tesseract'/'tesseract.exe').is_file():TESSERACT=PORTABLE_TOOLS/'tesseract'/'tesseract.exe'
if (PORTABLE_TOOLS/'pyzbar').is_dir():PYZBAR_PACKAGE=PORTABLE_TOOLS/'pyzbar'


def _tesseract_bin():
    if TESSERACT.is_file():
        return TESSERACT
    found=shutil.which('tesseract')
    return Path(found) if found else None


def _binwalk_bin():
    found=shutil.which('binwalk')
    if found:
        return Path(found)
    return BINWALK if BINWALK.is_file() else None


def _qr_package():
    bundled=(PYZBAR_PACKAGE/'pyzbar.py').is_file() and (PYZBAR_PACKAGE/'libzbar-64.dll').is_file()
    return bundled or importlib.util.find_spec('pyzbar') is not None


def status():
    import umi_ocr
    umi=umi_ocr.status()['available']
    tesseract=_tesseract_bin()
    return {'binwalk': _binwalk_bin() is not None, 'foremost': shutil.which('foremost') is not None, 'stegoveritas': STEGOVERITAS.is_file(),
            'yafu':YAFU.is_file(),'lll':bool(importlib.util.find_spec('flint')),'umi_ocr':umi,'image_ocr':(umi or tesseract is not None) and bool(importlib.util.find_spec('PIL')),
            'image_qr':_qr_package()}


def factor_integer(case_id,value):
    from attachment_tools import case_dir,limit_windows_process
    if type(value) is not int or not 2<value or value.bit_length()>320:
        raise ValueError('YAFU只接受320位以内的正整数')
    if not YAFU.is_file():
        return {'factors':[],'available':False}
    root=case_dir(case_id)
    work=root/'output'/f'yafu-{uuid.uuid4().hex[:8]}'
    work.mkdir()
    log=work/'factor-output.log'
    timed_out=False
    with log.open('wb') as stream:
        process=subprocess.Popen([str(YAFU),f'factor({value})','-threads','2'],cwd=work,stdin=subprocess.DEVNULL,
            stdout=stream,stderr=subprocess.STDOUT,shell=False,creationflags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0)
        cleanup=limit_windows_process(process)
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill();process.wait();timed_out=True
        finally:
            if cleanup:cleanup()
    output=_tail(log)
    remaining=value
    factors=[]
    for factor in sorted({int(x) for x in re.findall(r'\b(?:P|PRP)\d+\s*=\s*(\d+)',output,re.I)}):
        while factor>1 and remaining%factor==0:
            factors.append(factor);remaining//=factor
    return {'factors':factors if remaining==1 else [],'factor_product_verified':remaining==1,
            'timeout':timed_out,'exit_code':process.returncode,'log_file':log.relative_to(root).as_posix(),'output':output[-2000:]}


def image_ocr(case_id,file,args):
    import umi_ocr
    if umi_ocr.status()['available']:
        try:return umi_ocr.image_ocr(case_id,file,args)
        except (OSError,ValueError,subprocess.SubprocessError) as e:
            if not TESSERACT.is_file():raise ValueError('Umi-OCR调用失败：'+str(e)) from e
            result=_tesseract_ocr(case_id,file,args)
            result['fallback_reason']='Umi-OCR失败，回退英文Tesseract：'+str(e)[:500]
            return result
    return _tesseract_ocr(case_id,file,args)


def _tesseract_ocr(case_id,file,args):
    from attachment_tools import case_dir,resolve_file
    from PIL import Image,ImageOps
    source=resolve_file(case_id,file)
    tesseract=_tesseract_bin()
    if tesseract is None:raise ValueError('未找到本机Tesseract')
    with Image.open(source) as image:
        if image.width*image.height>20_000_000:raise ValueError('OCR图像像素上限2000万')
        rgb=image.convert('RGB')
    psm=int(args.get('psm',11))
    if psm not in (6,11,12):raise ValueError('OCR psm仅支持6、11、12')
    root=case_dir(case_id)
    results=[]
    variants=[('original',None,psm),('footer-red-contrast',rgb.crop((0,rgb.height*4//5,rgb.width,rgb.height)).getchannel('R'),6),
              ('grayscale-contrast',ImageOps.grayscale(rgb),11)]
    for label,variant,mode in variants:
        target=source
        if variant is not None:
            target=root/'output'/f'ocr-{label}-{uuid.uuid4().hex[:8]}.png'
            variant=ImageOps.autocontrast(variant)
            if variant.width*variant.height<=2_000_000:
                variant=variant.resize((variant.width*2,variant.height*2))
            variant.save(target)
        command=[str(tesseract),str(target),'stdout','-l','eng','--psm',str(mode)]
        tessdata=tesseract.parent/'tessdata'
        if tessdata.is_dir():command[3:3]=['--tessdata-dir',str(tessdata)]
        result=subprocess.run(command,cwd=root,stdin=subprocess.DEVNULL,capture_output=True,
            timeout=30,shell=False,creationflags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0)
        text=result.stdout[:12000].decode('utf-8',errors='replace')
        results.append({'variant':label,'file':target.relative_to(root).as_posix(),'exit_code':result.returncode,
            'text':text,'diagnostic':result.stderr[:500].decode('utf-8',errors='replace')})
        if re.search(r'[A-Za-z][A-Za-z0-9_-]{1,31}\{[^\s{}]{4,128}\}',text):break
    return {'exit_code':results[-1]['exit_code'],'output':'\n'.join(r['text'] for r in results)[:16000],
            'variants':results,'language':'eng','backend':'Tesseract'}


def image_qr(case_id,file):
    import importlib.util
    import importlib
    from PIL import Image,ImageOps,ImageFilter
    from attachment_tools import resolve_file,case_dir
    if not status()['image_qr']:raise ValueError('未找到本机QR解码库')
    bundled=(PYZBAR_PACKAGE/'pyzbar.py').is_file() and (PYZBAR_PACKAGE/'libzbar-64.dll').is_file()
    if bundled:
        name='_ctf_pyzbar'
        if name not in sys.modules:
            spec=importlib.util.spec_from_file_location(name,PYZBAR_PACKAGE/'__init__.py',submodule_search_locations=[str(PYZBAR_PACKAGE)])
            package=importlib.util.module_from_spec(spec)
            sys.modules[name]=package
            spec.loader.exec_module(package)
        decode=importlib.import_module(name+'.pyzbar').decode
    else:
        from pyzbar.pyzbar import decode
    with Image.open(resolve_file(case_id,file)) as image:
        if image.width*image.height>64_000_000:raise ValueError('QR图像像素上限6400万')
        gray=image.convert('L')
    scaled=gray.copy();scaled.thumbnail((2048,2048),Image.Resampling.NEAREST)
    averaged=gray.copy();averaged.thumbnail((1024,1024),Image.Resampling.BOX)
    contrast=ImageOps.autocontrast(averaged)
    binary=contrast.point(lambda x:255 if x>160 else 0)
    variants=[('scaled',scaled),('contrast-average',contrast),('contrast-binary',binary),
              ('dot-close3',binary.filter(ImageFilter.MinFilter(3)).filter(ImageFilter.MaxFilter(3))),
              ('dot-close5',binary.filter(ImageFilter.MinFilter(5)).filter(ImageFilter.MaxFilter(5))),
              ('inverted',ImageOps.invert(contrast))]
    root=case_dir(case_id)
    for label,variant in variants:
        symbols=decode(variant)
        if symbols:
            artifact=root/'output'/f'qr-{label}-{uuid.uuid4().hex[:8]}.png';variant.save(artifact)
            return {'variant':label,'file':artifact.relative_to(root).as_posix(),
                    'symbols':[{'type':item.type,'text':item.data.decode('utf-8',errors='replace')} for item in symbols[:20]]}
    return {'symbols':[],'tried':[label for label,_ in variants]}


def binwalk(case_id, file):
    from attachment_tools import case_dir, resolve_file
    source = resolve_file(case_id, file)
    root = case_dir(case_id)
    log_path = root / 'output' / f'binwalk-{uuid.uuid4().hex[:8]}.log'
    binary=_binwalk_bin()
    if binary is None:raise ValueError('未找到本机 Binwalk')
    command = [str(binary), '-B', str(source)]
    try:
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       shell=False, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {'exit_code': process.returncode, 'timeout': True, 'output': _tail(log_path)}
    except OSError as exc:
        raise ValueError(f'Binwalk 启动失败：{exc}') from exc
    return {'exit_code': process.returncode, 'timeout': False, 'output': _tail(log_path)}


def foremost(case_id, file):
    from attachment_tools import case_dir, resolve_file
    binary=shutil.which('foremost')
    if not binary:
        raise ValueError('未找到 foremost')
    source=resolve_file(case_id, file)
    if source.stat().st_size>256*1024*1024:
        raise ValueError('foremost 只处理 256MB 以内的附件')
    root=case_dir(case_id)
    out=root/'output'/f'foremost-{uuid.uuid4().hex[:8]}'
    out.mkdir()
    log_path=out/'foremost.log'
    command=[binary,'-q','-i',str(source),'-o',str(out)]
    try:
        with log_path.open('wb') as log:
            process=subprocess.Popen(command,cwd=root,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                     shell=False,creationflags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0)
            try:
                process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {'exit_code':process.returncode,'timeout':True,'output':_tail(log_path),'directory':out.relative_to(root).as_posix()}
    except OSError as exc:
        raise ValueError(f'foremost 启动失败：{exc}') from exc
    files=[]
    for path in sorted(out.rglob('*')):
        if not path.is_file() or path==log_path:
            continue
        files.append({'file':path.relative_to(root).as_posix(),'bytes':path.stat().st_size})
        if len(files)>=40:
            break
    return {'exit_code':process.returncode,'timeout':False,'output':_tail(log_path),'directory':out.relative_to(root).as_posix(),'files':files}


def stegoveritas(case_id, file):
    from attachment_tools import case_dir, resolve_file
    source = resolve_file(case_id, file)
    if source.stat().st_size > MAX_STEGOVERITAS_FILE:
        raise ValueError('随波逐流 StegoVeritas 单文件限制为128MB')
    root = case_dir(case_id)
    run_dir = root / 'output' / f'stegoveritas-{uuid.uuid4().hex[:8]}'
    run_dir.mkdir()
    result_dir = run_dir / 'results'
    log_path = run_dir / 'stegoveritas.log'
    command = [str(STEGOVERITAS), '--run-stegoveritas', str(source), '-out', str(result_dir)]
    try:
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, cwd=run_dir, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       shell=False, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                timed_out = True
            else:
                timed_out = False
    except OSError as exc:
        raise ValueError(f'随波逐流 StegoVeritas 启动失败：{exc}') from exc
    files = []
    if result_dir.is_dir():
        for path in result_dir.rglob('*'):
            if path.is_file():
                files.append({'file': path.relative_to(root).as_posix(), 'bytes': path.stat().st_size})
                if len(files) >= 100:
                    break
    return {'exit_code': process.returncode, 'timeout': timed_out, 'output': _tail(log_path),
            'output_dir': result_dir.relative_to(root).as_posix(),
            'log_file': log_path.relative_to(root).as_posix(), 'files': files}


def _tail(path, limit=20000):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - limit))
        return stream.read(limit).decode('utf-8', errors='replace')
