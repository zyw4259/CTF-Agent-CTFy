"""Restricted Python worker, NOT a security sandbox for adversarial code."""
import ast
import builtins
import io
import os
import sys
from pathlib import Path

if sys.platform=='linux':
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024*1024,64*1024*1024))
    seconds=170 if '--sage-sandbox' in sys.argv else 110 if '--analysis-sandbox' in sys.argv else 80 if '--math-sandbox' in sys.argv else 20
    resource.setrlimit(resource.RLIMIT_CPU,(seconds,seconds))

if sys.stdin.readline().strip()!='RUN':
    raise RuntimeError('执行许可未建立')

root=Path(sys.argv[1]).resolve()
script=Path(sys.argv[2]).resolve()
mode=sys.argv[3] if len(sys.argv)>3 else ''
math_mode=mode in {'--math-sandbox','--sage-sandbox','--analysis-sandbox'}
if math_mode and (sys.platform!='linux' or root!=Path('/tmp') or not script.is_relative_to(root/'output')):
    raise ValueError('数学库仅允许在Linux隔离数学环境内启用')
allowed={'base64','binascii','struct','zlib','hashlib','math','itertools','collections','re','json','string','functools','operator','statistics','decimal','fractions','codecs'}
venv_site=Path(sys.prefix)/'lib'/f'python{sys.version_info.major}.{sys.version_info.minor}'/'site-packages'
if venv_site.is_dir() and str(venv_site) not in sys.path:
    sys.path.append(str(venv_site))
heavy=set()
for name in ('Crypto','gmpy2','z3'):
    if (venv_site/name).is_dir():
        allowed.add(name)
        heavy.add(name)
if math_mode:
    allowed.update({'sympy','z3','Crypto','gmpy2','fpylll','py_ecc','cysignals','numpy','scipy'})
if mode=='--sage-sandbox':allowed.add('sage')
if mode=='--analysis-sandbox':
    allowed.update({'PIL','torch','transformers','safetensors','sklearn','matplotlib','pefile','capstone','lief','yara','oletools','dissect'})
source=script.read_text(encoding='utf-8')
tree=ast.parse(source,filename=str(script))
for node in ast.walk(tree):
    if isinstance(node,(ast.Import,ast.ImportFrom)):
        names=[x.name.split('.')[0] for x in node.names] if isinstance(node,ast.Import) else [(node.module or '').split('.')[0]]
        if any(name not in allowed for name in names):
            raise ValueError(f'模块不在允许列表内: {names}')
        if math_mode and isinstance(node,ast.ImportFrom) and any(part.startswith('_') for part in (node.module or '').split('.')):
            raise ValueError('不允许导入内部模块')
    if isinstance(node,ast.Attribute) and node.attr.startswith('_'):
        raise ValueError('不允许访问私有/内部属性')
    if isinstance(node,ast.Name) and node.id.startswith('__'):
        raise ValueError('不允许内部变量')
# Preload allowed standard libraries before applying filesystem restrictions.
if math_mode:
    import importlib
    requested=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):requested.update(alias.name for alias in node.names)
        elif isinstance(node,ast.ImportFrom) and node.module:requested.add(node.module)
    for name in requested:importlib.import_module(name)
    if mode=='--sage-sandbox':
        importlib.import_module('numpy')
        importlib.import_module('fpylll')
    modules={name:__import__(name) for name in allowed if name in sys.modules or name in {n.split('.')[0] for n in requested}}
else:
    requested=set()
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):requested.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node,ast.ImportFrom) and node.module:requested.add(node.module.split('.')[0])
    modules={name:__import__(name) for name in allowed if name not in heavy or name in requested}

def library_path(target):
    prefixes=('/usr','/opt','/lib','/lib64') if math_mode else ('/opt/venv','/usr/lib','/lib','/lib64')
    return any(target.is_relative_to(Path(prefix)) for prefix in prefixes)

def audit(event,args):
    if event=='open':
        path=args[0]
        if not isinstance(path,(str,bytes,os.PathLike)):
            raise PermissionError('不允许文件描述符访问')
        target=Path(os.fsdecode(path)).resolve()
        mode,flags=args[1],args[2]
        writing=(isinstance(mode,str) and any(c in mode for c in 'wax+')) or (isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        if not target.is_relative_to(root) and not (not writing and library_path(target)):
            raise PermissionError('只允许访问当前题目目录和只读数学运行库')
        if writing and not target.is_relative_to(root/'output'):
            raise PermissionError('只允许写入output目录')
    if event.startswith('os.'):
        if math_mode and event in {'os.putenv','os.unsetenv'}:
            return
        if math_mode and event in {'os.mkdir','os.remove','os.rmdir'}:
            name=args[0]
            directory=args[2] if event=='os.mkdir' else args[1]
            base=Path(os.readlink('/proc/self/fd/'+str(directory))) if isinstance(directory,int) and directory>=0 else Path.cwd()
            if (base/os.fsdecode(name)).resolve().is_relative_to(root/'output'):
                return
        if event not in {'os.listdir','os.scandir'}:
            raise PermissionError('不允许系统修改操作')
        path=Path(os.readlink('/proc/self/fd/'+str(args[0]))) if math_mode and isinstance(args[0],int) else Path(args[0]).resolve()
        if not path.is_relative_to(root) and not library_path(path):
            raise PermissionError('不允许枚举题目目录之外的文件')
    if math_mode and event in {'ctypes.dlopen','ctypes.dlsym'}:
        name=args[0] if event=='ctypes.dlopen' else getattr(args[0],'_name',None)
        if isinstance(name,str) and library_path(Path(name).resolve()):
            return
    if event.startswith(('socket.','subprocess.','ctypes.','winreg.','os.system','os.spawn','os.exec','os.fork')):
        raise PermissionError('不允许网络、启动进程或系统调用')
sys.addaudithook(audit)

def limited_import(name,globals=None,locals=None,fromlist=(),level=0):
    if math_mode and not level and name.split('.')[0] in allowed:
        return builtins.__import__(name,globals,locals,fromlist,0)
    if level or name not in modules:
        raise ImportError('模块不在允许列表内')
    return modules[name]

def limited_open(name,mode='r',*args,**kwargs):
    if any(c in mode for c in 'wax+'):
        target=Path(name).resolve()
        if not target.is_relative_to(root/'output'):
            raise PermissionError('只允许写入output目录')
    return builtins.open(name,mode,*args,**kwargs)

class BoundedOutput:
    def __init__(self,stream):
        self.stream=stream
        self.remaining=64000
    def write(self,text):
        if self.remaining<=0:
            raise RuntimeError('输出超过限制')
        value=str(text)[:self.remaining]
        self.remaining-=len(value)
        self.stream.write(value)
        self.stream.flush()
        return len(value)
    def flush(self):
        self.stream.flush()

sys.stdout=BoundedOutput(io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8',errors='replace'))
sys.stderr=sys.stdout
safe_names=['print','len','range','enumerate','zip','bytes','bytearray','str','int','float','bool','list','tuple','dict','set','sorted','reversed','sum','min','max','abs','all','any','chr','ord','hex','bin','oct','pow','round','isinstance','Exception','ValueError','TypeError']
safe={name:getattr(builtins,name) for name in safe_names}
if math_mode:
    safe.update({name:getattr(builtins,name) for name in ('map','filter','iter','next','repr','divmod','complex','frozenset','slice','KeyError','IndexError','RuntimeError','ArithmeticError')})
safe['__import__']=limited_import
safe['open']=limited_open
exec(compile(tree,str(script),'exec'),{'__builtins__':safe})
