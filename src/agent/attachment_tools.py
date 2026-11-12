"""Bounded static analysis tools. Uploaded binaries are never executed."""
import ast
import base64
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from collections import Counter
from pathlib import Path
from threading import Lock

BASE = Path(__file__).resolve().parent
LOCAL_DEPENDENCIES=BASE/'runtime'/'pydeps'
if LOCAL_DEPENDENCIES.is_dir():
    sys.path.insert(0,str(LOCAL_DEPENDENCIES))
CASES = BASE/'cases'
MAX_FILE = 8*1024*1024*1024
MAX_CASE = 16*1024*1024*1024
MAX_EXTRACT = 1024*1024*1024
MIN_FREE_DISK = 8*1024*1024*1024
UPLOAD_LOCK = Lock()

def limit_windows_process(process):
    """Hard 512MB process memory limit via Windows Job Object."""
    if sys.platform!='win32':
        raise RuntimeError('当前受限Python执行器仅支持Windows')
    import ctypes as c
    from ctypes import wintypes as w
    class Basic(c.Structure):
        _fields_=[('process_time',c.c_longlong),('job_time',c.c_longlong),('flags',w.DWORD),('minimum',c.c_size_t),('maximum',c.c_size_t),('active',w.DWORD),('affinity',c.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
    class IO(c.Structure):
        _fields_=[(name,c.c_ulonglong) for name in ('read_count','write_count','other_count','read_bytes','write_bytes','other_bytes')]
    class Extended(c.Structure):
        _fields_=[('basic',Basic),('io',IO),('process_memory',c.c_size_t),('job_memory',c.c_size_t),('peak_process',c.c_size_t),('peak_job',c.c_size_t)]
    kernel=c.WinDLL('kernel32',use_last_error=True)
    kernel.CreateJobObjectW.argtypes=[c.c_void_p,w.LPCWSTR]
    kernel.CreateJobObjectW.restype=w.HANDLE
    kernel.SetInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD]
    kernel.SetInformationJobObject.restype=w.BOOL
    kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
    kernel.AssignProcessToJobObject.restype=w.BOOL
    kernel.CloseHandle.argtypes=[w.HANDLE]
    job=kernel.CreateJobObjectW(None,None)
    limits=Extended()
    limits.basic.flags=0x100|0x2000|0x8
    limits.basic.active=1
    limits.process_memory=512*1024*1024
    if not job or not kernel.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)) or not kernel.AssignProcessToJobObject(job,w.HANDLE(int(process._handle))):
        if job:
            kernel.CloseHandle(job)
        raise c.WinError(c.get_last_error())
    return lambda:kernel.CloseHandle(job)

def limit_posix_process():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU,(20,20))
    resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
    resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024*1024,64*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def case_dir(case_id):
    if not re.fullmatch(r'[0-9a-f]{32}',case_id):
        raise ValueError('无效题目ID')
    root = (CASES/case_id).resolve()
    if not root.is_dir():
        raise ValueError('题目不存在')
    return root

def new_case():
    case_id = uuid.uuid4().hex
    (CASES/case_id/'input').mkdir(parents=True)
    (CASES/case_id/'output').mkdir()
    return case_id

def resolve_file(case_id,name):
    root = case_dir(case_id)
    relative=Path(str(name).replace('\\','/'))
    target = (root/relative).resolve()
    if (not target.is_file() and len(relative.parts)>=2 and relative.parts[0]=='input'
            and relative.parts[1].startswith('extracted_')):
        target=(root/'output'/Path(*relative.parts[1:])).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError('文件不在当前题目目录内')
    if target.stat().st_size > MAX_FILE:
        raise ValueError('文件超过8GB单文件限制')
    return target

def sha256_file(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(4*1024*1024):
            digest.update(block)
    return digest.hexdigest()

def save_upload(case_id,name,stream,size):
    if not 0 < size <= MAX_FILE:
        raise ValueError('附件大小需在1字节至8GB之间')
    root = case_dir(case_id)
    safe = re.sub(r'[^\w.\-\u4e00-\u9fff]','_',name)[:100].strip('.') or 'attachment.bin'
    target = root/'input'/f'{uuid.uuid4().hex[:8]}_{safe}'
    with UPLOAD_LOCK:
        current = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
        if current+size > MAX_CASE:
            raise ValueError('当前题目总大小超过16GB')
        if shutil.disk_usage(root).free-size < MIN_FREE_DISK:
            raise ValueError('上传后磁盘剩余空间需至少保留8GB')
        remaining = size
        digest = hashlib.sha256()
        try:
            with target.open('xb') as out:
                while remaining:
                    block = stream.read(min(4*1024*1024,remaining))
                    if not block:
                        raise ValueError('附件传输不完整')
                    out.write(block)
                    digest.update(block)
                    remaining -= len(block)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        content_hash=digest.hexdigest()
        for existing in (root/'input').iterdir():
            if existing==target or not existing.is_file() or existing.stat().st_size!=size:
                continue
            if sha256_file(existing)==content_hash:
                target.unlink()
                return existing.relative_to(root).as_posix()
    return target.relative_to(root).as_posix()

def manifest(case_id):
    root = case_dir(case_id)
    return [{'file':p.relative_to(root).as_posix(),'bytes':p.stat().st_size} for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'trace.json' and not p.name.startswith('.math-worker-')][:200]

def inspect_file(path):
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        head = stream.read(64)
        stream.seek(0)
        while block := stream.read(8*1024*1024):
            digest.update(block)
    sample_size = min(size,8*1024*1024)
    counts = Counter()
    with path.open('rb') as stream:
        if size <= sample_size:
            counts.update(stream.read())
        else:
            sample_block = sample_size//8
            for index in range(8):
                offset = (size-sample_block)*index//7
                stream.seek(offset)
                counts.update(stream.read(sample_block))
    sampled = size > sample_size
    sample_bytes = sum(counts.values())
    entropy = -sum((n/sample_bytes)*math.log2(n/sample_bytes) for n in counts.values()) if sample_bytes else 0
    kind = 'binary/text'
    for signature,label in [(b'\x7fELF','ELF'),(b'MZ','PE/DOS'),(b'\x89PNG\r\n\x1a\n','PNG'),(b'PK\x03\x04','ZIP'),(b'\xff\xd8\xff','JPEG'),(b'%PDF','PDF'),(b'\xd4\xc3\xb2\xa1','PCAP'),(b'\x0a\x0d\x0d\x0a','PCAPNG')]:
        if head.startswith(signature):
            kind=label
            break
    result={'type':kind,'bytes':size,'sha256':digest.hexdigest(),'entropy':round(entropy,3),'entropy_sample_bytes':sample_bytes,
            'entropy_note':'均匀抽样估算' if sampled else '全文件精确值','header_hex':head.hex()}
    result['strings_preview']=strings_file(path,limit=25)
    if kind=='PNG' and len(head)>=33:
        import zlib
        result['png']={'width':int.from_bytes(head[16:20],'big'),'height':int.from_bytes(head[20:24],'big'),
                       'ihdr_length':int.from_bytes(head[8:12],'big'),'stored_crc':head[29:33].hex(),
                       'computed_crc':f'{zlib.crc32(head[12:29]) & 0xffffffff:08x}'}
    if kind in {'ELF','PE/DOS'}:
        try:
            result['binary']=binary_info(path)
        except Exception as e:
            result['binary_error']=str(e)
    if path.suffix.lower() in {'.pth','.pt','.ckpt','.safetensors'}:
        try:
            result['checkpoint']=model_checkpoint_info(path)
        except Exception as e:
            result['checkpoint_error']=str(e)
    return result

def strings(data,limit=100):
    ascii_strings = [(m.start(),m.group().decode('ascii')) for m in re.finditer(rb'[\x20-\x7e]{4,}',data)]
    wide_strings = [(m.start(),m.group().decode('utf-16le',errors='replace')) for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',data)]
    values = sorted(ascii_strings+wide_strings)
    return [{'offset':offset,'text':value[:300]} for offset,value in values[:limit]]

def search_bytes(path,args):
    terms=args.get('terms',['flag{','ctf{'])
    if not isinstance(terms,list) or not 1<=len(terms)<=8 or any(not isinstance(t,str) or not 1<=len(t)<=80 for t in terms):
        raise ValueError('需要1到8个搜索词，每个最多80字符')
    limit=min(max(int(args.get('limit',40)),1),100)
    patterns=[(term,encoding,term.encode(encoding).lower()) for term in terms for encoding in ('utf-8','utf-16le')]
    found=[];seen=set();carry=b'';scanned=0
    with path.open('rb') as stream:
        while True:
            chunk=stream.read(4*1024*1024)
            block=carry+chunk;base=scanned-len(carry);lower=block.lower()
            for term,encoding,needle in patterns:
                offset=0
                while (position:=lower.find(needle,offset))>=0:
                    absolute=base+position;offset=position+len(needle)
                    if chunk and position>=len(block)-512:continue
                    if (absolute,encoding) in seen:continue
                    seen.add((absolute,encoding))
                    start=max(0,position-96);end=min(len(block),position+320)
                    if encoding=='utf-16le':
                        start+=(position-start)%2;end-=(end-start)%2
                    text=block[start:end].decode(encoding,errors='replace').replace('\x00',' ')
                    found.append({'offset':absolute,'encoding':encoding,'term':term,'context':text})
                    if len(found)>=limit:
                        return {'matches':found,'scanned_bytes':scanned+len(chunk),'complete_scan':False,'verified':False}
            scanned+=len(chunk)
            if not chunk:break
            carry=block[-1024:]
    return {'matches':found,'scanned_bytes':scanned,'complete_scan':True,'verified':False}


def strings_file(path,limit=100):
    patterns=(re.compile(rb'[\x20-\x7e]{4,}'),re.compile(rb'(?:[\x20-\x7e]\x00){4,}'))
    found=[]
    seen=set()
    carry=b''
    scanned=0
    with path.open('rb') as stream:
        while chunk := stream.read(4*1024*1024):
            block=carry+chunk
            base=scanned-len(carry)
            skip=max(0,len(carry)-8)
            matches=[]
            for pattern in patterns:
                for match in pattern.finditer(block):
                    if match.start()<skip:
                        continue
                    offset=base+match.start()
                    if offset in seen:
                        continue
                    seen.add(offset)
                    raw=match.group()
                    text=raw.decode('utf-16le' if b'\x00' in raw else 'ascii',errors='replace')
                    matches.append((offset,text[:300]))
            for offset,text in sorted(matches):
                found.append({'offset':offset,'text':text})
                if len(found)>=limit:
                    return found
            scanned+=len(chunk)
            carry=block[-4096:]
    return found

def model_checkpoint_info(path):
    """Inspect checkpoint metadata without importing torch or unpickling."""
    if path.suffix.lower()=='.safetensors':
        with path.open('rb') as stream:
            raw_length=stream.read(8)
            if len(raw_length)!=8:
                raise ValueError('safetensors 文件头不完整')
            header_length=int.from_bytes(raw_length,'little')
            if header_length>16*1024*1024 or header_length+8>path.stat().st_size:
                raise ValueError('safetensors 文件头长度异常或超过16MB')
            header=json.loads(stream.read(header_length).decode('utf-8'))
        tensors=[]
        for name,meta in header.items():
            if name=='__metadata__' or not isinstance(meta,dict):
                continue
            offsets=meta.get('data_offsets',[])
            tensors.append({'name':name[:160],'dtype':meta.get('dtype'),'shape':meta.get('shape'),
                            'bytes':max(0,int(offsets[1])-int(offsets[0])) if len(offsets)==2 else None})
        return {'format':'safetensors','tensors':tensors[:200],'tensor_count':len(tensors),'safe_note':'仅解析JSON头，未加载张量'}
    result={'format':'PyTorch checkpoint','bytes':path.stat().st_size,'deserialized':False,
            'warning':'仅检查ZIP目录和pickle操作码；没有调用pickle.load或torch.load。'}
    payload=None
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            infos=archive.infolist()
            result['members']=[{'name':info.filename[:200],'bytes':info.file_size} for info in infos[:200]]
            result['member_count']=len(infos)
            pickle_info=next((info for info in infos if info.filename=='data.pkl' or info.filename.endswith('/data.pkl')),None)
            if pickle_info and pickle_info.file_size<=4*1024*1024:
                payload=archive.read(pickle_info)
            elif pickle_info:
                result['pickle_summary']='metadata exceeds the 4MB parse cap'
    else:
        with path.open('rb') as stream:
            payload=stream.read(4*1024*1024)
        result['pickle_prefix_bytes']=len(payload)
    if payload is not None:
        import pickletools
        opcodes=Counter()
        globals_seen=[]
        strings_seen=[]
        try:
            for index,(opcode,arg,position) in enumerate(pickletools.genops(payload)):
                opcodes[opcode.name]+=1
                if opcode.name=='GLOBAL' and isinstance(arg,str) and len(globals_seen)<100:
                    globals_seen.append(arg[:240])
                if opcode.name in {'UNICODE','BINUNICODE','SHORT_BINUNICODE','BINUNICODE8'} and isinstance(arg,str) and len(strings_seen)<200:
                    strings_seen.append(arg[:240])
                if index>=100000:
                    result['pickle_summary']='stopped at 100000 opcodes'
                    break
        except Exception as e:
            result['pickle_parse_note']=str(e)[:240]
        result['pickle_opcodes']=opcodes.most_common(30)
        result['pickle_globals']=globals_seen
        result['pickle_strings']=strings_seen
    return result

def binary_info(path):
    with path.open('rb') as stream:
        magic=stream.read(2)
    if magic==b'MZ':
        import pefile
        pe = pefile.PE(str(path),fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        return {'format':'PE','machine':hex(pe.FILE_HEADER.Machine),'entry':hex(pe.OPTIONAL_HEADER.ImageBase+pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'bits':64 if pe.OPTIONAL_HEADER.Magic==0x20b else 32,
                'sections':[{'name':s.Name.rstrip(b'\x00').decode(errors='replace'),'address':hex(s.VirtualAddress),'size':s.SizeOfRawData} for s in pe.sections],
                'imports':[{'dll':d.dll.decode(errors='replace'),'names':[(i.name or b'ordinal').decode(errors='replace') for i in d.imports[:50]]} for d in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])[:20]]}
    from elftools.elf.elffile import ELFFile
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        symbols=[]
        for name in ('.symtab','.dynsym'):
            sec=elf.get_section_by_name(name)
            if sec:
                symbols.extend({'name':s.name,'address':hex(s['st_value'])} for s in sec.iter_symbols() if s.name)
        return {'format':'ELF','machine':elf['e_machine'],'bits':elf.elfclass,'entry':hex(elf['e_entry']),
                'sections':[{'name':s.name,'address':hex(s['sh_addr']),'size':s['sh_size']} for s in elf.iter_sections()][:80],
                'symbols':symbols[:120]}

def disassemble(path,args):
    import capstone as cs
    address=int(str(args.get('address','0')),0)
    size=min(max(int(args.get('size',256)),1),2048)
    with path.open('rb') as stream:
        magic=stream.read(4)
        if magic.startswith(b'MZ'):
            import pefile
            pe=pefile.PE(str(path),fast_load=True)
            machine=pe.FILE_HEADER.Machine
            if machine not in (0x8664,0x14c):
                raise ValueError('当前PE反汇编只支持x86/x64')
            arch,mode=cs.CS_ARCH_X86,cs.CS_MODE_64 if machine==0x8664 else cs.CS_MODE_32
            base=pe.OPTIONAL_HEADER.ImageBase
            address=address or base+pe.OPTIONAL_HEADER.AddressOfEntryPoint
            offset=pe.get_offset_from_rva(address-base)
        elif magic==b'\x7fELF':
            from elftools.elf.elffile import ELFFile
            stream.seek(0)
            elf=ELFFile(stream)
            machine=elf['e_machine']
            if machine in ('EM_X86_64','EM_386'):
                arch,mode=cs.CS_ARCH_X86,cs.CS_MODE_64 if elf.elfclass==64 else cs.CS_MODE_32
            elif machine=='EM_AARCH64':
                arch,mode=cs.CS_ARCH_ARM64,cs.CS_MODE_LITTLE_ENDIAN
            else:
                raise ValueError('当前ELF反汇编支持x86/x64/AArch64')
            address=address or elf['e_entry']
            segment=next((s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=address<s['p_vaddr']+s['p_filesz']),None)
            if not segment:
                raise ValueError('地址没有对应文件数据')
            offset=segment['p_offset']+address-segment['p_vaddr']
        else:
            offset=int(str(args.get('offset','0')),0)
            arch,mode=cs.CS_ARCH_X86,cs.CS_MODE_64 if int(args.get('bits',64))==64 else cs.CS_MODE_32
            address=address or offset
        if offset<0 or offset>=path.stat().st_size:
            raise ValueError('文件偏移越界')
        stream.seek(offset)
        data=stream.read(min(size,path.stat().st_size-offset))
    engine=cs.Cs(arch,mode)
    return {'address':hex(address),'file_offset':offset,'assembly':[f'{a:#x}: {m} {op}' for a,_,m,op in engine.disasm_lite(data,address)][:150],
            'note':'静态汇编；不等于反编译，也未运行程序'}

def subset_sum_lll(path):
    """Solve literal beta_i/c_i subset-sum assignments and verify every block."""
    if path.stat().st_size > 1024*1024:
        return {'detected':False}
    try:
        tree=ast.parse(path.read_text(encoding='utf-8-sig'))
    except (UnicodeDecodeError,SyntaxError):
        return {'detected':False}
    values={}
    for node in tree.body:
        if not isinstance(node,ast.Assign) or len(node.targets)!=1 or not isinstance(node.targets[0],ast.Name):
            continue
        name=node.targets[0].id
        if not re.fullmatch(r'(?:beta|c)_\d+',name):
            continue
        try:
            value=ast.literal_eval(node.value)
        except (ValueError,TypeError,MemoryError,RecursionError):
            continue
        if name.startswith('beta_') and isinstance(value,list) and 8<=len(value)<=96 and all(type(x) is int and x>=0 and x.bit_length()<=512 for x in value):
            values[name]=value
        elif name.startswith('c_') and type(value) is int and value>=0 and value.bit_length()<=512:
            values[name]=value
    indices=sorted(int(m.group(1)) for name in values if (m:=re.fullmatch(r'beta_(\d+)',name)) and f'c_{m.group(1)}' in values)
    if not indices or indices!=list(range(1,len(indices)+1)):
        return {'detected':False}

    from flint import fmpz_mat
    blocks=[]
    plaintext=bytearray()
    for index in indices:
        beta=values[f'beta_{index}']
        target=values[f'c_{index}']
        size=len(beta)
        basis=[[int(row==col) for col in range(size)]+[value] for row,value in enumerate(beta)]
        basis.append([0]*size+[-target])
        reduced=fmpz_mat(basis).lll(delta=0.99)
        solution=None
        for row_index in range(reduced.nrows()):
            row=[int(reduced[row_index,col]) for col in range(size+1)]
            if row[-1]!=0:
                continue
            for sign in (1,-1):
                bits=[sign*value for value in row[:-1]]
                if all(value in (0,1) for value in bits) and sum(bit*weight for bit,weight in zip(bits,beta))==target:
                    solution=bits
                    break
            if solution is not None:
                break
        if solution is None:
            blocks.append({'index':index,'bits':size,'verified':False})
            continue
        bit_string=''.join(map(str,solution))
        block_bytes=int(bit_string,2).to_bytes((size+7)//8,'big')
        plaintext.extend(block_bytes)
        blocks.append({'index':index,'bits':size,'verified':True,'bytes_hex':block_bytes.hex()})
    solved=len(blocks)==len(indices) and all(block['verified'] for block in blocks)
    result={'detected':True,'solved':solved,'blocks':blocks}
    if solved:
        result['bytes_hex']=bytes(plaintext).hex()
        result['plaintext']=bytes(plaintext).decode('utf-8',errors='replace')
    return result

def extract_zip(case_id,path,password=None):
    root=case_dir(case_id)
    if password is not None:
        password=str(password).encode('utf-8')
        if len(password)>256:raise ValueError('ZIP密码过长')
    output=root/'output'/f'extracted_{uuid.uuid4().hex[:8]}'
    with zipfile.ZipFile(path) as archive:
        infos=archive.infolist()
        if len(infos)>5000 or sum(i.file_size for i in infos)>MAX_EXTRACT:
            raise ValueError('压缩包文件数超过5000或解压数据超过1GB')
        for info in infos:
            target=(output/info.filename).resolve()
            if not target.is_relative_to(output.resolve()) or '\\' in info.filename or ':' in info.filename or (info.external_attr>>16)&0o170000==0o120000:
                raise ValueError('压缩包含越界路径或链接')
        output.mkdir()
        total=0
        for info in infos:
            target=output/info.filename
            if info.is_dir():
                target.mkdir(parents=True,exist_ok=True)
                continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with archive.open(info,pwd=password) as source,target.open('wb') as dest:
                while block:=source.read(1024*1024):
                    total+=len(block)
                    if total>MAX_EXTRACT:
                        raise ValueError('解压数据超过1GB限制')
                    dest.write(block)
    return {'directory':output.relative_to(root).as_posix(),'files':manifest(case_id)}

def _printable_text(data):
    try:
        text=data.decode('utf-8-sig')
    except UnicodeDecodeError:
        return None
    if not text:
        return ''
    printable=sum(char.isprintable() or char in '\r\n\t' for char in text)
    return text if printable/len(text)>=0.95 else None

_BASE92_ALPHABET='!'+''.join(chr(i) for i in range(ord('#'),ord('_')+1))+''.join(chr(i) for i in range(ord('a'),ord('}')+1))
_BASE92_INDEX={char:index for index,char in enumerate(_BASE92_ALPHABET)}

# Base92 bit packing adapted from py3base92 by Gu-f and Nathan Hwang.
# Beerware License (Revision 42): <Gu-f> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.
def _base92_decode(data):
    text=data.decode('ascii')
    if text=='~':
        return b''
    if any(char not in _BASE92_INDEX for char in text):
        raise ValueError('invalid Base92 character')
    output=bytearray()
    buffer=bit_count=0
    pairs=len(text)//2
    for i in range(pairs):
        value=_BASE92_INDEX[text[2*i]]*91+_BASE92_INDEX[text[2*i+1]]
        if value>8191:
            raise ValueError('invalid Base92 pair')
        buffer=(buffer<<13)|value
        bit_count+=13
        while bit_count>=8:
            bit_count-=8
            output.append((buffer>>bit_count)&255)
            buffer&=(1<<bit_count)-1
    if len(text)%2:
        value=_BASE92_INDEX[text[-1]]
        if value>=64:
            raise ValueError('invalid Base92 trailing character')
        buffer=(buffer<<6)|value
        bit_count+=6
        while bit_count>=8:
            bit_count-=8
            output.append((buffer>>bit_count)&255)
            buffer&=(1<<bit_count)-1
    return bytes(output)

def decode_text_layers(path):
    size=path.stat().st_size
    if size>8*1024*1024:
        return {'status':'too_large','bytes':size,'limit_bytes':8*1024*1024}
    original=path.read_bytes()
    current=original.strip()
    if _printable_text(current) is None:
        return {'status':'not_text','bytes':size}
    encodings=[]
    for _ in range(128):
        compact=b''.join(current.split())
        decoded=None
        base32_chars=b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567='
        if len(compact)>=2 and len(compact)%2==0 and re.fullmatch(rb'[0-9A-Fa-f]+',compact):
            try:
                candidate=bytes.fromhex(compact.decode('ascii'))
                if _printable_text(candidate) is not None:
                    decoded=('base16',candidate)
            except (ValueError,UnicodeDecodeError):
                pass
        if decoded is None and compact and all(byte in base32_chars for byte in compact) and not any(97<=byte<=122 for byte in compact):
            try:
                candidate=base64.b32decode(compact+b'='*((-len(compact))%8))
                if _printable_text(candidate) is not None:
                    decoded=('base32',candidate)
            except Exception:
                pass
        if decoded is None and compact:
            padded=compact+b'='*((-len(compact))%4)
            try:
                candidate=base64.b64decode(padded,validate=True)
                if _printable_text(candidate) is not None:
                    decoded=('base64',candidate)
            except Exception:
                try:
                    candidate=base64.b64decode(padded,altchars=b'-_',validate=True)
                    if _printable_text(candidate) is not None:
                        decoded=('base64url',candidate)
                except Exception:
                    pass
        if decoded is None and compact:
            try:
                candidate=base64.b32decode(compact.upper()+b'='*((-len(compact))%8))
                if _printable_text(candidate) is not None:
                    decoded=('base32',candidate)
            except Exception:
                pass
        if decoded is None and compact:
            for name,decoder in (('base85',base64.b85decode),('ascii85',base64.a85decode)):
                try:
                    candidate=decoder(compact)
                    if _printable_text(candidate) is not None:
                        decoded=(name,candidate)
                        break
                except Exception:
                    pass
        if decoded is None and compact:
            try:
                candidate=_base92_decode(compact)
                if _printable_text(candidate) is not None:
                    decoded=('base92',candidate)
            except Exception:
                pass
        if decoded is None or decoded[1]==current:
            break
        encoding,current=decoded
        encodings.append(encoding)
        if re.search(rb'(?i)[A-Za-z0-9][A-Za-z0-9_-]{1,31}\{[^\s{}]{4,128}\}',current):
            break
    terminal=_printable_text(current)
    result={'status':'decoded' if encodings else 'no_base_layer','source_bytes':size,
            'decoded_layers':len(encodings),'encodings':encodings,'terminal_bytes':len(current)}
    if terminal is not None:
        result['terminal_text']=terminal[:2000]
    else:
        result['terminal_hex']=current[:256].hex()
    return result

def run_python(case_id,code):
    root=case_dir(case_id)
    if not isinstance(code,str) or len(code)>12000:
        raise ValueError('脚本过长')
    name=f'analysis_{uuid.uuid4().hex[:8]}.py'
    script=root/'output'/name
    script.write_text(code,encoding='utf-8')
    capture=root/'output'/f'{script.stem}.log'
    # The worker limits imports, filesystem access and runtime. It is NOT an OS sandbox.
    with capture.open('wb') as out:
        process=subprocess.Popen([sys.executable,'-X','utf8','-I','-S',str(BASE/'python_worker.py'),str(root),str(script)],cwd=root,stdin=subprocess.PIPE,
                                 stdout=out,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0,
                                 preexec_fn=limit_posix_process if sys.platform!='win32' else None)
        cleanup=None
        try:
            if sys.platform=='win32':cleanup=limit_windows_process(process)
            process.stdin.write(b'RUN\n')
            process.stdin.close()
            deadline=time.monotonic()+20
            timed_out=False
            while process.poll() is None:
                output_size=sum(p.stat().st_size for p in (root/'output').rglob('*') if p.is_file())
                if time.monotonic()>deadline or capture.stat().st_size>1024*1024 or output_size>64*1024*1024:
                    process.kill()
                    process.wait()
                    timed_out=True
                    break
                time.sleep(.1)
        except Exception:
            process.kill()
            process.wait()
            raise
        finally:
            if cleanup:
                cleanup()
    with capture.open('rb') as log:
        output=log.read(16000).decode('utf-8',errors='replace')
    return {'script':script.relative_to(root).as_posix(),'exit_code':process.returncode,'timeout':timed_out,'output':output,'files':manifest(case_id)}

def decode_text(data):
    try:
        return data.decode('utf-8-sig'),'utf-8'
    except UnicodeDecodeError:
        try:
            return data.decode('gb18030'),'gb18030'
        except UnicodeDecodeError:
            return data.decode('utf-8',errors='replace'),'utf-8-replace'

def execute(case_id,action,file='',args=None,allow_execution=False,allow_symbol_download=False,target_url='',allow_web_tools=False):
    args=args or {}
    allow_execution=allow_execution is True
    allow_symbol_download=allow_symbol_download is True
    allow_web_tools=allow_web_tools is True
    if action in {'skills_list','skill_search','skill_read'}:
        import skill_tools
        if action=='skills_list':return skill_tools.list_skills(args.get('query',''),args.get('limit',15))
        if action=='skill_search':return skill_tools.search(args.get('query',''),args.get('skill',''),args.get('limit',4))
        return skill_tools.read(args.get('skill',''),args.get('path','SKILL.md'),args.get('start',1),args.get('lines',70))
    if action in {'kb_search','kb_read'}:
        import knowledge_tools
        if action=='kb_search':
            return knowledge_tools.search(args.get('query',''),args.get('limit',4),args.get('scope',''))
        return knowledge_tools.read(args.get('path',file),args.get('start',1),args.get('lines',80),args.get('scope',''))
    if action in {'image_qr','image_ocr'}:
        import ctf_tools
        return ctf_tools.image_qr(case_id,file) if action=='image_qr' else ctf_tools.image_ocr(case_id,file,args)
    if action in {'rsa_analyze','linear_recurrence','png_repair','text_transforms','zip_repair_flags'}:
        import solver_tools
        if action=='rsa_analyze':return solver_tools.rsa_analyze(case_id,file,args)
        if action=='png_repair':return solver_tools.png_repair(case_id,file,args)
        if action=='zip_repair_flags':return solver_tools.zip_repair_flags(case_id,file)
        path=resolve_file(case_id,file)
        return solver_tools.linear_recurrence(path) if action=='linear_recurrence' else solver_tools.text_transforms(path)
    if action=='binwalk':
        import ctf_tools
        if not ctf_tools.status().get('binwalk'):
            raise ValueError('未找到本机 Binwalk')
        return ctf_tools.binwalk(case_id,file)
    if action=='foremost':
        import ctf_tools
        if not ctf_tools.status().get('foremost'):
            raise ValueError('未找到 foremost')
        return ctf_tools.foremost(case_id,file)
    if action=='stegoveritas':
        import ctf_tools
        if not ctf_tools.status().get('stegoveritas'):
            raise ValueError('未找到随波逐流 CTF 编码工具')
        return ctf_tools.stegoveritas(case_id,file)
    if action == 'tcp_exchange':
        import web_tools
        return web_tools.tcp_exchange(args)
    if action == 'own_ssh':
        import local_binary
        return local_binary.own_ssh((args or {}).get('command', ''))
    if action in {'local_checksec', 'local_objdump', 'local_r2', 'local_gdb'}:
        import local_binary
        path = resolve_file(case_id, file)
        if action == 'local_checksec':
            return local_binary.checksec(path)
        if action == 'local_objdump':
            return local_binary.objdump(path, args)
        if action == 'local_r2':
            return local_binary.radare(path)
        return local_binary.gdb_run(path, args)
    if action in {'web_request','web_discover','sqlmap'}:
        if not target_url:
            raise ValueError('Web 工具需要用户提供靶场地址')
        if action in {'web_discover','sqlmap'} and not allow_web_tools:
            raise ValueError('请先启用主动 Web 工具')
        import web_tools
        if action=='web_request':
            return web_tools.request(case_id,target_url,args)
        if action=='web_discover':
            return web_tools.discover(case_id,target_url)
        return web_tools.sqlmap(case_id,target_url,args)
    if action.startswith('wsl_'):
        import wsl_tools
        return wsl_tools.execute(case_id,action,file,args,allow_execution=allow_execution,allow_symbol_download=allow_symbol_download)
    if action=='python':
        return run_python(case_id,args.get('code',''))
    if action=='decode_layers':
        return decode_text_layers(resolve_file(case_id,file))
    path=resolve_file(case_id,file)
    if action=='subset_sum_lll':
        return subset_sum_lll(path)
    if action=='inspect':
        return inspect_file(path)
    if action=='strings':
        return strings_file(path,limit=100)
    if action=='search_bytes':
        return search_bytes(path,args)
    if action=='model_checkpoint_info':
        return model_checkpoint_info(path)
    if action=='read':
        offset=max(0,int(args.get('offset',0)))
        with path.open('rb') as stream:
            stream.seek(offset)
            data=stream.read(8192)
        text,encoding=decode_text(data)
        return {'offset':offset,'text':text,'encoding':encoding,'hex':data[:512].hex()}
    if action=='hex':
        offset=max(0,int(args.get('offset',0)))
        with path.open('rb') as stream:
            stream.seek(offset)
            data=stream.read(512)
        return {'offset':offset,'hex':data.hex()}
    if action=='disassemble':
        return disassemble(path,args)
    if action=='zip_list':
        with zipfile.ZipFile(path) as archive:
            return [{'name':i.filename,'bytes':i.file_size,'crc':f'{i.CRC:08x}','encrypted':bool(i.flag_bits&1)} for i in archive.infolist()[:300]]
    if action=='extract_zip':
        return extract_zip(case_id,path,args.get('password'))
    if action=='tshark_summary':
        tool=shutil.which('tshark')
        if not tool:
            raise ValueError('未安装tshark或未加入PATH')
        cmd=[tool,'-r',str(path),'-c','100','-T','fields','-e','frame.number','-e','ip.src','-e','ip.dst','-e','_ws.col.Protocol','-e','_ws.col.Info']
        result=subprocess.run(cmd,capture_output=True,timeout=20,shell=False)
        return {'exit_code':result.returncode,'output':(result.stdout+result.stderr)[:16000].decode(errors='replace')}
    raise ValueError('不支持的工具')
