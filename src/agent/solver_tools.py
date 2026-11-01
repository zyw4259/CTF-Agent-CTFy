"""Bounded, verifiable operations used by common CTF writeups."""
import ast
import hashlib
import math
import re
import struct
import uuid
import zlib
from functools import lru_cache


def literals(source):
    values={}
    try:
        nodes=ast.walk(ast.parse(source))
        for node in nodes:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                try:
                    value=ast.literal_eval(node.value)
                except (ValueError,TypeError,RecursionError):
                    continue
                if type(value) is int or isinstance(value,list) and len(value)<=8192 and all(type(x) is int for x in value):
                    values[node.targets[0].id]=value
    except (SyntaxError,ValueError,RecursionError):
        pass
    for match in re.finditer(r'(?m)^\s*#\s*(\w+)\s*=\s*(\[[^\r\n]*\]|\d+)\s*$',source):
        try:
            values[match[1]]=ast.literal_eval(match[2])
        except (ValueError,SyntaxError,RecursionError):
            pass
    for match in re.finditer(r'(?<![A-Za-z0-9_])(n|e\d*|c\d*|p|q|dp|dq|d|phi)\s*[:=]\s*(0x[0-9a-f]+|\d+)',source,re.I):
        try:
            values[match[1].lower()]=int(match[2],0 if match[2].lower().startswith('0x') else 10)
        except ValueError:
            pass
    return values


def linear_recurrence(path):
    if path.stat().st_size>1024*1024:
        return {'detected':False}
    source=path.read_text(encoding='utf-8-sig',errors='replace')
    values=literals(source)
    initial=next((values[k] for k in ('initState','initial_state','initial') if isinstance(values.get(k),list)),None)
    outputs=next((values[k] for k in ('outputState','outputs','output_state') if isinstance(values.get(k),list)),None)
    if not initial or not outputs or not 2<=len(initial)<=512 or not len(initial)<=len(outputs)<=4096:
        return {'detected':False}
    if not all(type(x) is int and x in (0,1) for x in initial) or not all(type(x) is int and x>=0 and x.bit_length()<=8192 for x in outputs):
        return {'detected':False}
    width=len(initial)
    sequence=initial+outputs
    pivots={}
    for index,output in enumerate(outputs):
        row=sum((sequence[index+j]&1)<<j for j in range(width))|((output&1)<<width)
        for column in range(width):
            if (row>>column)&1:
                if column in pivots:
                    row^=pivots[column]
                else:
                    pivots[column]=row
                    break
        else:
            if (row>>width)&1:
                return {'detected':True,'solved':False,'reason':'线性方程矛盾，可能包含非线性项或噪声'}
    if len(pivots)!=width:
        return {'detected':True,'solved':False,'rank':len(pivots),'unknowns':width,'reason':'秩不足，不能唯一恢复反馈系数'}
    solution=0
    for column in range(width-1,-1,-1):
        row=pivots[column]
        bit=((row>>width)&1)^((row&solution).bit_count()&1)
        solution|=bit<<column
    mask=[(solution>>i)&1 for i in range(width)]
    mode='integer' if any(x>1 for x in outputs) else 'gf2'
    for index,expected in enumerate(outputs):
        actual=sum(sequence[index+j]*mask[j] for j in range(width))
        if (actual if mode=='integer' else actual&1)!=expected:
            return {'detected':True,'solved':False,'reason':'候选系数未通过全部原始递推式验证'}
    secret=''.join(map(str,mask))
    digest=hashlib.md5(secret.encode('ascii')).hexdigest()
    result={'detected':True,'solved':False,'verified':True,'mode':mode,'equations_verified':len(outputs),
            'rank':width,'secret':secret,'secret_md5':digest}
    wrapper=re.search(r'([A-Za-z][A-Za-z0-9_-]{1,31})\{md5\(secret\)\.hexdigest\(\)\}',source)
    if wrapper:
        result['plaintext']=wrapper[1]+'{'+digest+'}'
        result['solved']=True
    return result


def integer_root(value,degree):
    low,high=0,1<<((value.bit_length()+degree-1)//degree)
    while low<high:
        mid=(low+high+1)//2
        if mid**degree<=value:
            low=mid
        else:
            high=mid-1
    return low


def rsa_repeated_cipher_pairs(source_texts):
    pairs=[]
    pending=None
    for source in source_texts:
        for line in source.splitlines():
            match=re.fullmatch(r'\s*([nc])\s*=\s*([0-9]+)\s*',line,re.I)
            if not match:
                continue
            if match[1].lower()=='n':
                pending=match[2]
            elif pending is not None:
                pairs.append((pending,match[2]))
                pending=None
    return pairs


def rsa_analyze(case_id,file,args):
    import attachment_tools as tools
    import ctf_tools
    path=tools.resolve_file(case_id,file)
    sources=[path]
    sources.extend(p for p in path.parent.iterdir() if p!=path and p.is_file() and p.suffix.lower() in {'.py','.txt','.sage',''})
    values={};source_texts=[]
    for source in sources[:12]:
        if source.stat().st_size<=1024*1024:
            text,_=tools.decode_text(source.read_bytes())
            source_texts.append(text)
            values.update({k:v for k,v in literals(text).items() if type(v) is int and v.bit_length()<=16384})
    for key in ('n','e','c','e1','e2','c1','c2','p','q','dp','dq','d','phi'):
        if key in args:
            values[key]=int(str(args[key]),0) if str(args[key]).startswith('0x') else int(args[key])
    n,e,c=(values.get(k) for k in ('n','e','c'))
    p,q=values.get('p'),values.get('q')
    if c is None and type(e) is int and type(p) is int and type(q) is int and p>1 and q>1 and e>0:
        n=p*q
        phi=p*(p-1) if p==q else (p-1)*(q-1)
        if math.gcd(e,phi)!=1:
            return {'detected':True,'solved':False,'verified':False,'modulus':str(n),'phi':str(phi),
                    'reason':'已识别 p、q、e，但 e 与 phi(n) 不互素，无法求私钥指数 d'}
        d=pow(e,-1,phi)
        verified=(e*d)%phi==1
        result={'detected':True,'solved':verified,'verified':verified,'method':'private exponent from supplied p,q,e',
                'modulus':str(n),'phi':str(phi),'private_exponent':str(d),'secret':str(d),
                'verification':'(e*d) mod phi(n) = 1'}
        source_text='\n'.join(source_texts)
        if verified and re.search(r'd.{0,24}(?:as|作为).{0,16}(?:flag|flga)|(?:flag|flga).{0,16}d',source_text,re.I):
            result['flag_candidate']=f'flag{{{d}}}'
            result['plaintext']=result['flag_candidate']
        return result
    e1,e2,c1,c2=(values.get(k) for k in ('e1','e2','c1','c2'))
    if type(n) is int and type(e1) is int and type(e2) is int and type(c1) is int and type(c2) is int and n>1 and e1>1 and e2>1 and math.gcd(e1,e2)==1 and 0<=c1<n and 0<=c2<n:
        coefficient1=pow(e1,-1,e2)
        coefficient2=(1-e1*coefficient1)//e2
        try:
            base1=pow(c1,-1,n) if coefficient1<0 else c1
            base2=pow(c2,-1,n) if coefficient2<0 else c2
            message=(pow(base1,abs(coefficient1),n)*pow(base2,abs(coefficient2),n))%n
        except ValueError:
            message=None
        if message is not None and pow(message,e1,n)==c1 and pow(message,e2,n)==c2:
            result=rsa_plaintext(message,n,e1,c1,'common modulus attack')
            result['verified']=True
            result['reencryption_matches']=True
            result['verification']='both ciphertexts re-encrypt to the supplied values'
            return result
    raw_pairs=rsa_repeated_cipher_pairs(source_texts)
    exponent=values.get('e') if type(values.get('e')) is int else 3
    if len(raw_pairs)>=exponent>=2:
        base5=all(len(modulus)>=50 and len(ciphertext)>=50 and set(modulus+ciphertext)<=set('01234') for modulus,ciphertext in raw_pairs)
        pairs=[(int(modulus,5 if base5 else 10),int(ciphertext,5 if base5 else 10)) for modulus,ciphertext in raw_pairs]
        if all(0<=ciphertext<modulus for modulus,ciphertext in pairs) and all(math.gcd(pairs[i][0],pairs[j][0])==1 for i in range(len(pairs)) for j in range(i+1,len(pairs))):
            product=math.prod(modulus for modulus,_ in pairs)
            combined=sum(ciphertext*(product//modulus)*pow(product//modulus,-1,modulus) for modulus,ciphertext in pairs)%product
            message=integer_root(combined,exponent)
            if message**exponent==combined and all(pow(message,exponent,modulus)==ciphertext for modulus,ciphertext in pairs):
                result=rsa_plaintext(message,pairs[0][0],exponent,pairs[0][1],'Hastad broadcast attack')
                result['verified']=True
                result['reencryption_matches']=True
                result['ciphertexts_verified']=len(pairs)
                result['input_base']=5 if base5 else 10
                return result
    if not all(type(v) is int for v in (n,e,c)) or not (1<n and 1<=e and e.bit_length()<=16384 and 0<=c<n and n.bit_length()<=16384):
        return {'detected':False,'reason':'需要本题提供的 n、e、c 常量；不会执行上传源码'}
    tried=[]
    if 1<=e<=7:
        root=integer_root(c,e)
        tried.append('exact integer root')
        if pow(root,e)==c:
            return rsa_plaintext(root,n,e,c,'small exponent without wrap')
    for leak_key,prime_key in (('dp','p'),('dq','q')):
        leak=values.get(leak_key)
        if type(leak) is not int or leak<0 or e>1_000_000:
            continue
        tried.append(f'{leak_key} CRT exponent leakage')
        numerator=e*leak-1
        for k in range(1,e):
            if numerator%k:
                continue
            prime=numerator//k+1
            if prime<=1 or prime>=n or n%prime:
                continue
            p,q=(prime,n//prime) if prime_key=='p' else (n//prime,prime)
            phi=(p-1)*(q-1)
            if math.gcd(e,phi)!=1:
                continue
            d=pow(e,-1,phi)
            result=rsa_plaintext(pow(c,d,n),n,e,c,f'{leak_key} CRT exponent leakage')
            if result.get('verified'):
                result.update({'factors':[p,q],'private_exponent':str(d),'leaked_parameter':leak_key})
                return result
    # Wiener: test continued-fraction convergents, then verify the resulting factors.
    a,b=e,n
    numerator0,numerator1=0,1
    denominator0,denominator1=1,0
    while b:
        quotient,a,b=a//b,b,a%b
        k=quotient*numerator1+numerator0
        candidate_d=quotient*denominator1+denominator0
        numerator0,numerator1=numerator1,k
        denominator0,denominator1=denominator1,candidate_d
        if not k or (e*candidate_d-1)%k:continue
        phi=(e*candidate_d-1)//k
        total=n-phi+1
        discriminant=total*total-4*n
        if total>0 and discriminant>=0 and math.isqrt(discriminant)**2==discriminant:
            root=math.isqrt(discriminant)
            if (total+root)%2==0 and ((total+root)//2)*((total-root)//2)==n:
                return rsa_plaintext(pow(c,candidate_d,n),n,e,c,'Wiener continued fractions')
    tried.append('Wiener continued fractions')
    d=values.get('d') if type(values.get('d')) is int and values['d']>0 else None
    p=values.get('p') if type(values.get('p')) is int and values['p']>1 else None
    q=values.get('q') if type(values.get('q')) is int and values['q']>1 else None
    if not d and type(p) is int and n%p==0:
        q=n//p
    if not d and type(q) is int and n%q==0:
        p=n//q
    factors=[]
    factor_result=None
    if not d and not (p and q and p*q==n) and n.bit_length()<=320:
        factor_result=ctf_tools.factor_integer(case_id,n)
        factors=factor_result.get('factors',[])
        tried.append('local YAFU factorization')
        if len(factors)==2:
            p,q=factors
    if not d and p and q and p*q==n:
        phi=p*(p-1) if p==q else (p-1)*(q-1)
        if math.gcd(e,phi)==1:
            d=pow(e,-1,phi)
    if not d and type(values.get('phi')) is int and math.gcd(e,values['phi'])==1:
        d=pow(e,-1,values['phi'])
    if d:
        result=rsa_plaintext(pow(c,d,n),n,e,c,'known/factored private key')
        result['factors']=factors or ([p,q] if p and q else [])
        if factor_result:
            result['factor_log']=factor_result.get('log_file')
        return result
    return {'detected':True,'solved':False,'modulus_bits':n.bit_length(),'tried':tried,
            'factor_result':factor_result,'reason':'基础攻击未恢复私钥；可检索 Wiener、共模、广播或部分素数泄漏等方法'}


def rsa_plaintext(m,n,e,c,method):
    verified=pow(m,e,n)==c
    raw=m.to_bytes(max(1,(m.bit_length()+7)//8),'big')
    try:
        text=raw.decode('utf-8')
        readable=sum(c.isprintable() or c in '\r\n\t' for c in text)/max(1,len(text))>=0.95
    except UnicodeDecodeError:
        text=raw.decode('utf-8',errors='replace');readable=False
    return {'detected':True,'solved':verified and readable,'verified':verified,'method':method,'reencryption_matches':verified,
            'plaintext':text,'bytes_hex':raw.hex(),'needs_further_decoding':not readable}


def png_repair(case_id,file,args):
    import attachment_tools as tools
    path=tools.resolve_file(case_id,file)
    if path.stat().st_size>128*1024*1024:
        raise ValueError('PNG修复上限128MB')
    data=bytearray(path.read_bytes())
    if len(data)<33 or data[:16]!=b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR':
        raise ValueError('不是具有标准IHDR的PNG')
    stored=int.from_bytes(data[29:33],'big')
    width,height=struct.unpack('>II',data[16:24])
    if zlib.crc32(data[12:29])&0xffffffff==stored:
        return {'repaired':False,'crc_valid':True,'width':width,'height':height,'reason':'IHDR CRC已经正确'}
    limit=max(1,min(int(args.get('max_dimension',65535)),65535))
    candidates=set()
    for dimension in range(1,limit+1):
        for pair in ((width,dimension),(dimension,height)):
            header=b'IHDR'+struct.pack('>II',*pair)+data[24:29]
            if zlib.crc32(header)&0xffffffff==stored:
                candidates.add(pair)
    if len(candidates)!=1:
        return {'repaired':False,'crc_valid':False,'candidates':sorted(candidates),'reason':'不能唯一恢复单一宽/高字段；可能两者都被修改或CRC本身已损坏'}
    fixed_width,fixed_height=candidates.pop()
    data[16:24]=struct.pack('>II',fixed_width,fixed_height)
    output=tools.case_dir(case_id)/'output'/f'png-repair-{uuid.uuid4().hex[:8]}.png'
    output.write_bytes(data)
    return {'repaired':True,'verified':True,'crc_valid':True,'width':fixed_width,'height':fixed_height,
            'original_width':width,'original_height':height,'file':output.relative_to(tools.case_dir(case_id)).as_posix(),
            'next':'修复后的图片可用 image_ocr 读取文字或 image_qr 解码二维码。'}


def _multitap_options(encoded,limit=64):
    if not re.fullmatch(r'[2-9]{1,64}',encoded):
        return []
    keys={'2':'abc','3':'def','4':'ghi','5':'jkl','6':'mno','7':'pqrs','8':'tuv','9':'wxyz'}

    @lru_cache(maxsize=None)
    def split(key,count):
        if count==0:
            return ('',)
        options=[]
        for taps in range(min(len(keys[key]),count),0,-1):
            letter=keys[key][taps-1]
            for tail in split(key,count-taps):
                options.append(letter+tail)
                if len(options)>=limit:
                    return tuple(options)
        return tuple(options)

    runs=[(match.group(1),len(match.group(0))) for match in re.finditer(r'([2-9])\1*',encoded)]
    candidates=['']
    for key,count in runs:
        options=split(key,count)
        candidates=[prefix+suffix for prefix in candidates for suffix in options][:limit]
    unique=list(dict.fromkeys(candidates))
    return sorted(unique,key=lambda candidate:(len(candidate),candidate))


def _t9_flag_options(prefix_options,word_options,limit=16):
    flags=[]
    for prefix in prefix_options:
        bodies=['']
        for options in word_options:
            bodies=[(body+'_' if body else '')+word for body in bodies for word in options[:4]][:limit]
        flags.extend(prefix+'{'+body+'}' for body in bodies)
        if len(flags)>=limit:
            break
    return flags[:limit]


def text_transforms(path):
    if path.stat().st_size>65536:
        raise ValueError('古典文本分析上限64KB')
    text=path.read_text(encoding='utf-8-sig',errors='replace')
    candidates=[]
    frequencies=(8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,.153,.772,4.025,2.406,6.749,7.507,1.929,.095,5.987,6.327,9.056,2.758,.978,2.36,.15,1.974,.074)
    for line in text.splitlines()[:8]:
        clean=line.strip()
        if re.fullmatch('[ABab]{10,}',clean) and len(clean)%5==0:
            indices=[int(clean[i:i+5].upper().replace('A','0').replace('B','1'),2) for i in range(0,len(clean),5)]
            if max(indices)<26:
                decoded=''.join(chr(65+x) for x in indices)
                candidates.append({'method':'bacon26','text':decoded})
                for shift in range(26):
                    plaintext=''.join(chr((ord(c)-65+shift)%26+65) for c in decoded)
                    score=sum((plaintext.count(chr(65+i))-len(plaintext)*frequency/100)**2/(len(plaintext)*frequency/100) for i,frequency in enumerate(frequencies))
                    candidates.append({'method':'bacon26+caesar','shift':shift,'text':plaintext,'english_chi_square':round(score,3)})
    for match in re.finditer(r'([2-9]{4,16})\s*\{\s*([2-9]+(?:_[2-9]+)*)\s*\}',text):
        prefix,encoded_words=match.groups()
        words=encoded_words.split('_')
        if len(words)>12 or any(len(word)>64 for word in words):
            continue
        prefix_candidates=_multitap_options(prefix,512)
        prefix_candidates=[candidate for candidate in prefix_candidates if len(candidate)==len(prefix_candidates[0])][:8]
        word_candidates=[]
        for word in words:
            options=_multitap_options(word,512)
            word_candidates.append([candidate for candidate in options if len(candidate)==len(options[0])][:8])
        candidates.append({'method':'T9 multi-tap','prefix_candidates':prefix_candidates,
                           'word_candidates':word_candidates,
                           'likely_flag_options':_t9_flag_options(prefix_candidates,word_candidates),
                           'hint':'同一数字的连续按键次数可拆成多个字母；下划线分隔单词。按词义选择各候选，不要把数字密文当成 flag。'})
    candidates.sort(key=lambda x:x.get('english_chi_square',float('inf')))
    return {'reference_only':False,'candidates':candidates,'verified_plaintext':False,
            'hint':'这是变换候选，需要根据题目说明识别明文；不自动添加flag外壳。'}


def zip_repair_flags(case_id,file):
    import zipfile
    import attachment_tools as tools
    source=tools.resolve_file(case_id,file)
    if source.stat().st_size>64*1024*1024:raise ValueError('ZIP伪加密验证上限64MB')
    raw=bytearray(source.read_bytes())
    with zipfile.ZipFile(source) as archive:
        infos=archive.infolist()
        if len(infos)>5000 or sum(i.file_size for i in infos)>64*1024*1024:
            raise ValueError('ZIP伪加密验证解压总量上限64MB / 5000文件')
        if not any(i.flag_bits&1 for i in infos):return {'repaired':False,'reason':'目录没有设置加密标志'}
        offset=archive.start_dir
        for info in infos:
            if raw[offset:offset+4]!=b'PK\x01\x02' or raw[info.header_offset:info.header_offset+4]!=b'PK\x03\x04':
                raise ValueError('ZIP目录/本地头结构异常')
            for position in (offset+8,info.header_offset+6):
                flags=int.from_bytes(raw[position:position+2],'little')&~1
                raw[position:position+2]=flags.to_bytes(2,'little')
            name_len,extra_len,comment_len=struct.unpack_from('<HHH',raw,offset+28)
            offset+=46+name_len+extra_len+comment_len
    root=tools.case_dir(case_id)
    output=root/'output'/f'zip-flags-{uuid.uuid4().hex[:8]}.zip'
    output.write_bytes(raw)
    try:
        with zipfile.ZipFile(output) as archive:
            bad=archive.testzip()
        if bad:return {'repaired':False,'reason':'去除标志后文件CRC不匹配，不能认定为伪加密'}
    except (RuntimeError,zipfile.BadZipFile,zlib.error,NotImplementedError) as error:
        return {'repaired':False,'reason':'去除标志后仍无法验证内容，可能是真实加密','error':str(error)[:200]}
    return {'repaired':True,'verified':True,'all_member_crc_valid':True,
            'file':output.relative_to(root).as_posix(),'next':'用extract_zip读取这个经过CRC验证的副本。'}
