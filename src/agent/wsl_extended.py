"""Fixed, bounded entry points for the installed CTF dependency tools."""
import re
import uuid

SPECS={
    'wsl_pngcheck':('pngcheck','PNG结构与CRC检查'),
    'wsl_zbar':('zbarimg','离线条码与二维码'),
    'wsl_image_info':('magick','ImageMagick图像信息'),
    'wsl_stegseek':('stegseek','隐写种子/限时字典'),
    'wsl_fcrackzip':('fcrackzip','ZIP限时字典'),
    'wsl_jadx':('jadx','APK/DEX静态Java反编译'),
    'wsl_exiftool':('exiftool','Exif/文档元数据'),
    'wsl_zsteg':('zsteg','PNG/BMP低位隐写'),
    'wsl_steghide_info':('steghide','隐写文件信息'),
    'wsl_steghide_extract':('steghide','已知密码提取隐写'),
    'wsl_foremost':('foremost','小附件文件雕刻'),
    'wsl_ffprobe':('ffprobe','音视频流与格式'),
    'wsl_audio_wav':('ffmpeg','导出前5分钟单声道WAV'),
    'wsl_pcapfix':('pcapfix','修复流量文件副本'),
    'wsl_r2':('radare2','静态函数与main反汇编'),
    'wsl_ropgadgets':('ROPgadget','ROP gadgets'),
    'wsl_one_gadget':('one_gadget','libc one_gadget'),
    'wsl_pycdc':('pycdc','Python字节码反编译'),
    'wsl_pycdas':('pycdas','Python字节码反汇编'),
    'wsl_upx_unpack':('upx','UPX解包副本'),
    'wsl_apktool':('apktool','APK资源与smali解码'),
    'wsl_zip2john':('zip2john','提取ZIP哈希'),
    'wsl_hashid':('hashid','离线哈希类型识别'),
    'wsl_hashcat':('hashcat','离线哈希识别/限时字典'),
    'wsl_john':('john','离线哈希显示/限时字典'),
    'wsl_hash_extend':('hash_extender','哈希长度扩展'),
    'wsl_rsactftool':('RsaCtfTool','离线RSA攻击'),
    'wsl_yara':('yara','题目内规则扫描'),
    'wsl_strace':('strace','隔离系统调用跟踪'),
    'wsl_ltrace':('ltrace','隔离库调用跟踪'),
    'wsl_qemu_run':('qemu-x86_64','隔离x86-64用户态模拟'),
    'wsl_seccomp_dump':('seccomp-tools','隔离运行并提取seccomp'),
    'wsl_ghidra':('@ghidra','静态反编译关键函数'),
    'wsl_qiling_run':('@qiling','隔离Qiling Linux x86-64模拟'),
}
ACTIONS=set(SPECS)
DYNAMIC={'wsl_strace','wsl_ltrace','wsl_qemu_run','wsl_seccomp_dump','wsl_qiling_run'}


def available(environment):
    tools=set(environment.get('sandbox_tools',[]));runtimes=environment.get('runtimes',{})
    return [{'action':action,'label':label,'dynamic':action in DYNAMIC} for action,(tool,label) in SPECS.items()
            if environment.get('sandbox_ready') and (tool in tools or (tool.startswith('@') and tool[1:] in runtimes))
            and (action!='wsl_qiling_run' or 'qiling_rootfs' in runtimes)]


def execute(case_id,action,file,args,allow_execution=False):
    import attachment_tools as tools
    import wsl_tools as wsl
    env=wsl.status();args=args or {};root=tools.case_dir(case_id)
    if action not in {item['action'] for item in available(env)}:raise ValueError('此工具在隔离环境中尚未就绪')
    if action in DYNAMIC and allow_execution is not True:raise ValueError('请先允许在隔离环境中运行上传程序')
    target=tools.resolve_file(case_id,file)
    path='/tmp/'+target.relative_to(root).as_posix()
    token=uuid.uuid4().hex[:8];artifact=None;stdin=b''
    def local(name):return '/tmp/'+tools.resolve_file(case_id,str(name)).relative_to(root).as_posix()
    def output(name):
        nonlocal artifact
        artifact=root/'output'/name
        return '/tmp/output/'+name
    password=str(args.get('password',''))
    if len(password)>256:raise ValueError('密码最多256字符')
    if action=='wsl_pngcheck':argv=['pngcheck','-v',path]
    elif action=='wsl_zbar':argv=['zbarimg','--quiet',path]
    elif action=='wsl_image_info':argv=['magick','identify','-limit','memory','256MiB','-limit','map','512MiB','-ping','-verbose',path+'[0]']
    elif action=='wsl_stegseek':
        destination=output('stegseek-'+token+'.bin')
        argv=['stegseek',path,local(args['wordlist']),destination] if args.get('wordlist') else ['stegseek','--seed',path,destination]
    elif action=='wsl_fcrackzip':
        if not args.get('wordlist'):raise ValueError('ZIP字典尝试需要题目目录内的wordlist文件')
        argv=['fcrackzip','-D','-p',local(args['wordlist']),'-u',path]
    elif action=='wsl_jadx':
        if target.stat().st_size>128*1024*1024:raise ValueError('Java反编译单次最多128MB')
        argv=['jadx','--no-res','--threads-count','2','--output-dir',output('jadx-'+token),path]
    elif action=='wsl_exiftool':argv=['exiftool','-j','-G','-a','-s','--',path]
    elif action=='wsl_zsteg':argv=['zsteg','-a',path]
    elif action=='wsl_steghide_info':argv=['steghide','info',path,'-p',password]
    elif action=='wsl_steghide_extract':argv=['steghide','extract','-sf',path,'-p',password,'-xf',output('steghide-'+token+'.bin'),'-f']
    elif action=='wsl_foremost':
        if target.stat().st_size>128*1024*1024:raise ValueError('文件雕刻单次最多128MB，请先按偏移提取相关区域')
        argv=['foremost','-Q','-i',path,'-o',output('carved-'+token)]
    elif action=='wsl_ffprobe':argv=['ffprobe','-v','error','-show_format','-show_streams','-print_format','json',path]
    elif action=='wsl_audio_wav':argv=['ffmpeg','-nostdin','-v','error','-i',path,'-t','300','-vn','-ac','1','-ar','16000',output('audio-'+token+'.wav')]
    elif action=='wsl_pcapfix':argv=['pcapfix','-o',output('repaired-'+token+'.pcap'),path]
    elif action=='wsl_r2':
        function=str(args.get('function','main'))
        if not re.fullmatch(r'(?:[A-Za-z_.$?][A-Za-z0-9_.$?]*|0x[0-9a-fA-F]+)',function):raise ValueError('function只接受符号名或十六进制地址')
        command=f'af @ {function};pdf @ {function}' if function.startswith('0x') else f'afl~{function};pdf @ {function}'
        argv=['radare2','-N','-2','-q','-e','scr.color=0','-A','-c',command,path]
    elif action=='wsl_ropgadgets':argv=['ROPgadget','--binary',path,'--depth',str(min(max(int(args.get('depth',5)),2),8))]
    elif action=='wsl_one_gadget':argv=['one_gadget','--level','0',path]
    elif action in {'wsl_pycdc','wsl_pycdas'}:argv=[SPECS[action][0],path]
    elif action=='wsl_upx_unpack':argv=['upx','-d','-o',output('unpacked-'+token+'.bin'),path]
    elif action=='wsl_apktool':
        if target.stat().st_size>128*1024*1024:raise ValueError('APK解码单次最多128MB')
        argv=['apktool','d','-f','-o',output('apk-'+token),path]
    elif action=='wsl_zip2john':argv=['zip2john',path]
    elif action=='wsl_hashid':argv=['hashid',path]
    elif action=='wsl_hashcat':
        if args.get('wordlist'):
            mode=int(args.get('mode',0))
            if not 0<=mode<=400000:raise ValueError('无效的hashcat哈希模式')
            argv=['hashcat','-D','1','-w','1','--runtime','60','--restore-disable','--potfile-path',output('hashcat-'+token+'.pot'),'-m',str(mode),path,local(args['wordlist'])]
        else:argv=['hashcat','--identify',path]
    elif action=='wsl_john':
        argv=['john','--pot='+output('john-'+token+'.pot')]
        if args.get('wordlist'):argv+=['--wordlist='+local(args['wordlist']),'--max-run-time=60','--session=/tmp/output/john-'+token]
        else:argv+=['--show']
        if args.get('format'):
            fmt=str(args['format'])
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,50}',fmt):raise ValueError('无效的John格式名称')
            argv+=['--format='+fmt]
        argv.append(path)
    elif action=='wsl_hash_extend':
        algorithm=str(args.get('algorithm','sha256'));signature=str(args.get('signature',''));append=str(args.get('append_hex',''));length=int(args.get('secret_length',0))
        if algorithm not in {'md4','md5','sha1','sha256','sha512','ripemd160','whirlpool'} or not re.fullmatch(r'[0-9a-fA-F]{32,128}',signature) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,4096}',append) or not 0<=length<=1024:
            raise ValueError('长度扩展需要有效算法、十六进制摘要/追加数据和0到1024的秘密前缀长度')
        argv=['hash_extender','--file='+path,'--signature='+signature,'--format='+algorithm,'--append='+append,'--append-format=hex','--secret='+str(length)]
    elif action=='wsl_rsactftool':
        attacks=args.get('attacks',['wiener','fermat'])
        if not isinstance(attacks,list) or not attacks or len(attacks)>5 or any(name not in {'wiener','fermat','pollard_p_1','smallq','common_factors','hastads','boneh_durfee'} for name in attacks):raise ValueError('请选择最多5种已适配的离线RSA攻击')
        argv=['RsaCtfTool','--publickey',path,'--private','--timeout','45','--attack',*attacks]
    elif action=='wsl_yara':
        if not args.get('rules'):raise ValueError('请提供题目目录内的YARA规则文件')
        argv=['yara','-w','-m',local(args['rules']),path]
    elif action in {'wsl_strace','wsl_ltrace','wsl_qemu_run','wsl_seccomp_dump'}:
        argv={'wsl_strace':['strace','-f','-qq','-s','128',path],
              'wsl_ltrace':['ltrace','-f','-s','128',path],
              'wsl_qemu_run':['qemu-x86_64',path],
              'wsl_seccomp_dump':['seccomp-tools','dump',path]}[action]
        if args.get('stdin_file'):
            input_file=tools.resolve_file(case_id,str(args['stdin_file']))
            if input_file.stat().st_size>65536:raise ValueError('标准输入最多64KB')
            stdin=input_file.read_bytes()
    elif action=='wsl_qiling_run':
        code='import sys;from qiling import Qiling;from qiling.const import QL_VERBOSE;q=Qiling([sys.argv[1]],sys.argv[2],verbose=QL_VERBOSE.OFF);q.run(timeout=30000000,count=10000000)'
        argv=[env['runtimes']['qiling'],'-I','-c',code,path,env['runtimes']['qiling_rootfs']]
    elif action=='wsl_ghidra':
        script=root/'output'/'CTFDecompile.java'
        script.write_text('''import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class CTFDecompile extends GhidraScript {
 public void run() throws Exception {
  DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
  try(PrintWriter out=new PrintWriter(getScriptArgs()[0])) {
   FunctionIterator fs=currentProgram.getFunctionManager().getFunctions(true); int count=0;
   while(fs.hasNext() && count<12 && !monitor.isCancelled()) {
    Function f=fs.next();String name=f.getName().toLowerCase();
    if(!(name.equals("main")||name.equals("entry")||name.contains("check")||name.contains("flag")||name.contains("verify")))continue;
    DecompileResults r=d.decompileFunction(f,10,monitor);
    if(r.decompileCompleted()){out.println(r.getDecompiledFunction().getC());count++;}
   }
   out.println("// Exported functions: "+count);
  } finally {d.dispose();}
 }
}''',encoding='utf-8')
        project=root/'output'/('ghidra-'+token);project.mkdir()
        destination=output('decompiled-'+token+'.c')
        argv=[env['runtimes']['ghidra'],'/tmp/output/'+project.name,'ctf','-import',path,'-analysisTimeoutPerFile','120','-scriptPath','/tmp/output','-postScript','CTFDecompile.java',destination]
    else:raise ValueError('不支持的扩展工具')
    prefix=wsl._sandbox_prefix(root)
    if action=='wsl_hashcat':
        for path in ('/sys/devices/system/cpu','/sys/devices/system/node'):
            prefix[-1:-1]=['--ro-bind',path,path]
        for name,value in {'POCL_MEMORY_LIMIT':'1','POCL_CPU_MAX_CU_COUNT':'2'}.items():
            prefix[-1:-1]=['--setenv',name,value]
    for name,value in {'HOME':'/tmp/output','TMPDIR':'/tmp/output','_JAVA_OPTIONS':'-Xshare:off -Xms64m -Xmx1024m -Xss512k -XX:MaxMetaspaceSize=256m -XX:-UseCompressedClassPointers -XX:-UseCompressedOops -XX:+UseSerialGC -XX:ReservedCodeCacheSize=128m -XX:ActiveProcessorCount=2','OMP_NUM_THREADS':'2','POCL_MAX_PTHREAD_COUNT':'2','POCL_CACHE_DIR':'/tmp/output/.pocl'}.items():
        prefix[-1:-1]=['--setenv',name,value]
    sink=root/'output'/('zip-hashes-'+token+'.txt') if action=='wsl_zip2john' else None
    result=wsl._run_supervised(env['sandbox_distro'],root,prefix+argv,stdin=stdin,timeout=240 if action=='wsl_ghidra' else 120,memory_mb=6144 if action=='wsl_ghidra' else 4096,open_files=1024 if action=='wsl_ghidra' else 128,output_file=sink)
    if sink and sink.exists():
        artifact=sink
        with sink.open('rb') as stream:result['output']=stream.read(4000).decode('utf-8','replace')
    result['sandboxed']=True
    if artifact and artifact.exists():result['artifact']=artifact.relative_to(root).as_posix()
    result['files']=tools.manifest(case_id)
    return result
