"""Small, deterministic prompt routing; challenge data never becomes system instructions."""
import re
from pathlib import Path

PRESETS={
    'general':{
        'label':'综合排查','description':'先辨认文件和线索，再选择具体解题路线。',
        'prompt':'先区分题目原始输入、容器和工具产物，确认实际文件类型及目标。用已有工具做低成本检查；读取匹配的WP方法，列出可由本题证据验证的下一步。线索不足时说明缺少的数据，避免无依据遍历所有工具。'},
    'encoding':{
        'label':'编码与古典密码','description':'多层Base、培根、凯撒、字符替换与异或。',
        'prompt':'根据字符集、长度、分组、填充和熵判断编码。优先decode_layers和text_transforms；从已成功解码的terminal_text继续。保留每层变换和原始字节；凯撒等候选需判断明文含义。遇到异或先寻找已知格式或密钥周期；不要把所有文本强行当成Base64。没有提交格式依据时不添加flag外壳。'},
    'image':{
        'label':'图片与隐写','description':'文件结构、PNG宽高、二维码、OCR与隐写线索。',
        'prompt':'先检查真实格式、尺寸、CRC和附加数据。PNG头异常时使用png_repair，再对修复产物调用image_qr/image_ocr。点阵二维码优先现有预处理。需要隐藏数据时再按WP检查通道、LSB或StegoVeritas产物。没有追加文件证据不要反复解压图片；OCR空格、下划线和相似字符须核对。'},
    'archive':{
        'label':'压缩包','description':'目录、密码线索、伪加密和CRC验证。',
        'prompt':'先zip_list确认成员、大小和加密标志，再extract_zip。已知密码放args.password；怀疑伪加密时用zip_repair_flags，必须通过成员CRC校验。真正加密不能只靠清除标志解密。解压成功后围绕实际成员继续分析；不要重复操作原ZIP，不执行成员中的程序或现成exp。'},
    'misc':{
        'label':'MISC 杂项','description':'非标准编码、T9、多媒体与混合线索。',
        'prompt':'先根据附件和题目描述确认具体表示方式。数字键盘、摩斯等多义变换用text_transforms列出候选，再按题意和词义筛选；不能把编码原串直接当flag。图像/二维码优先用image_qr、image_ocr和png_repair；压缩包用zip_list和extract_zip。未经独立证据验证的结果只能标成候选。'},
    'crypto':{
        'label':'Crypto 数学密码','description':'RSA、LFSR、格、约束求解与密码参数验证。',
        'prompt':'先读加密/生成代码，区分公开参数、秘密量和输出，检查是否缺参数。RSA优先rsa_analyze，线性反馈用linear_recurrence，子集和用subset_sum_lll。非标准方法先读对应WP，再适配本题变量与等式。需要矩阵、约束或AES时，在已启用WSL/Python且库可用时用wsl_math。没有SageMath时不得声称运行了Sage/Coppersmith。解密或恢复后重算原方程验证。'},
    'web':{
        'label':'Web 靶场与源码','description':'先读正常响应和源码，再验证具体入口。',
        'prompt':'有靶场先用web_request读取正常响应，记录表单、参数、Cookie、路由和错误；只有源码时先读入口及数据流。根据实际技术栈检索WP，围绕一个有证据的假设做对照请求。保留会话并比较响应差异，限制在已给靶场同源。未启用的扫描工具不可调用；源码掩码或WP示例flag不算服务端结果。'},
    'pwn':{
        'label':'PWN 二进制利用','description':'保护机制、输入路径、漏洞原语与地址证据。',
        'prompt':'先确认架构、libc/加载器、保护机制和交互协议；优先checksec、符号、反汇编和相关WP。定位输入长度、格式化字符串或堆操作，明确可控数据与利用原语。动态验证只在执行权限和隔离环境就绪时使用GDB；区分静态地址、泄漏地址和ASLR基址。远程地址或libc缺失须说明，不编造偏移，不把checksec当成已经利用成功。'},
    'reverse':{
        'label':'Reverse 逆向分析','description':'程序格式、关键函数、校验逻辑和约束还原。',
        'prompt':'先判断ELF/PE/APK等格式、架构、符号和壳线索。用字符串交叉定位校验入口，再读取有限范围反汇编或静态CFG；优先还原输入到输出的变换与常量。根据WP将算法转为受限脚本或约束，最后代回校验逻辑。未启用隔离执行时只做静态分析，不声称已经运行目标。'},
    'forensics':{
        'label':'取证与流量','description':'内存、磁盘、PCAP、偏移及原始证据。',
        'prompt':'先确认采集格式、时间范围、编码及目标。内存先识别系统和符号，再按线索检查进程、命令行、环境变量；空表不等于没有数据，可用search_bytes找UTF-16LE并记录上下文与偏移。磁盘使用mmls/fls/icat且分区偏移按扇区；流量先概要再跟进具体会话。大文件分块读取，区分扫描范围与完整扫描，保留可复核产物。'},
    'ai_ml':{
        'label':'AI / 模型附件','description':'安全查看权重、网络结构、输入与输出目标。',
        'prompt':'先区分权重、模型结构、预处理、样本和服务接口。用model_checkpoint_info或可用的wsl_torch_summary安全读取结构；不得用普通pickle加载不可信checkpoint。根据题意明确目标是推理、模型反演、对抗样本还是提示注入，再读相应WP。缺少网络结构或输入规范时说明缺失；权重形状摘要不等于已完成推理或攻击。'},
}

RULES={
    'encoding':r'base(?:16|32|58|64|85|91|92)|培根|凯撒|古典密码|多层编码|bacon|caesar|rot13|brainfuck|摩斯|\bxor\b|异或',
    'image':r'隐写|二维码|宽高|图像|图片|stegan|\b(?:png|jpeg|exif|ihdr|lsb|qrcode|qr|ocr)\b',
    'archive':r'压缩包|伪加密|已知明文|\b(?:zip|rar|7z|crc32|bkcrack)\b',
    'misc':r'杂项|\bmisc\b|\bt9\b|多击键|手机键盘|键盘编码|\b(?:stego|steganography|audio|wav|morse|qr.code)\b',
    'crypto':r'密码学|线性递推|格基|子集和|椭圆曲线|\b(?:crypto|rsa|aes|ecc|lfsr|prng|lwe|lll|coppersmith|wiener|initstate|outputstate|getprime)\b',
    'web':r'反序列化|文件包含|文件上传|原型链|注入|\b(?:web|http|php|ssti|ssrf|sqli|sqlmap|xss|jwt|unserialize|preg_match|flask)\b',
    'pwn':r'栈溢出|堆溢出|堆利用|格式化字符串|\b(?:pwn|ret2libc|ret2win|rop|use.after.free|tcache|double.free|canary)\b',
    'reverse':r'逆向|反编译|加壳|脱壳|\b(?:reverse|reversing|decompile|ida|ghidra|vmprotect|wasm|apk)\b',
    'forensics':r'取证|内存|环境变量|流量|磁盘|注册表|\b(?:forensics|pcap(?:ng)?|volatility|wireshark|tshark|ntfs|registry|hbc\.raw)\b',
    'ai_ml':r'模型反演|对抗样本|机器学习|神经网络|模型提取|权重|提示注入|\b(?:ai|ml|pytorch|torch|checkpoint|onnx|safetensors|adversarial|membership.inference|prompt.injection)\b',
}
SUFFIXES={
    'image':{'.png','.jpg','.jpeg','.bmp','.gif','.webp'},
    'archive':{'.zip','.rar','.7z'},
    'web':{'.php','.html','.htm','.jsp'},
    'reverse':{'.exe','.dll','.elf','.apk','.wasm'},
    'forensics':{'.raw','.mem','.vmem','.dmp','.pcap','.pcapng','.evtx','.e01','.vmdk'},
    'ai_ml':{'.pth','.pt','.ckpt','.onnx','.safetensors'},
}


def validate(requested):
    if not isinstance(requested,str) or requested not in {'auto',*PRESETS}:
        raise ValueError('未知的解题提示词预设')
    return requested


def catalog():
    return [{'id':'auto','label':'自动判断（推荐）','description':'按题目和实际工具结果选择策略，新线索出现后重新判断。'}]+[
        {'id':key,'label':value['label'],'description':value['description']} for key,value in PRESETS.items()]


def choose(question,files,steps=(),target_url='',requested='auto',source_text=''):
    validate(requested)
    if requested!='auto':
        return {'requested':requested,'ids':[requested],'label':PRESETS[requested]['label'],'reason':'手动选择'}
    scores={key:0 for key in RULES};reasons={key:[] for key in RULES}
    def add(key,points,reason):
        if reason not in reasons[key]:
            scores[key]+=points;reasons[key].append(reason)
    def keywords(text,weight,reason):
        for key,pattern in RULES.items():
            if re.search(pattern,text,re.I|re.ASCII):add(key,weight,reason)
    keywords(question[:1000],8,'题目描述')
    for key,pattern in [('crypto',r'密码学|\bcrypto(?:graphy)?\b'),('reverse',r'逆向|\breverse(?: engineering)?\b'),('misc',r'\bmisc\b|杂项'),('web',r'\bweb\b')]:
        if re.search(pattern,question[:1000],re.I|re.ASCII):add(key,20,'题目显式分类')
    keywords(source_text[:12000],4,'附件内容')
    expanded={s.get('file') for s in steps if s.get('action')=='extract_zip' and isinstance(s.get('result'),dict) and s['result'].get('directory')}
    for item in files[:24]:
        name=item.get('file','')
        if name in expanded or not name.startswith(('input/','output/extracted_')):continue
        suffix=Path(name).suffix.lower()
        for key,suffixes in SUFFIXES.items():
            if suffix in suffixes:add(key,3 if key=='archive' else 6,'附件类型')
        keywords(Path(name).name,3,'附件名称')
    for step in steps:
        result=step.get('result',{})
        if not isinstance(result,dict) or result.get('error') or result.get('reference_only'):continue
        if step.get('action')=='inspect' and step.get('file') not in expanded:
            key={'ELF':'reverse','PE/DOS':'reverse','PNG':'image','JPEG':'image','ZIP':'archive','PCAP':'forensics','PCAPNG':'forensics'}.get(result.get('type'))
            if key:add(key,3 if key=='archive' else 6,'文件头识别')
            preview=' '.join(str(row.get('text',''))[:240] for row in result.get('strings_preview',[])[:25] if isinstance(row,dict))
            keywords(preview[:4000],4,'附件字符串')
        action=step.get('action')
        if action=='decode_layers' and result.get('decoded_layers',0)>0:add('encoding',12,'实际解码结果')
        if action=='text_transforms' and result.get('candidates'):add('encoding',12,'密码变换候选')
        if action in {'rsa_analyze','linear_recurrence','subset_sum_lll'} and (result.get('detected') or result.get('solved')):add('crypto',12,'数学工具识别')
    if target_url:add('web',100,'提供了靶场地址')
    ranked=sorted(scores,key=scores.get,reverse=True)
    if target_url:
        challenge_type=next((key for key in ranked if key!='web' and scores[key]>=8),None)
        selected=[challenge_type,'web'] if challenge_type else ['web']
    else:
        selected=[key for key in ranked if scores[key]>=5][:1]
        if selected:
            primary=selected[0]
            secondary=next((key for key in ranked[1:] if key!='archive' and scores[key]>=max(8,scores[primary]/2)),None)
            if secondary:selected.append(secondary)
        else:selected=['general']
    return {'requested':'auto','ids':selected,'label':' + '.join(PRESETS[key]['label'] for key in selected),
            'reason':'；'.join(PRESETS[key]['label']+'：'+'、'.join(reasons[key][:3]) for key in selected if key in reasons) or '线索不足，先做综合排查'}


def instructions(selection):
    objective='''
首要目标：结合本题附件、靶场、知识库方法和已启用工具，找出并明确输出真实Flag；不要只给题型判断、思路或工具清单。
只有中间明文、解压文件、图片修复或权重摘要时，若存在可验证的下一步，应继续求解。先读WP方法，再适配本题数据；不能复制WP中的示例Flag。
成功时finish.answer首行写“Flag：实际完整字符串”，后面简述来源和验证依据。原题没有规定外壳时，不把候选明文擅自包装成flag{...}。
若缺少必要附件/参数、执行权限或在本轮预算内未解出，明确写“未获取可靠Flag”，保留实际中间结果并说明具体阻塞点；禁止为了满足输出要求编造Flag。
'''
    return objective+'\n本轮解题策略（按新证据调整；只使用已启用且可用的工具）：\n'+'\n'.join(
        f'【{PRESETS[key]["label"]}】{PRESETS[key]["prompt"]}' for key in selection['ids'])
