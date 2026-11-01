"""Read-only access to indexed methods and writeups; never executes their code."""
from pathlib import Path


def search(query,limit=4,scope=''):
    import app
    query=str(query).strip()[:1000]
    if not query:
        raise ValueError('知识库搜索需要具体技术词或题目特征')
    hits=app.search(query,limit=max(1,min(int(limit),5)),scope=str(scope)[:100])
    hits=[{**hit,'body':hit['body'][:600]} for hit in hits]
    return {'reference_only':True,'query':query,'hits':hits,
            'hint':'题解中的 flag 是参考资料，不能作为当前题目的解题结果。用 kb_read 按行或按 PDF 页读取原文。'}


def read(path,start=1,lines=80,scope=''):
    import app
    path=str(path).replace('\\','/')
    if scope and str(scope) not in path:
        raise ValueError('来源不在当前知识库范围内')
    root=app.KB.resolve()
    relative=path
    if path.startswith('参考补充/'):
        root=(app.BASE/'references').resolve()
        relative=path.removeprefix('参考补充/')
    elif path.startswith(app.PDF_KB_NAME+'/'):
        with app.connect() as c:
            row=c.execute('SELECT value FROM settings WHERE key=?',('pdf_kb',)).fetchone()
        source=row['value'] if row else ''
        if source.startswith('@bundle/'):
            root=(app.KB/source.removeprefix('@bundle/')).resolve()
        elif source:
            root=Path(source).resolve()
        elif app.PDF_KB:
            root=app.PDF_KB.resolve()
        relative=path.removeprefix(app.PDF_KB_NAME+'/')
    target=(root/relative).resolve()
    if not relative or not target.is_relative_to(root) or not target.is_file():
        raise ValueError('知识库来源路径无效')
    if target.suffix.lower()=='.pdf':
        if target.stat().st_size>app.PDF_MAX_BYTES:
            raise ValueError('PDF 超过20MB读取上限')
        executable=app.pdftotext_path()
        if not executable:
            raise ValueError('读取 PDF 需要 Poppler pdftotext')
        content=app.pdf_pages(target,executable)
        while content and not content[-1].strip():
            content.pop()
        total=len(content)
        start=max(1,int(start))
        end=min(total,start+max(1,min(int(lines),120))-1)
        selected=[]
        length=0
        for page_number in range(start,end+1):
            page=f'--- PDF 第 {page_number} 页 ---\n{content[page_number-1].strip()}'
            if length+len(page)+1>8000:
                if not selected:
                    selected.append(page[:7999])
                    end=page_number
                else:
                    end=page_number-1
                break
            selected.append(page)
            length+=len(page)+1
        return {'reference_only':True,'path':path,'start':start,'end':end,'total_lines':total,
                'total_pages':total,'body':'\n\n'.join(selected),
                'next_start':end+1 if end<total else None}
    if target.suffix.lower() not in {'.md','.py','.txt','.js','.sage'} or target.stat().st_size>2_000_000:
        raise ValueError('只支持2MB以内的知识库文本/脚本')
    content=target.read_text(encoding='utf-8-sig',errors='replace').splitlines()
    start=max(1,int(start))
    end=min(len(content),start+max(1,min(int(lines),120))-1)
    selected=[]
    length=0
    for line in content[start-1:end]:
        if length+len(line)+1>8000:
            if not selected:
                selected.append(line[:7999])
            break
        selected.append(line)
        length+=len(line)+1
    end=start+len(selected)-1
    return {'reference_only':True,'path':path,'start':start,'end':end,'total_lines':len(content),
            'body':'\n'.join(selected),'next_start':end+1 if end<len(content) else None}
