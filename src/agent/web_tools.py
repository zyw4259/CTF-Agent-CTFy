"""Origin-scoped HTTP and installed CTF web-tool adapters."""
import http.cookiejar
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from threading import Lock

BASE = Path(__file__).resolve().parent
TOOLS_ROOT = BASE.parent.parent.parent
SQLMAP = TOOLS_ROOT / '4.WEB' / 'sqlmap-ai' / 'sqlmap' / 'sqlmap.py'
FEROX = TOOLS_ROOT / '4.WEB' / 'x86_64-windows-feroxbuster.exe' / 'feroxbuster.exe'
PORTABLE_TOOLS=BASE.parent/'tools'
if (PORTABLE_TOOLS/'sqlmap'/'sqlmap.py').is_file():SQLMAP=PORTABLE_TOOLS/'sqlmap'/'sqlmap.py'
if (PORTABLE_TOOLS/'feroxbuster.exe').is_file():FEROX=PORTABLE_TOOLS/'feroxbuster.exe'
MAX_RESPONSE = 512 * 1024
JARS = {}
JAR_LOCK = Lock()
COMMON_PATHS = '''admin
administrator
api
backup
config
debug
dev
flag
flag.txt
index.php.bak
login
robots.txt
sitemap.xml
server-status
upload
uploads
static
templates
console
secret
hidden
test
source
src
.git
.env
www.zip
backup.zip
db.sql
'''


def _parts(url):
    url = str(url)
    if len(url) > 2048 or any(ord(char) < 32 or ord(char) == 127 or char.isspace() for char in url):
        raise ValueError('靶场 URL 过长或含有空白/控制字符')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('靶场地址必须是完整的 http:// 或 https:// URL')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('靶场地址不能包含用户名或密码')
    try:
        parsed_port = parsed.port
        port = parsed_port if parsed_port is not None else (443 if parsed.scheme.lower() == 'https' else 80)
    except ValueError as exc:
        raise ValueError('靶场端口无效') from exc
    if not 1 <= port <= 65535:
        raise ValueError('靶场端口无效')
    return parsed, (parsed.scheme.lower(), parsed.hostname.lower(), port)


def normalize_target(url):
    parsed, _ = _parts(url)
    netloc = parsed.netloc.lower()
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or '/', parsed.query, ''))


def _scope_allows(hostname):
    raw = os.environ.get('CTFY_SCOPE_HOSTS', '')
    host = str(hostname or '').lower().rstrip('.')
    if not raw or not host:
        return False
    for item in raw.split(','):
        item = item.strip().lower()
        if not item:
            continue
        if '://' in item:
            item = urllib.parse.urlsplit(item).hostname or ''
        if '/' in item:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                continue
            continue
        if host == item.split(':')[0]:
            return True
    return False


def _same_origin(target, candidate):
    _, expected = _parts(target)
    _, actual = _parts(candidate)
    return expected == actual or _scope_allows(actual[1])


def _target_url(target, args):
    raw = args.get('url') or args.get('path') or ''
    candidate = urllib.parse.urljoin(target, str(raw)) if raw else target
    if not _same_origin(target, candidate):
        raise ValueError('Web 工具只允许访问用户提供靶场的同源地址')
    parsed, _ = _parts(candidate)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', parsed.query, ''))


def _add_params(url, params):
    if not params:
        return url
    if not isinstance(params, dict) or len(params) > 40:
        raise ValueError('params 必须是最多40项的对象')
    if any(len(str(k)) > 128 or len(str(v)) > 4096 for k, v in params.items()):
        raise ValueError('URL 参数过长')
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.extend((str(k), str(v)) for k, v in params.items())
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ''))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def allowed_tcp_endpoints():
    allowed = {}
    for item in os.environ.get('CTFY_TCP_ENDPOINTS', '').split(','):
        parts = [part.strip() for part in item.split(':') if part.strip()]
        if len(parts) < 2:
            continue
        try:
            port = int(parts[1])
        except ValueError:
            continue
        if not 1 <= port <= 65535:
            continue
        allowed[(parts[0].lower(), port)] = len(parts) > 2 and parts[2] == 'tls'
    return allowed


def tcp_exchange(args):
    allowed = allowed_tcp_endpoints()
    host = str((args or {}).get('host') or '').strip().lower().rstrip('.')
    try:
        port = int((args or {}).get('port') or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError('TCP 端口无效') from exc
    if (host, port) not in allowed:
        raise ValueError('只允许连接任务公布的 TCP 地址')
    data = str((args or {}).get('data') or '')
    if len(data.encode('utf-8')) > 512:
        raise ValueError('发送内容最多512字节')
    use_tls = bool((args or {}).get('tls')) or allowed[(host, port)]
    raw = socket.create_connection((host, port), timeout=8)
    try:
        if use_tls:
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        raw.settimeout(3)

        def read_some():
            chunks = []
            total = 0
            try:
                while total < 8192:
                    part = raw.recv(4096)
                    if not part:
                        break
                    chunks.append(part)
                    total += len(part)
            except socket.timeout:
                pass
            return b''.join(chunks)

        banner = read_some()
        sent = data.encode('utf-8')
        if sent:
            raw.sendall(sent)
        reply = read_some()
    finally:
        raw.close()
    body = (banner + reply).decode('utf-8', 'replace')[:8000]
    return {'host': host, 'port': port, 'tls': use_tls, 'sent': data, 'body': body}


def request(case_id, target, args):
    url = _add_params(_target_url(target, args), args.get('params'))
    method = str(args.get('method', 'GET')).upper()
    if method not in {'GET', 'POST'}:
        raise ValueError('目前只允许 GET 和 POST')
    headers = {'User-Agent': 'CTF-Agent/1.0', 'Accept': 'text/html,application/json,text/plain,*/*'}
    supplied = args.get('headers') or {}
    if not isinstance(supplied, dict) or len(supplied) > 12:
        raise ValueError('headers 必须是最多12项的对象')
    blocked = {'host', 'cookie', 'authorization', 'proxy-authorization', 'content-length', 'connection', 'transfer-encoding'}
    for name, value in supplied.items():
        name, value = str(name).strip(), str(value)
        if not re.fullmatch(r'[A-Za-z0-9-]{1,64}', name) or name.lower() in blocked or len(value) > 2048 or '\r' in value or '\n' in value:
            raise ValueError('请求头名称或内容不允许')
        if name.lower() == 'referer' and not _same_origin(target, value):
            raise ValueError('Referer 只能指向同源靶场')
        headers[name] = value
    data = args.get('data')
    if method == 'GET' and (data is None or data == '' or data == {}):
        data = None
    body = None
    if method == 'POST' and data is not None:
        if isinstance(data, dict):
            if len(data) > 40:
                raise ValueError('POST 表单最多40项')
            body = urllib.parse.urlencode({str(k): str(v) for k, v in data.items()}).encode()
            headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        elif isinstance(data, str):
            body = data.encode('utf-8')
        else:
            raise ValueError('POST data 必须是字符串或表单对象')
        if len(body) > 32768:
            raise ValueError('POST 请求体最多32KB')
    elif data is not None:
        raise ValueError('GET 请求请把参数放进 params')
    with JAR_LOCK:
        jar = JARS.setdefault(case_id, http.cookiejar.CookieJar())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPCookieProcessor(jar))
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ValueError(f'HTTP 请求失败：{exc}') from exc
    with response:
        raw = response.read(MAX_RESPONSE + 1)
        truncated = len(raw) > MAX_RESPONSE
        raw = raw[:MAX_RESPONSE]
        content_type = response.headers.get('Content-Type', '')
        charset = re.search(r'charset\s*=\s*["\']?([^;"\']+)', content_type, re.I)
        encoding = charset.group(1).strip() if charset else 'utf-8'
        is_text = any(part in content_type.lower() for part in ('text/', 'json', 'xml', 'javascript', 'x-www-form-urlencoded'))
        if is_text:
            try:
                text = raw.decode(encoding, errors='replace')
            except LookupError:
                text = raw.decode('utf-8', errors='replace')
        else:
            text = ''
        result_headers = {k: response.headers.get(k, '')[:1000] for k in ('Content-Type', 'Location', 'Server') if response.headers.get(k)}
        if not is_text:
            text = '非文本响应；前512字节 hex：' + raw[:512].hex()
        return {'status': response.status, 'url': url, 'headers': result_headers,
                'bytes_read': len(raw), 'truncated': truncated, 'body': text[:12000]}


def _case_root(case_id):
    from attachment_tools import case_dir
    return case_dir(case_id)


def _tail(path, limit=16000):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - limit))
        return stream.read(limit).decode('utf-8', errors='replace')


def _case_cookies(case_id, url):
    with JAR_LOCK:
        jar = JARS.get(case_id)
    if not jar:
        return ''
    req = urllib.request.Request(url)
    jar.add_cookie_header(req)
    return str(req.get_header('Cookie') or '')[:4096]


def discover(case_id, target):
    if not FEROX.is_file():
        raise ValueError('未找到本机 Feroxbuster')
    root = _case_root(case_id)
    suffix = uuid.uuid4().hex[:8]
    wordlist = root / 'output' / f'paths-{suffix}.txt'
    output = root / 'output' / f'feroxbuster-{suffix}.json'
    wordlist.write_text(COMMON_PATHS, encoding='utf-8')
    scan_url = _target_url(target, {'path': target})
    parsed = urllib.parse.urlsplit(scan_url)
    scan_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
    command = [str(FEROX), '-u', scan_url, '-w', str(wordlist), '--no-recursion', '--dont-extract-links',
               '--no-state', '--json', '--quiet', '--threads', '4', '--scan-limit', '1', '--rate-limit', '5',
               '--timeout', '8', '--output', str(output)]
    cookies = _case_cookies(case_id, scan_url)
    if cookies:
        command.extend(['--headers', 'Cookie: ' + cookies])
    try:
        with (root / 'output' / f'feroxbuster-{suffix}.log').open('wb') as log:
            process = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       shell=False, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {'exit_code': process.returncode, 'timeout': True, 'output': 'Feroxbuster 超过90秒，已停止。'}
    except OSError as exc:
        raise ValueError(f'Feroxbuster 启动失败：{exc}') from exc
    entries = []
    if output.is_file():
        for line in output.read_text(encoding='utf-8', errors='replace').splitlines()[:300]:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    log_path = root / 'output' / f'feroxbuster-{suffix}.log'
    return {'exit_code': process.returncode, 'timeout': False, 'results': entries[:100],
            'log': _tail(log_path, 4000) if log_path.is_file() else ''}


def sqlmap(case_id, target, args):
    if not SQLMAP.is_file():
        raise ValueError('未找到本机 sqlmap')
    url = _add_params(_target_url(target, args), args.get('params'))
    data = args.get('data')
    if data is not None and not isinstance(data, str):
        raise ValueError('sqlmap 的 POST data 必须是字符串')
    if isinstance(data, str) and len(data) > 8192:
        raise ValueError('sqlmap 的 POST data 最多8KB')
    root = _case_root(case_id)
    suffix = uuid.uuid4().hex[:8]
    out_dir = root / 'output' / f'sqlmap-{suffix}'
    out_dir.mkdir()
    log_path = root / 'output' / f'sqlmap-{suffix}.log'
    command = [sys.executable, str(SQLMAP), '-u', url, '--batch', '--disable-coloring', '--ignore-redirects',
               '--level=1', '--risk=1', '--technique=BEUT', '--timeout=5', '--retries=0', '--threads=1',
               '--output-dir', str(out_dir)]
    cookies = _case_cookies(case_id, url)
    if cookies:
        command.extend(['--cookie', cookies])
    if data:
        command.extend(['--data', data])
    try:
        with log_path.open('wb') as log:
            process = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       shell=False, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return {'exit_code': process.returncode, 'timeout': True, 'output': _tail(log_path)}
    except OSError as exc:
        raise ValueError(f'sqlmap 启动失败：{exc}') from exc
    return {'exit_code': process.returncode, 'timeout': False, 'output': _tail(log_path)}


def status():
    return {'feroxbuster': FEROX.is_file(), 'sqlmap': SQLMAP.is_file()}
