"""Local Linux binary inspection for the CTFy container.

These actions read or run only a file inside the current case. They do not
accept a shell command.
"""
import re
import shutil
import subprocess
from pathlib import Path


def available():
    names = ('readelf', 'objdump', 'gdb', 'r2', 'ssh', 'sshpass')
    return {name: bool(shutil.which(name)) for name in names}


def _run(argv, timeout):
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or '') + (exc.stderr or ''))[:12000]
        return {'exit_code': 124, 'timeout': True, 'output': output}
    output = ((completed.stdout or '') + (completed.stderr or ''))[:12000]
    return {'exit_code': completed.returncode, 'timeout': False, 'output': output}


def checksec(path):
    header = _run(['readelf', '-h', '-l', '-W', '--', str(path)], 20)
    symbols = _run(['readelf', '-s', '-W', '--', str(path)], 20)
    text = header.get('output', '')
    syms = symbols.get('output', '')
    stack = re.search(r'GNU_STACK\s+\S+\s+\S+\s+(\S+)', text)
    return {
        'pie': 'DYN' in text and 'Type:' in text,
        'nx': bool(stack and 'E' not in stack.group(1)),
        'relro': 'GNU_RELRO' in text,
        'bind_now': 'BIND_NOW' in text,
        'canary': '__stack_chk_fail' in syms,
        'header': text[:4000],
    }


def objdump(path, args):
    try:
        address = max(0, int(str((args or {}).get('address', '0')), 0))
        size = min(max(int((args or {}).get('size', 2048)), 64), 4096)
    except (TypeError, ValueError) as exc:
        raise ValueError('反汇编地址或长度无效') from exc
    return _run(['objdump', '-d', f'--start-address={address}', f'--stop-address={address + size}', '--', str(path)], 30)


def radare(path):
    if not shutil.which('r2'):
        raise ValueError('容器里没有 radare2')
    return _run(['r2', '-q', '-e', 'scr.color=0', '-c', 'aaa; afl; pd 60 @ entry0', str(path)], 60)


def gdb_run(path, args):
    if not shutil.which('gdb'):
        raise ValueError('容器里没有 gdb')
    argv_args = (args or {}).get('argv') or []
    if not isinstance(argv_args, list) or len(argv_args) > 16 or any(not isinstance(item, str) or len(item) > 200 for item in argv_args):
        raise ValueError('程序参数需要是最多16个短字符串')
    return _run(['gdb', '--quiet', '--batch', '--nx',
                 '-ex', 'set pagination off', '-ex', 'set confirm off', '-ex', 'run',
                 '-ex', 'bt', '-ex', 'info registers', '--args', str(path), *argv_args], 20)


def own_ssh(command):
    command = str(command or '').strip()
    if not command or len(command) > 300 or '\n' in command or '\r' in command or '\x00' in command:
        raise ValueError('只允许一条不超过300字符的命令')
    host = os_env('CTFY_OWN_SSH_HOST')
    user = os_env('CTFY_OWN_SSH_USER')
    port = os_env('CTFY_OWN_SSH_PORT') or '22'
    key_dir = os_env('CTFY_OWN_SSH_DIR')
    if not host or not user or not key_dir:
        raise ValueError('还没有本队主机的 SSH 凭据')
    base = ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-p', port]
    key = Path(key_dir) / 'key'
    cert = Path(key_dir) / 'key-cert.pub'
    if key.is_file():
        base += ['-i', str(key)]
    if cert.is_file():
        base += ['-o', f'CertificateFile={cert}']
    argv = base + [f'{user}@{host}', command]
    if not key.is_file() and shutil.which('sshpass') and os_env('CTFY_OWN_SSH_PASSWORD_FILE'):
        argv = ['sshpass', '-f', os_env('CTFY_OWN_SSH_PASSWORD_FILE'), *argv]
    result = _run(argv, 25)
    result['host'] = host
    return result


def os_env(name):
    import os
    return os.environ.get(name, '').strip()
