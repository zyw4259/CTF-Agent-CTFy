"""One local model endpoint shared by the launcher, Q&A and attachment agent."""
import json
import os
import urllib.request

DEFAULT_PORT=18080


def base_url():
    return os.environ.get('CTF_AGENT_MODEL_URL',f'http://127.0.0.1:{DEFAULT_PORT}').rstrip('/')


def endpoint(path):
    return base_url()+'/'+path.lstrip('/')


def check_model(url=None,alias='ctf-qwen',timeout=2):
    url=(url or base_url()).rstrip('/')
    try:
        with urllib.request.urlopen(url+'/v1/models',timeout=timeout) as response:
            models=json.loads(response.read(16384).decode('utf-8-sig'))
        if not isinstance(models,dict) or not isinstance(models.get('data'),list):
            raise ValueError('模型列表格式不正确')
        if not any(isinstance(item,dict) and item.get('id')==alias for item in models['data']):
            raise ValueError(f'未提供模型 {alias}')
        with urllib.request.urlopen(url+'/health',timeout=timeout) as response:
            if response.status!=200:raise ValueError('模型尚未就绪')
    except (json.JSONDecodeError,UnicodeDecodeError) as error:
        raise RuntimeError(f'{url}/v1/models 返回空内容或非JSON') from error
    except (OSError,ValueError) as error:
        raise RuntimeError(f'{url} 不是已就绪的 {alias} 模型服务：{error}') from error


def ready(url=None,alias='ctf-qwen',timeout=.5):
    try:
        check_model(url,alias,timeout)
        return True
    except RuntimeError:
        return False
