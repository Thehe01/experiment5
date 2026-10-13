"""Atomic state and bounded, ledgered source downloads."""
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class BindingError(ValueError):
    """An integrity failure must never be downgraded to source unavailability."""


def sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name+'.tmp')
    with temp.open('w') as f:
        json.dump(obj, f, ensure_ascii=False, sort_keys=True, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    os.replace(temp, path)


def read_json(path):
    return json.loads(Path(path).read_text())


def append_event(path, event):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as f:
        f.write(json.dumps(dict(at=time.time(), **event), ensure_ascii=False, sort_keys=True)+'\n'); f.flush(); os.fsync(f.fileno())


def download(url, cache, cfg, expected=None, min_interval=0):
    """The reservation counts persist across interruptions, including uncertain attempts."""
    cache = Path(cache); cache.parent.mkdir(parents=True, exist_ok=True)
    meta_path = cache.with_name(cache.name+'.receipt.json')
    temporary = cache.with_name(cache.name+'.tmp')
    if not cache.exists() and meta_path.exists():
        receipt = read_json(meta_path)
        if not temporary.exists() or receipt['url'] != url or sha_file(temporary) != receipt['sha256'] or (expected and expected != receipt['sha256']):
            raise BindingError('incomplete or corrupt receipted download')
        os.replace(temporary, cache)
    if cache.exists():
        if not meta_path.exists():
            raise BindingError('download bytes without receipt: '+str(cache))
        receipt = read_json(meta_path)
        if receipt['url'] != url or receipt['sha256'] != sha_file(cache) or (expected and expected != receipt['sha256']):
            raise BindingError('source cache binding mismatch')
        return cache, receipt
    state_path = cache.with_name(cache.name+'.request-state.json')
    state = read_json(state_path) if state_path.exists() else {'url': url, 'attempts': 0, 'last_sent': 0}
    if state['url'] != url:
        raise BindingError('request URL changed while resuming')
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.hostname in ('localhost','127.0.0.1','::1'):
        raise ValueError('unsupported source URL')
    last_error = None
    while state['attempts'] < cfg['download_attempts']:
        if min_interval:
            throttle = cache.parent / 'rate-limit.json'
            previous = read_json(throttle).get('last_sent', 0) if throttle.exists() else 0
            time.sleep(max(0, previous + min_interval - time.time()))
            atomic_json(throttle, {'last_sent': time.time()})
        state['attempts'] += 1; state['last_sent'] = time.time()
        atomic_json(state_path, state)
        append_event(cache.parent / 'requests.jsonl', {'event': 'reserved', 'url': url, 'attempt': state['attempts']})
        try:
            request = urllib.request.Request(url, headers={'User-Agent':'Chapter5AcademicExperiment/1.0','Accept':'application/json,text/html,*/*'})
            with urllib.request.urlopen(request, timeout=cfg['request_timeout_seconds']) as response:
                limit = cfg.get('response_limit_bytes', 64 * 1024 * 1024)
                body = response.read(limit + 1)
                content_type = response.headers.get('Content-Type', '')
            if len(body) > limit:
                raise ValueError('source exceeds bounded response size')
            sha = hashlib.sha256(body).hexdigest()
            if expected and sha != expected:
                raise BindingError('frozen source SHA256 mismatch')
            tmp = cache.with_name(cache.name+'.tmp'); tmp.write_bytes(body)
            receipt = {'url': url, 'sha256': sha, 'bytes':len(body), 'content_type':content_type, 'attempts':state['attempts'], 'retrieved_at':time.time()}
            # Receipt precedes rename. A crash here cannot make unbound bytes look valid.
            atomic_json(meta_path, receipt); os.replace(tmp, cache)
            append_event(cache.parent / 'requests.jsonl', {'event':'success','url':url,'sha256':sha})
            return cache, receipt
        except BindingError:
            raise
        except (OSError, urllib.error.URLError, ValueError) as exc:
            last_error = str(exc)
            append_event(cache.parent / 'requests.jsonl', {'event':'failure','url':url,'attempt':state['attempts'],'error':last_error})
            if isinstance(exc, ValueError):
                break
            if state['attempts'] < cfg['download_attempts']:
                time.sleep(min(12, 2 ** state['attempts']))
    raise RuntimeError('source request budget exhausted: '+url+'; '+str(last_error))
