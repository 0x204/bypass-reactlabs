import re
import requests
from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

class Fail(Exception):
    pass

def get_ck(raw):
    def d(m): return chr(int(m.group(1), 16))
    src = re.sub(r'\\x([A-F0-9]{2})', d, raw)
    keys = re.findall(r'[a-f0-9]{32}', src)
    if len(keys) < 3:
        raise Fail('keys?')
    k, iv, data = map(unhexlify, keys[:3])
    name_match = re.search(r'[a-z0-9]{32}","cookie","([^"=]+)', src, re.I)
    if not name_match:
        raise Fail('name?')
    name = name_match.group(1)
    dec = AES.new(k, AES.MODE_CBC, iv).decrypt(data)
    val = hexlify(dec).decode()
    info_match = re.search(r'(expires=[^"]+)', src, re.I)
    info = info_match.group(1) if info_match else None
    out = f"{name}={val}{'; ' + info if info else ';'}"
    return {'cookie': out, 'cookieName': name, 'cookieValue': val, 'cookieInfo': info}

def go(url, hdr=None):
    if not hdr:
        hdr = {}
    s = requests.Session()
    r = s.get(url, headers=hdr)
    t = r.text
    if 'navigator.userAgent' in t or 'slowAES' in t:
        try:
            c = get_ck(t)
            h = dict(hdr)
            h['Cookie'] = c['cookie']
            r2 = s.get(url, headers=h)
            return r2.text
        except Exception as e:
            raise
    else:
        return t

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('usage: py main.py url')
        sys.exit(1)
    u = sys.argv[1]
    res = go(u)
    print(f'HTML: {res}...')
