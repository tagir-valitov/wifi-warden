import ssl
import socket
import hashlib
import requests

known_fingerprints = {}

def get_fingerprint(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert(binary_form=True)
            return hashlib.sha256(cert).hexdigest()

def check_https(domain):
    try:
        r = requests.get(f"http://{domain}", allow_redirects=True, timeout=5)
        return r.url.startswith("https://")
    except:
        return False

def check_tls(domain):
    if not check_https(domain):
        return True

    fp = get_fingerprint(domain)
    old = known_fingerprints.get(domain)
    known_fingerprints[domain] = fp

    return old is not None and old != fp