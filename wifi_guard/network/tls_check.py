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

# Причём здесь WiFi? На https тебя обычно переводит ответ сервера 301 Moved Permanently или подобный.
# http://google.com перенаправляет тебя на http://www.google.com, но на этом всё
def check_https(domain):
    try:
        r = requests.get(f"http://{domain}", allow_redirects=True, timeout=5)
        return r.url.startswith("https://")
    except:
        return False

def check_tls(domain):
    # Из-за этого check_https у меня сеть считается небезопасной >:|
    # И из-за него, поскольку домен google.com не переводит тебя на https,
    # ничего ниже return True никогда не исполняется. Печально.
    if not check_https(domain):
        return True

    # К тому же, почему все check_функции (совершенно правильно) возвращают True, когда всё хорошо,
    # и False, когда всё плохо, а эта - наоборот?
    # Вроде из-за того, что результат передаётся в calculate_risk, да. Он ожидает True, когда всё плохо.
    # Но с check_dns_spoof вроде понятно, что True - это spoof есть, False - spoof отсутствует.
    # Здесь же, если я вызову check_tls и получу True, я подумаю, что TLS в моей системе правильно работает.
    # Хотя на самом деле True означает ошибку.

    # known_fingerprints нигде до этого не наполняется, и check_tls используется
    # всего 1 раз. Откуда в known_fingerprints что-то будет?
    fp = get_fingerprint(domain)
    old = known_fingerprints.get(domain)
    known_fingerprints[domain] = fp

    return old is not None and old != fp
