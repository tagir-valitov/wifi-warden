import dns.resolver
import requests

TRUSTED_DOH_SERVERS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://doh.opendns.com/dns-query",
]

TRUSTED_DNS_SERVERS = [
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
]

def resolve_normal(domain):
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        return sorted([r.address for r in answers])
    except Exception:
        return []

def resolve_trusted_dns(domain):
    results = []
    for dns_server in TRUSTED_DNS_SERVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(domain, "A")
            ips = sorted([r.address for r in answers])
            if ips:
                results.append(ips)
        except Exception:
            continue
    
    if results:
        return results[0]
    return []

def resolve_doh(domain):
    for doh_server in TRUSTED_DOH_SERVERS:
        try:
            r = requests.get(
                doh_server,
                headers={"Accept": "application/dns-json"},
                params={"name": domain, "type": "A"},
                timeout=5,
                verify=True
            )
            if r.status_code == 200:
                data = r.json()
                ips = sorted([a["data"] for a in data.get("Answer", []) if a["type"] == 1])
                if ips:
                    return ips
        except Exception:
            continue
    return []

def check_dns_spoof(domain):
    normal_ips = resolve_normal(domain)
    trusted_ips = resolve_trusted_dns(domain)
    doh_ips = resolve_doh(domain)

    if not normal_ips and not trusted_ips and not doh_ips:
        return False
    if not normal_ips and (trusted_ips or doh_ips):
        return True

    if normal_ips:
        suspicious_ips = []
        for ip in normal_ips:
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    first_octet = int(parts[0])
                    second_octet = int(parts[1])
                    if (first_octet == 127 or 
                        first_octet == 10 or 
                        (first_octet == 172 and 16 <= second_octet <= 31) or
                        (first_octet == 192 and second_octet == 168)):
                        suspicious_ips.append(ip)
                except ValueError:
                    pass
        if suspicious_ips and len(suspicious_ips) == len(normal_ips):
            return True
    return False

