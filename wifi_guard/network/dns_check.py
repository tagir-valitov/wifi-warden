import dns.resolver
import requests

def resolve_normal(domain):
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        return sorted([r.address for r in answers])
    except:
        return []

def resolve_doh(domain):
    try:
        r = requests.get(
            "https://cloudflare-dns.com/dns-query",
            headers={"Accept": "application/dns-json"},
            params={"name": domain, "type": "A"},
            timeout=5
        )
        data = r.json()
        return sorted([a["data"] for a in data.get("Answer", []) if a["type"] == 1])
    except:
        return []

def check_dns_spoof(domain):
    return resolve_normal(domain) != resolve_doh(domain)