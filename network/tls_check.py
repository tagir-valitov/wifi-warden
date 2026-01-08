import ssl
import socket
import hashlib

KNOWN_FINGERPRINTS = {}

known_fingerprints = {}

def get_fingerprint(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                return hashlib.sha256(cert).hexdigest()
    except Exception:
        return None

def check_certificate_validity(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer_dict = {}
                subject_dict = {}
                
                if 'issuer' in cert:
                    for item in cert['issuer']:
                        if isinstance(item, tuple) and len(item) > 0:
                            issuer_dict[item[0]] = item[1] if len(item) > 1 else ''
                
                if 'subject' in cert:
                    for item in cert['subject']:
                        if isinstance(item, tuple) and len(item) > 0:
                            subject_dict[item[0]] = item[1] if len(item) > 1 else ''
                
                if issuer_dict and subject_dict and issuer_dict == subject_dict:
                    return False, "Self-signed certificate detected"
                
                return True, None
    except ssl.SSLError as e:
        return False, f"SSL Error: {str(e)}"
    except socket.timeout:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

def check_tls(domain):
    is_valid, error = check_certificate_validity(domain)
    if not is_valid:
        return True
    
    current_fp = get_fingerprint(domain)
    if not current_fp:
        return True
    
    if domain in KNOWN_FINGERPRINTS:
        known_fp = KNOWN_FINGERPRINTS[domain]
        if current_fp != known_fp:
            return True
    
    old_fp = known_fingerprints.get(domain)
    if old_fp and old_fp != current_fp:
        return True
    
    known_fingerprints[domain] = current_fp
    
    return False

