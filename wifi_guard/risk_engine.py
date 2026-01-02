def calculate_risk(events):
    score = 0
    reasons = []

    weights = {
        "arp": 40,
        "dns": 30,
        "tls": 30,
        "dos": 25,
        "portscan": 20,
        "gateway": 15,
        "open_gateway": 25
    }

    for k, v in events.items():
        if v:
            score += weights.get(k, 0)
            if isinstance(v, list):
                reasons.extend(v)
            else:
                reasons.append(f"{k.upper()} detected")

    if score == 0:
        reasons.append("No threats detected")

    return min(score, 100), reasons