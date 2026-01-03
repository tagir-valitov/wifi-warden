# Честное слово, я не понимаю, в чём проблема, если на роутере открыты порты изнутри сети.
# Наверное, по задумке мы хотим здесь проверить, можно ли из открытого Интернета
# или из внешней сети подключиться к нашему роутеру, но подключаемся-то мы из локальной сети.
# А если бы мы не были в локальной сети, то тогда шлюз был бы другой у нас, а
# у самого роутера был бы другой адрес.

# У меня программа видит, что открыты порты 80 и 22, и выдаёт 85% опасности :(


import socket
import subprocess
import sys

PORTS = {80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "Telnet"}

def get_gateway():
    if sys.platform.startswith("win"):
        out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
        for line in out.splitlines():
            if "Default Gateway" in line and ":" in line:
                gw = line.split(":")[-1].strip()
                if gw:
                    return gw
    # У меня вот так сработало
    # ip route выводит подобное:
#default via 192.168.1.1 dev enp0s31f6 proto dhcp src 192.168.1.173 metric 100 
#172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
#192.168.1.0/24 dev enp0s31f6 proto kernel scope link src 192.168.1.173 metric 100 
    # видимо, слово после via - это IP-адрес шлюза
    elif sys.platform.startswith("linux"):
        out = subprocess.check_output("ip route list default", shell=True).decode(errors="ignore")
        for line in out.splitlines():
            if "default" in line:
                line = line.split()
                via = -1
                for i, word in enumerate(line):
                    if word == 'via':
                        via = i
                        break
                if via != -1:
                    return line[via + 1]
    return None

def check_open_gateway():
    gw = get_gateway()
    if not gw:
        return False, []

    reasons = []
    for p in PORTS:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((gw, p)) == 0:
            reasons.append(f"Gateway open port {p} ({PORTS[p]})")
        s.close()

    return bool(reasons), reasons
