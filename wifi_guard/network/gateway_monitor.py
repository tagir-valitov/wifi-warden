import psutil
import time

gateway_changes = 0
last_gateway = None

def monitor_gateway():
    global last_gateway, gateway_changes

    while True:
        gws = psutil.net_if_stats()
        current = list(gws.keys())

        if last_gateway and current != last_gateway:
            gateway_changes += 1

        last_gateway = current
        time.sleep(1)  # У нас 15 секунд программа работает. За это время надо
        #  набрать 4 смены шлюза или больше. Тут было sleep(10), больше 1
        #  смены не было бы никогда

def is_gateway_unstable():
    return gateway_changes > 3
