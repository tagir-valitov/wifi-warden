import argparse
import ctypes
import threading
import time
import asyncio
import concurrent.futures
import sys

from utils.logger import log
from risk_engine import calculate_risk

from network.arp_monitor import start_arp_monitor, is_arp_attack
from network.dns_check import check_dns_spoof
from network.tls_check import check_tls
from network.dos_monitor import start_dos_monitor, is_dos_detected
from network.portscan_monitor import start_portscan_monitor, is_portscan_detected
from network.gateway_monitor import monitor_gateway, is_gateway_unstable
from network.open_gateway_check import check_open_gateway
from network.wifi_scanner import scan_wifi_networks, get_current_wifi


def show_networks():
    try:
        networks = scan_wifi_networks()

        current = get_current_wifi()
        current_ssid = current.get("ssid") if current else None

        log("\nСети рядом с вами:")
        log("-" * 60)

        if networks:
            for i, n in enumerate(networks, 1):
                ssid = n.get("ssid", "<скрытая сеть>")
                auth = n.get("auth", "Неизвестно")
                signal = n.get("signal", "Неизвестно")

                current_mark = " (ВЫ ПОДКЛЮЧЕНЫ)" if ssid == current_ssid else ""
                log(f"{i}. {ssid}{current_mark}")
                log(f"   Защита: {auth} | Сигнал: {signal}")
        else:
            log("Не найдено доступных Wi-Fi сетей")

        if current_ssid:
            log(f"\nВы подключены к: {current_ssid}")
        else:
            log("\nВы не подключены к Wi-Fi")

        log("-" * 60)
        return current_ssid

    except Exception as e:
        log(f"Ошибка при сканировании сетей: {e}")
        current = get_current_wifi()
        return current.get("ssid") if current else None


def select_check_mode():
    log("\nВыберите режим проверки:")
    log("1. Быстрая проверка (15 секунд)")
    log("2. Непрерывная проверка")
    log("3. Обычная проверка (30 секунд)")

    while True:
        try:
            choice = input("\nВыберите режим (1-3) или нажмите ENTER для обычной: ").strip()
            if not choice:
                return "normal"

            if choice == "1":
                log("Выбрана быстрая проверка (15 секунд)")
                return "fast"
            elif choice == "2":
                log("Выбрана непрерывная проверка")
                return "continuous"
            elif choice == "3":
                log("Выбрана обычная проверка (30 секунд)")
                return "normal"
            else:
                log("Пожалуйста, введите число от 1 до 3")
        except KeyboardInterrupt:
            return "normal"
        except EOFError:
            return "normal"


def get_security_recommendations(problems):
    recommendations = []

    if any("ARP спуфинг" in p for p in problems):
        recommendations.append("• Установите статический ARP или используйте защищенные сети")
        recommendations.append("• Включите защиту от ARP-атак в настройках роутера")
        recommendations.append("• Используйте VPN для шифрования трафика")

    if any("DNS подмена" in p for p in problems):
        recommendations.append("• Используйте DNS-over-HTTPS или DNS-over-TLS")
        recommendations.append("• Настройте DNS сервера вручную (например, 8.8.8.8, 1.1.1.1)")
        recommendations.append("• Проверьте настройки DHCP на роутере")

    if any("TLS/SSL" in p for p in problems):
        recommendations.append("• Не вводите пароли и личные данные на этом сайте")
        recommendations.append("• Проверьте дату и время на устройстве")
        recommendations.append("• Обновите браузер и операционную систему")

    if any("DDoS" in p for p in problems):
        recommendations.append("• Отключитесь от сети на 5-10 минут")
        recommendations.append("• Используйте проводное подключение если возможно")
        recommendations.append("• Сообщите администратору сети")

    if any("Сканирование портов" in p for p in problems):
        recommendations.append("• Включите файерволл на устройстве")
        recommendations.append("• Отключите ненужные сетевые службы")
        recommendations.append("• Используйте VPN для скрытия реального IP")

    if any("Шлюз нестабилен" in p for p in problems):
        recommendations.append("• Перезагрузите роутер")
        recommendations.append("• Проверьте кабель подключения роутера")
        recommendations.append("• Обновите прошивку роутера")

    if any("Открытый шлюз" in p for p in problems):
        recommendations.append("• Смените пароль администратора роутера")
        recommendations.append("• Отключите удаленный доступ к роутеру")
        recommendations.append("• Обновите прошивку роутера")

    if not recommendations:
        recommendations.append("• Регулярно меняйте пароль Wi-Fi сети")
        recommendations.append("• Используйте WPA3 или WPA2-AES шифрование")
        recommendations.append("• Отключайте Wi-Fi когда не используете")
        recommendations.append("• Не подключайтесь к публичным Wi-Fi без VPN")

    return recommendations


async def run_security_checks_async():
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            loop = asyncio.get_running_loop()

            futures = {
                'open_gateway': loop.run_in_executor(executor, check_open_gateway),
                'arp': loop.run_in_executor(executor, is_arp_attack),
                'dns': loop.run_in_executor(executor, lambda: check_dns_spoof("google.com")),
                'tls': loop.run_in_executor(executor, lambda: check_tls("google.com")),
                'dos': loop.run_in_executor(executor, is_dos_detected),
                'portscan': loop.run_in_executor(executor, is_portscan_detected),
                'gateway': loop.run_in_executor(executor, is_gateway_unstable),
            }

            results = {}
            for key, future in futures.items():
                try:
                    results[key] = await future
                except Exception:
                    results[key] = (False, ["Ошибка проверки"]) if key == 'open_gateway' else False

            og, og_reasons = results['open_gateway']

            events = {
                "arp": results['arp'],
                "dns": results['dns'],
                "tls": results['tls'],
                "dos": results['dos'],
                "portscan": results['portscan'],
                "gateway": results['gateway'],
                "open_gateway": og_reasons if og else False,
            }

            score, reasons = calculate_risk(events)
            return score, reasons
    except Exception:
        return 0, ["Ошибка выполнения проверок"]


def run_security_checks():
    try:
        return asyncio.run(run_security_checks_async())
    except RuntimeError:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(lambda: asyncio.run(run_security_checks_async()))
                    return future.result()
            else:
                return loop.run_until_complete(run_security_checks_async())
        except Exception:
            return run_security_checks_sync_fallback()
    except Exception:
        return run_security_checks_sync_fallback()


def run_security_checks_sync_fallback():
    try:
        og, og_reasons = check_open_gateway()

        events = {
            "arp": is_arp_attack(),
            "dns": check_dns_spoof("google.com"),
            "tls": check_tls("google.com"),
            "dos": is_dos_detected(),
            "portscan": is_portscan_detected(),
            "gateway": is_gateway_unstable(),
            "open_gateway": og_reasons if og else False,
        }

        score, reasons = calculate_risk(events)
        return score, reasons
    except Exception:
        return 0, ["Ошибка при выполнении проверок безопасности"]


def warn_user(score, reasons):
    if not reasons:
        return

    real_reasons = [r for r in reasons if r != "No threats detected"]
    if not real_reasons or score == 0:
        return

    log("\n!!! ВНИМАНИЕ: ОБНАРУЖЕНЫ ПРОБЛЕМЫ БЕЗОПАСНОСТИ !!!")
    log(f"Уровень угрозы: {score}/100")
    for r in real_reasons:
        log(f"  - {r}")

    try:
        MB_ICONWARNING = 0x30
        MB_TOPMOST = 0x00040000
        text = "Обнаружены проблемы с сетью:\n\n" + "\n".join(f"- {r}" for r in real_reasons)
        ctypes.windll.user32.MessageBoxW(
            None,
            text,
            "WiFi Guard – предупреждение",
            MB_ICONWARNING | MB_TOPMOST,
        )
    except Exception:
        pass


def start_all_monitors():
    arp_monitor_thread = threading.Thread(target=start_arp_monitor, daemon=True)
    dos_monitor_thread = threading.Thread(target=start_dos_monitor, daemon=True)
    portscan_monitor_thread = threading.Thread(target=start_portscan_monitor, daemon=True)
    gateway_monitor_thread = threading.Thread(target=monitor_gateway, daemon=True)

    arp_monitor_thread.start()
    dos_monitor_thread.start()
    portscan_monitor_thread.start()
    gateway_monitor_thread.start()

    log("Мониторы безопасности запущены")
    return [arp_monitor_thread, dos_monitor_thread, portscan_monitor_thread, gateway_monitor_thread]


def run_fast_check(current_network=None):
    log("=" * 60)
    log("ЗАПУСК БЫСТРОЙ ПРОВЕРКИ (15 СЕКУНД)")
    log("=" * 60)

    if current_network:
        log(f"Проверяемая сеть: {current_network}")
    else:
        current = get_current_wifi()
        if current and current.get("ssid"):
            current_network = current.get('ssid')
            log(f"Проверяемая сеть: {current_network}")
        else:
            log("Проверка текущего сетевого подключения")

    log("\nЗапуск мониторов безопасности...")
    monitors = start_all_monitors()

    log("\nСбор данных...")
    for i in range(15, 0, -1):
        log(f"Осталось {i} секунд...")
        time.sleep(1)

    log("\nАнализ данных...")
    score, reasons = run_security_checks()

    log("\n" + "=" * 60)
    log("РЕЗУЛЬТАТЫ ПРОВЕРКИ")
    log("=" * 60)

    if current_network:
        log(f"Сеть: {current_network}")

    real_reasons = [r for r in reasons if r != "No threats detected"]

    if real_reasons and score > 0:
        log(f"\nУРОВЕНЬ УГРОЗЫ: {score}/100")
        log("\nОбнаруженные проблемы:")
        for r in real_reasons:
            log(f"  ⚠ {r}")

        log("\nРекомендации по безопасности:")
        recommendations = get_security_recommendations(real_reasons)
        for rec in recommendations:
            log(f"  {rec}")

        warn_user(score, real_reasons)
    else:
        log(f"\nУРОВЕНЬ УГРОЗЫ: {score}/100")
        log("✅ Сеть безопасна")

        log("\nОбщие рекомендации:")
        recommendations = get_security_recommendations([])
        for rec in recommendations:
            log(f"  {rec}")

    log("\n" + "=" * 60)
    log("Проверка завершена!")


def run_continuous_check(current_network=None):
    log("\n" + "=" * 60)
    log("НЕПРЕРЫВНЫЙ МОНИТОРИНГ БЕЗОПАСНОСТИ")
    log("=" * 60)

    if current_network:
        log(f"Мониторинг сети: {current_network}")
    else:
        current = get_current_wifi()
        if current and current.get("ssid"):
            current_network = current.get('ssid')
            log(f"Мониторинг сети: {current_network}")
        else:
            log("Мониторинг текущего подключения")

    log("\nЗапуск мониторов безопасности...")
    monitors = start_all_monitors()

    log("\nМониторинг запущен. Нажмите Ctrl+C для остановки.")
    log("=" * 60)

    check_count = 0
    last_alert_time = 0
    ALERT_COOLDOWN = 30

    try:
        while True:
            check_count += 1
            log(f"\n[Проверка #{check_count}] " + "-" * 40)

            score, reasons = run_security_checks()

            real_reasons = [r for r in reasons if r != "No threats detected"]

            current_time = time.time()

            if real_reasons and score > 0:
                if current_time - last_alert_time > ALERT_COOLDOWN:
                    log(f"УРОВЕНЬ УГРОЗЫ: {score}/100")
                    log("Проблемы:")
                    for r in real_reasons:
                        log(f"  - {r}")

                    log("Рекомендации:")
                    recommendations = get_security_recommendations(real_reasons)
                    for rec in recommendations[:3]:
                        log(f"  {rec}")

                    warn_user(score, real_reasons)
                    last_alert_time = current_time
                else:
                    log(f"УРОВЕНЬ УГРОЗЫ: {score}/100 (предупреждение было недавно)")
            else:
                log(f"УРОВЕНЬ УГРОЗЫ: {score}/100 - безопасно")

            time.sleep(2)

    except KeyboardInterrupt:
        log("\n" + "=" * 60)
        log("Мониторинг остановлен.")
        log(f"Всего проверок: {check_count}")
        log("=" * 60)
    except Exception as e:
        log(f"\nОшибка: {e}")
        log("Перезапуск...")
        time.sleep(5)
        run_continuous_check(current_network)


def run_normal_check(current_network=None):
    log("\n" + "=" * 60)
    log("ОБЫЧНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ (30 СЕКУНД)")
    log("=" * 60)

    if current_network:
        log(f"Проверка сети: {current_network}")
    else:
        current = get_current_wifi()
        if current and current.get("ssid"):
            current_network = current.get('ssid')
            log(f"Проверка сети: {current_network}")
        else:
            log("Проверка текущего подключения")

    log("\nЗапуск мониторов безопасности...")
    monitors = start_all_monitors()

    log("\nСбор данных...")
    for i in range(30, 0, -1):
        if i % 5 == 0:
            log(f"Осталось {i} секунд...")
        time.sleep(1)

    log("\nАнализ данных...")
    score, reasons = run_security_checks()

    log("\n" + "=" * 60)
    log("РЕЗУЛЬТАТЫ ПРОВЕРКИ")
    log("=" * 60)

    if current_network:
        log(f"Сеть: {current_network}")

    real_reasons = [r for r in reasons if r != "No threats detected"]

    if real_reasons and score > 0:
        log(f"\nУРОВЕНЬ УГРОЗЫ: {score}/100")
        log("\nОбнаруженные проблемы:")
        for r in real_reasons:
            log(f"  ⚠ {r}")

        log("\nРекомендации по безопасности:")
        recommendations = get_security_recommendations(real_reasons)
        for rec in recommendations:
            log(f"  {rec}")

        warn_user(score, real_reasons)
    else:
        log(f"\nУРОВЕНЬ УГРОЗЫ: {score}/100")
        log("✅ Сеть безопасна")

        log("\nОбщие рекомендации:")
        recommendations = get_security_recommendations([])
        for rec in recommendations:
            log(f"  {rec}")

    log("\n" + "=" * 60)
    log("Проверка завершена!")


def main():
    log("=" * 60)
    log("WIFI GUARD - ПРОВЕРКА БЕЗОПАСНОСТИ СЕТИ")
    log("=" * 60)

    current_network = show_networks()

    check_mode = select_check_mode()

    if check_mode == "fast":
        run_fast_check(current_network)
    elif check_mode == "continuous":
        run_continuous_check(current_network)
    elif check_mode == "normal":
        run_normal_check(current_network)


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(description="WiFi Guard – проверка безопасности Wi-Fi")
    parser.add_argument(
        "--background",
        action="store_true",
        help="непрерывный мониторинг",
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["fast", "continuous", "normal"],
        default=None,
        help="режим: fast (15 сек), continuous, normal (30 сек)",
    )
    args = parser.parse_args()

    try:
        if args.background or args.mode == "continuous":
            current = get_current_wifi()
            current_network = current.get("ssid") if current else None
            run_continuous_check(current_network)
        elif args.mode:
            current = get_current_wifi()
            current_network = current.get("ssid") if current else None

            if args.mode == "fast":
                run_fast_check(current_network)
            elif args.mode == "normal":
                run_normal_check(current_network)
        else:
            main()
    except KeyboardInterrupt:
        log("\nПрограмма остановлена.")
    except Exception as e:
        log(f"\nОшибка: {e}")
