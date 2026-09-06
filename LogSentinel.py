import json
import re
from datetime import datetime
from collections import defaultdict, Counter
from itertools import filterfalse


# =====================================================================
# РОДИТЕЛЬСКИЙ КЛАСС (Базовый парсер)
# =====================================================================
class BaseLogParser:
    """
    Базовый класс для всех парсеров.
    Отвечает за открытие файла и построчную ленивую десериализацию JSON.
    """
    def __init__(self, filepath):
        self.filepath = filepath

    def read_logs(self):
        """Ленивый генератор: читает файл построчно."""
        with open(self.filepath, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line:
                    yield json.loads(line)


# =====================================================================
# КЛАСС 1: Ночные сбои (00:00 - 04:00)
# =====================================================================
class NightCrashParser(BaseLogParser):
    """Анализирует сбои в обозначенные ночные часы (с 00:00 - 04:00)."""
    
    def get_night_report(self, max_hour=4):
        rows = self.read_logs()
        # Фильтруем ERROR
        sts_err = filterfalse(lambda row: row.get('level') != 'ERROR', rows)
        
        # Фильтруем по ночным часам до 4 утра
        night_errors = [row for row in sts_err if datetime.strptime(row['timestamp'],'%Y-%m-%dT%H:%M:%S').hour <= max_hour]
        
        if not night_errors:
            return None
            
        reporting_date = datetime.strptime(night_errors[0]['timestamp'], '%Y-%m-%dT%H:%M:%S').strftime('%d.%m.%Y')
        error_counts = Counter(row['msg'] for row in night_errors)
        
        return {'date': reporting_date, 'counts': error_counts}


# =====================================================================
# КЛАСС 2: Детектор Пикового Часа Сбоев (за весь день)
# =====================================================================
class PeakHourParser(BaseLogParser):
    """Анализирует логи за весь день и определяет час с наибольшим числом ошибок."""

    def get_peak_hour_report(self):
        error_hour = defaultdict(list)
        all_errors_counter = Counter()
        pattern = re.compile(r'\d{4}-\d{2}-\d{2}T(\d{2}):\d{2}')

        for line in self.read_logs():
            if line.get('level') != "ERROR":
                continue

            match = pattern.search(line.get('timestamp', ''))
            if match:
                hour_key = f"{match.group(1)}:00"
                msg = line.get('msg', 'Unknown Error')
                error_hour[hour_key].append(msg)
                all_errors_counter[msg] += 1

        if not error_hour:
            return None

        peak_hour = max(error_hour, key=lambda h: len(error_hour[h]))

        return {'peak_hour': peak_hour, 'peak_count': len(error_hour[peak_hour]), 'peak_errors': error_hour[peak_hour], 'total_stats': all_errors_counter}


# =====================================================================
# КЛАСС 3: Анализатор Безопасности (Поиск IP взломщиков)
# =====================================================================
class SecurityLogParser(BaseLogParser):
    """Ищет попытки взлома админ-панели и собирает уникальные IP-адреса."""
    
    def get_suspicious_ips(self):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        suspicious_ips = set()

        for log in self.read_logs():
            status = log.get('status', log.get('level', ''))
            message = log.get('message', log.get('msg', ''))

            if status == "ERROR" and "admin" in message:
                match = re.search(ip_pattern, message)
                if match:
                    suspicious_ips.add(match.group())

        return suspicious_ips


# =====================================================================
# КЛАСС 4: Извлечение Email-адресов пользователей
# =====================================================================
class EmailLogParser(BaseLogParser):
    """Извлекает email-адреса пользователей и группирует их по статусу (SUCCESS / ERROR)."""

    def get_user_emails(self):
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails_by_status = defaultdict(list)

        for log in self.read_logs():
            message = log.get('msg', log.get('message', ''))
            # Достаем статус
            status = log.get('status', log.get('level', 'UNKNOWN')).upper()

            match = re.search(email_pattern, message)
            if match:
                email = match.group()
                emails_by_status[status].append(email)

        return emails_by_status


# =====================================================================
# ДЕМОНСТРАЦИЯ РАБОТЫ ВСЕХ 4 ПАРСЕРОВ
# =====================================================================
if __name__ == "__main__":
    test_log_file = "server_timelog.json"
    
    print("==================================================")
    print("      ЗАПУСК ООП ФРЕЙМВОРКА АНАЛИЗА ЛОГОВ        ")
    print("==================================================\n")

    # 1. Демонстрация NightCrashParser
    print("--- 1. РЕЗУЛЬТАТ: NightCrashParser ---")
    night_parser = NightCrashParser(test_log_file)
    try:
        night_res = night_parser.get_night_report(max_hour=4)
        if night_res:
            print(f"Отчет за {night_res['date']} (00:00 - 04:00):")
            for err, count in night_res['counts'].items():
                print(f"Ошибка '{err}' повторилась {count} раз(а)")
        else:
            print("Ночных ошибок не обнаружено.")
    except Exception as e:
        print(f"Информация об ошибке: ({e})")

    # 2. Демонстрация PeakHourParser
    print("\n--- 2. РЕЗУЛЬТАТ: PeakHourParser ---")
    peak_parser = PeakHourParser(test_log_file)
    try:
        peak_res = peak_parser.get_peak_hour_report()
        if peak_res:
            print(f"Час Пик: {peak_res['peak_hour']} (Сбоев: {peak_res['peak_count']})")
            print("Ошибки в Час Пик:", *peak_res['peak_errors'], sep="\n  - ")
        else:
            print("Сбоев за день не найдено.")
    except Exception as e:
        print(f"Информация: {e}")

    # 3. Демонстрация SecurityLogParser
    print("\n--- 3. РЕЗУЛЬТАТ: SecurityLogParser ---")
    security_parser = SecurityLogParser('Security_log.json')
    try:
        ips = security_parser.get_suspicious_ips()
        if ips:
            print("Обнаружены подозрительные IP-адреса хакеров:")
            for ip in ips:
                print(f"  - {ip}")
        else:
            print("Подозрительных IP не найдено.")
    except Exception as e:
        print(f"Информация: {e}")

    # --- 4. Демонстрация EmailLogParser с defaultdict ---
    print("\n--- 4. РЕЗУЛЬТАТ: EmailLogParser ---")
    email_parser = EmailLogParser('email.json')
    try:
        emails_by_status = email_parser.get_user_emails()
        if emails_by_status:
            for status, email_list in emails_by_status.items():
                print(f"Статус [{status}] ({len(email_list)} шт.):")
                for email in email_list:
                    print(f"  - {email}")
        else:
            print("Email-адресов не найдено.")
    except Exception as e:
        print(f"Информация о сбое: {e}")

    print("\n==================================================")