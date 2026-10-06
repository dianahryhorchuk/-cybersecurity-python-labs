import argparse
import logging
from datetime import timedelta
from pathlib import Path

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import audit_headers


def run_demo():
    print("Завдання 1")
    audit = AuditLog()
    user = User("sec_user", "security@university.edu", role="operator")
    user.set_password("StrongMasterPass2026!")

    account = UserAccount(user, audit)

    print("\n1. Вхід із некоректним паролем:")
    account.login("sec_user", "WrongPass123", "192.168.1.50")
    print("Автентифіковано:", account.is_authenticated())

    print("\n2. Вхід із правильним паролем:")
    account.login("sec_user", "StrongMasterPass2026!", "192.168.1.50")
    print("Автентифіковано:", account.is_authenticated())

    print("\n3. Перевірка валідації пошти (невірний формат):")
    try:
        user.email = "bad_email_format"
    except ValueError as err:
        print("Виняток перехоплено успішно:", err)

    print("\n4. Перевірка класу Admin та прав доступу:")
    admin = Admin("root_admin", "admin@company.corp")
    admin.grant_permission("READ_CONFIDENTIAL_DATA")
    admin.grant_permission("EXECUTE_DIAGNOSTICS")
    print(admin)
    print("Чи має доступ до 'EXECUTE_DIAGNOSTICS':", admin.has_permission("EXECUTE_DIAGNOSTICS"))

    print("\n5. Демонстрація завершення сеансу за таймаутом:")
    # Віднімаємо 901 секунду, щоб перевищити SESSION_TIMEOUT_SEC = 900
    account["session"].last_activity -= timedelta(seconds=901)
    print("Автентифіковано після 901 секунди бездіяльності:", account.is_authenticated())

    print("\n6. Вихід із системи (logout):")
    account.logout()
    print("Автентифіковано після logout:", account.is_authenticated())

    print("\n Вміст AuditLog")
    for record in audit.show_all():
        time_str = record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{time_str}] User: {record.username} | Action: {record.action}")


def main():
    parser = argparse.ArgumentParser(description="ЛР №2: Розробка консольних утиліт для задач кібербезпеки")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Підкоманда demo
    subparsers.add_parser("demo", help="Запустити демонстрацію об'єктної моделі (Завдання 1)")

    # Підкоманда analyze
    analyze_parser = subparsers.add_parser("analyze", help="Запустити аудит HTTP-заголовків (Варіант 9)")
    analyze_parser.add_argument(
        "--headers-file",
        type=Path,
        default=Path("labs/lab02/data/data_v09/headers.json"),
        help="Шлях до вхідного JSON-файлу заголовків",
    )
    analyze_parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("labs/lab02/data/headers_audit.csv"),
        help="Шлях для збереження підсумкового звіту CSV",
    )
    analyze_parser.add_argument(
        "--strict",
        action="store_true",
        help="Увімкнути режим суворої оцінки безпеки",
    )
    analyze_parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Рівень деталізації журналу",
    )

    args = parser.parse_args()

    # Розділяємо логіку виконання, щоб уникнути помилок з атрибутами
    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        # Налаштовуємо логування ТІЛЬКИ для команди analyze
        logging.basicConfig(
            level=args.log_level,
            format="[%(levelname)s] %(message)s",
        )
        audit_headers(args.headers_file, args.output_csv, strict=args.strict)


if __name__ == "__main__":
    main()