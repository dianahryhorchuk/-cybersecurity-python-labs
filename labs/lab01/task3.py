import csv
from datetime import datetime
import hashlib
import json
import os
import sys

#Підключення модуля student зі спільної папки shared
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


#Власний виняток для коротких паролів
class ValidationError(Exception):
    pass


#Декоратор для логування спроб входу у файл log.json
def log_event(func):
    def wrapper(*args, **kwargs):
        # Викликаємо основну функцію (login) та отримуємо True або False
        result = func(*args, **kwargs)

        # Визначаємо ім'я користувача з аргументів
        username = (
            args[0] if len(args) > 0 else kwargs.get("username", "unknown")
        )

        #Формуємо структуру логу за вимогами з методички
        log_data = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": list(args),
            "kwargs": kwargs,
        }

        #Шлях до файлу log.json
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(data_dir, exist_ok=True)
        log_file = os.path.join(data_dir, "log.json")

        #Зчитуємо існуючі логи або створюємо новий список
        logs = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except (json.JSONDecodeError, IOError):
                logs = []

        logs.append(log_data)

        #Записуємо оновлений список у JSON
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)

        return result

    return wrapper


#Функція генерації хешу (sha224 для 9 варіанту, мін. довжина = 13)
def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    #Варіант 9 вимагає мінімум 13 символів
    if len(password) < 13:
        raise ValidationError(
            "Пароль занадто короткий! Мінімальна довжина: 13 символів"
        )

    #Хешування sha224 від конкатенації пароля та солі
    text = password + salt
    return hashlib.sha224(text.encode("utf-8")).hexdigest()


#Створення одного користувача з персональною сіллю
def create_user(username: str, password: str):
    # Крок 2: Персональна сіль для 9 варіанту -> "00009"
    personal_salt = "{:05d}".format(VARIANT_NUMBER)
    hashed_password = generate_hash(password, personal_salt)
    return (username, hashed_password)


#Запис користувачів у CSV-файл
def create_users(users_list):
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)
    csv_path = os.path.join(data_dir, "users.csv")

    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for username, password in users_list:
            try:
                user_tuple = create_user(username, password)
                writer.writerow(user_tuple)
            except (ValueError, ValidationError) as e:
                print("Помилка реєстрації {}: {}".format(username, e))

    return csv_path


#Функція входу з декоратором логування
@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")

    personal_salt = "{:05d}".format(VARIANT_NUMBER)
    try:
        hashed_input = generate_hash(password, personal_salt)
    except (ValidationError, ValueError):
        return False

    data_dir = os.path.join(os.path.dirname(__file__), "data")
    csv_path = os.path.join(data_dir, "users.csv")

    if not os.path.exists(csv_path):
        raise FileNotFoundError("Базу даних користувачів users.csv не знайдено")

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) == 2:
                db_user, db_hash = row
                if db_user == username and db_hash == hashed_input:
                    return True

    return False


#Головна функція запуску
def main():
    print(
        "=== Завдання 3 (Студент: {}, Група: {}, Варіант: {}) ===".format(
            STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
        )
    )

    #Кортеж з 10 користувачами (декілька паролів спеціально < 13 символів)
    users_to_register = (
        ("admin_user", "SuperSecurePass123!"),
        ("analyst_01", "StrongPassword999#"),
        ("sec_officer", "CyberSecurity2026$"),
        ("test_short", "Short123!"),  # Викличе ValidationError (довжина 9 < 13)
        ("cloud_dev", "MySecretKey2026!"),
        ("audit_spec", "DataProtection_9"),
        ("partner_user", "AnotherPassword8"),
        ("bad_pass", "123"),  # Викличе ValidationError (довжина 3 < 13)
        ("guest_account", "SafeAndSecure#9"),
        ("final_tester", "FinalTestPassword!9"),
    )

    #Обробка винятків навколо файлових операцій та входу
    try:
        print("\n--- Реєстрація користувачів ---")
        csv_path = create_users(users_to_register)

        # Крок 4: Читання CSV та вивід у вигляді таблиці
        print("\n--- Вміст бази даних (users.csv) ---")
        print("{:<15} | {:<56}".format("Логін", "Хеш (sha224)"))
        print("-" * 75)

        users_db = []
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                users_db.append(row)
                print("{:<15} | {:<56}".format(row[0], row[1]))

        # Крок 5 та 6: Автентифікація та автоматичне логування
        print("\n--- Перевірка автентифікації ---")

        # Успішна спроба
        res1 = login("admin_user", "SuperSecurePass123!")
        print("Вхід admin_user (вірна інформація):", res1)

        # Неуспішна спроба (невірно пароль)
        res2 = login("admin_user", "WrongPassword123!")
        print("Вхід admin_user (невірний пароль):", res2)

        # Неуспішна спроба (користувача немає)
        res3 = login("unknown_user", "SuperSecurePass123!")
        print("Вхід unknown_user (неіснуючий):", res3)

        print("\nЛоги входу збережено у файл labs/lab01/data/log.json")

    except FileNotFoundError as e:
        print("Помилка: Файл не знайдено -", e)
    except PermissionError as e:
        print("Помилка: Немає прав доступу до файлу -", e)
    except IOError as e:
        print("Помилка введення/виведення файлу -", e)
    except ValidationError as e:
        print("Помилка валідації даних -", e)
    except ValueError as e:
        print("Помилка значення -", e)


if __name__ == "__main__":
    main()