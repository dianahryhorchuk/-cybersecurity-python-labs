import csv
from datetime import datetime
import hashlib
import json
import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

class ValidationError(Exception):
    pass

def log_event(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        username = (
            args[0] if len(args) > 0 else kwargs.get("username", "unknown")
        )

        log_data = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "args": list(args),
            "kwargs": kwargs,
        }

        data_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(data_dir, exist_ok=True)
        log_file = os.path.join(data_dir, "log.json")

        logs = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except (json.JSONDecodeError, IOError):
                logs = []

        logs.append(log_data)
      
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=4)

        return result

    return wrapper

def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми")
    
    if len(password) < 13:
        raise ValidationError(
            "Пароль занадто короткий! Мінімальна довжина: 13 символів"
        )

    text = password + salt
    return hashlib.sha224(text.encode("utf-8")).hexdigest()

def create_user(username: str, password: str):
    personal_salt = "{:05d}".format(VARIANT_NUMBER)
    hashed_password = generate_hash(password, personal_salt)
    return (username, hashed_password)

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


def main():
    print(
        "  Завдання 3 (Студент: {}, Група: {}, Варіант: {})  ".format(
            STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
        )
    )

    users_to_register = (
        ("admin_user", "SuperSecurePass123!"),
        ("analyst_01", "StrongPassword999#"),
        ("sec_officer", "CyberSecurity2026$"),
        ("test_short", "Short123!"),  
        ("cloud_dev", "MySecretKey2026!"),
        ("audit_spec", "DataProtection_9"),
        ("partner_user", "AnotherPassword8"),
        ("bad_pass", "123"), 
        ("guest_account", "SafeAndSecure#9"),
        ("final_tester", "FinalTestPassword!9"),
    )

    try:
        print("\n Реєстрація користувачів ")
        csv_path = create_users(users_to_register)

        print("\n Вміст бази даних (users.csv)")
        print("{:<15} | {:<56}".format("Логін", "Хеш (sha224)"))
        print("-" * 75)

        users_db = []
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                users_db.append(row)
                print("{:<15} | {:<56}".format(row[0], row[1]))

        print("\n  Перевірка автентифікації  ")

        res1 = login("admin_user", "SuperSecurePass123!")
        print("Вхід admin_user (вірна інформація):", res1)

        res2 = login("admin_user", "WrongPassword123!")
        print("Вхід admin_user (невірний пароль):", res2)

        res3 = login("unknown_user", "SuperSecurePass123!")
        print("Вхід unknown_user (неіснуючий):", res3)

        print("\n Логи входу збережено у файл labs/lab01/data/log.json")

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
