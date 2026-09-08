import os
import random
import string
import sys

#Налаштування шляхів імпорту
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def run_task1():
    print(
        "=== Завдання 1 (Студент: {}, Група: {}, Варіант: {}) ===".format(
            STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
        )
    )

    #Вхідні дані 9 варіанту з методички
    passwords = [
        "Digital@F0r3nsics",
        "plain",
        "Encrypt10n@Key",
        "member",
        "Security@Audit2023",
        "regular",
        "Hack3r@D3fense",
        "ordinary",
        "Threat@Intel",
        "usual",
    ]

    criteria = {
        "min_length": 8,
        "require_digits": True,
        "require_upper": True,
        "require_special": True,
    }

    forbidden_passwords = {
        "plain",
        "member",
        "regular",
        "ordinary",
        "usual",
        "user",
    }

    #Додаємо 3 випадкові дублікати в кінець списку
    random_indices = random.sample(range(len(passwords)), 3)
    for idx in random_indices:
        passwords.append(passwords[idx])

    min_len = criteria["min_length"]

    # Шапка таблиці
    print("\nПароль                     | Статус надійності")
    print("-" * 50)

    #Перевіряємо кожен пароль по черзі
    for pwd in passwords:
        is_unique = passwords.count(pwd) == 1

        has_digit = False
        has_upper = False
        has_lower = False
        has_special = False

        for char in pwd:
            if char.isdigit():
                has_digit = True
            elif char.isupper():
                has_upper = True
            elif char.islower():
                has_lower = True
            elif char in string.punctuation:
                has_special = True

        meets_all = (
            len(pwd) >= min_len
            and has_digit
            and has_upper
            and has_special
            and has_lower
        )

        if pwd in forbidden_passwords or len(pwd) < min_len:
            status = "Заборонений"
        elif meets_all and len(pwd) >= (min_len + 4) and is_unique:
            status = "Дуже сильний"
        elif meets_all:
            status = "Сильний"
        elif len(pwd) >= min_len:
            status = "Середній"
        else:
            status = "Слабкий"

        print("{:<26} | {}".format(pwd, status))


#Точка входу для прямого запуску файлу task1.py
if __name__ == "__main__":
    run_task1()