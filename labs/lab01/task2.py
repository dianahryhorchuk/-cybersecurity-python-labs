import os
import sys

#Налаштування шляху для імпорту з папки shared
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def run_task2():
    print(
        "2 (Студент: {}, Група: {}, Варіант: {}) ===".format(
            STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
        )
    )

    #Вхідні дані
    users = {
        "cloud_architect": {
            "role": "cloud_security",
            "clearance": 4,
            "department": "Cloud",
            "active": True,
        },
        "devops_engineer": {
            "role": "devops",
            "clearance": 3,
            "department": "DevOps",
            "active": True,
        },
        "qa_tester": {
            "role": "quality_assurance",
            "clearance": 2,
            "department": "QA",
            "active": True,
        },
        "partner_access": {
            "role": "partner",
            "clearance": 2,
            "department": "Partnership",
            "active": True,
        },
        "migrated_user": {
            "role": "migrated",
            "clearance": 1,
            "department": "Migration",
            "active": False,
        },
    }

    resources = [
        ("cloud_configs", 4),
        ("deployment_pipelines", 3),
        ("test_environments", 2),
        ("partner_apis", 2),
        ("infrastructure_code", 4),
        ("shared_resources", 1),
        ("container_registry", 3),
        ("secrets_vault", 4),
        ("build_artifacts", 2),
        ("public_endpoints", 1),
    ]

    security_levels = (
        "Development",
        "Staging",
        "Production",
        "Critical Infrastructure",
    )

    blocked_users = {
        "migrated_user",
        "container_breach",
        "pipeline_compromise",
    }

    #Вивід списку ресурсів із текстовими рівнями замість чисел
    print("\n--- Список ресурсів системи ---")
    for res_name, level in resources:
        # Оскільки рівні 1..4, а індекси 0..3, віднімаємо 1
        level_text = security_levels[level - 1]
        print("Ресурс: {:<25} | Рівень: {}".format(res_name, level_text))

    #Перевірка доступу кожної особи до кожного ресурсу
    print("\n--- Результати перевірки доступу ---")

    #Створюємо список користувачів (+ додаємо невідомого користувача для перевірки)
    test_users = list(users.keys()) + ["unknown_user"]

    for username in test_users:
        user_info = users.get(username)

        for res_name, res_level in resources:
            #Послідовна перевірка за правилами з методички
            if user_info is None:
                reason = "DENY (User not found)"
            elif username in blocked_users:
                reason = "DENY (User is blocked)"
            elif not user_info["active"]:
                reason = "DENY (Account inactive)"
            elif user_info["clearance"] >= res_level:
                reason = "ALLOW"
            else:
                reason = "DENY (Insufficient clearance)"

            print(
                "user={:<16} resource={:<22} -> {}".format(
                    username, res_name, reason
                )
            )


#Завдяки цьому блоку def працює у VS Code при прямому запуску файлу
if __name__ == "__main__":
    run_task2()