import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def run_task2():
    print(
        "Завдання 2 (Студент: {}, Група: {}, Варіант: {}) ===".format(
            STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
        )
    )

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
  
    print("\n Список ресурсів системи")
    for res_name, level in resources:
      
        level_text = security_levels[level - 1]
        print("Ресурс: {:<25} | Рівень: {}".format(res_name, level_text))

    print("\n Результати перевірки доступу ")

    test_users = list(users.keys()) + ["unknown_user"]

    for username in test_users:
        user_info = users.get(username)

        for res_name, res_level in resources:
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


if __name__ == "__main__":
    run_task2()
