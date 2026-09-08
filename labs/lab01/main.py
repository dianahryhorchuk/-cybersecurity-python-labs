import os
import sys

#Налаштування шляхів імпорту
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

#Імпортуємо головні функції з ваших файлів завдань
from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import main as run_task3


def main():
    print("   ДЕМОНСТРАЦІЯ ВИКОНАННЯ ЛАБОРАТОРНОЇ РОБОТИ №1   ")

    print(">>> ЗАПУСК ЗАВДАННЯ 1: Аналіз паролів <<<")
    run_task1()

    print("\n" + "=" * 50 + "\n")

    print(">>> ЗАПУСК ЗАВДАННЯ 2: Система контролю доступу <<<")
    run_task2()

    print("\n" + "=" * 50 + "\n")

    print(">>> ЗАПУСК ЗАВДАННЯ 3: Хешування, CSV та JSON-лог <<<")
    run_task3()

    print(" Усі завдання виконано ")


if __name__ == "__main__":
    main()
