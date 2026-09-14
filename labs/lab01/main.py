import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import main as run_task3


def main():
    print("  Демонстрація виконання лаборатороної роботи №1   ")

    print("Запуск завдання 1")
    run_task1()

    print("\n" + "=" * 50 + "\n")

    print("Запуск завдання 2")
    run_task2()

    print("\n" + "=" * 50 + "\n")

    print("Запуск завдання 3")
    run_task3()

    print(" Усі завдання виконано ")


if __name__ == "__main__":
    main()
