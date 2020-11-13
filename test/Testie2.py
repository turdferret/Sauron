import time
import atexit
import sys
import os


def goodbye(message):
    print(message)
    print()

if __name__ == '__main__':
    goodbye(sys.argv[1:])
    atexit.register(goodbye, "Goob Bye!!!!!!")

    count = 0
    while True:
        count += 1

        if count == 10:
            count = 0
            print("Hello World????")

        time.sleep(1)


