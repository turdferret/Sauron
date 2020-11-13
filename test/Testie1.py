import time
import atexit
import sys
import os


def goodbye(message):
    print(message)


def start_up(fileplace):
    print("Starting!!!!")
    data = None
    try:
        os.mkfifo(fileplace)
        print("File Made and Reading File!!!!")

        with open(fileplace, "r") as fifo:
            data = fifo.read()

    except Exception as oe:
        data = None
        print(oe)
        print(oe.__traceback__.tb_lineno)

    print(data)
    os.remove(fileplace)
    print("Removing Fileplace!!!!")
    return data


if __name__ == '__main__':

    if len(sys.argv) > 1:
        data = start_up(sys.argv[1])
        goodbye(data)

    atexit.register(goodbye, "Goob Bye!!!!!!")

    count = 0
    while True:
        count += 1

        if count == 10:
            count = 0
            print("Hello World????")

        time.sleep(1)


