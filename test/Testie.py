import time
import multiprocessing


def extra(lock):
    lock.acquire()
    print("Starting Extra")
    lock.release()

    while True:
        lock.acquire()
        print("Extra Hello World!!!!")
        lock.release()
        time.sleep(4)


if __name__ == '__main__':
    lock = multiprocessing.Lock()

    p1 = multiprocessing.Process(target=extra, args=(lock,))
    p1.start()

    p2 = multiprocessing.Process(target=extra, args=(lock,))
    p2.start()

    while True:
        lock.acquire()
        print("Hello World!!!!")
        lock.release()
        time.sleep(4)


