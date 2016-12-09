from threading import Thread
import Queue
import sys

threads = []
q = Queue

someone_found_solution = False

blockchain = {
    "head": "154971044876302db71bcd6d972dafc73b0f7ed385007d52be109b05c9800000",
    "154971044876302db71bcd6d972dafc73b0f7ed385007d52be109b05c9800000": {
        "comment": "Satoshi",
        "nonce": "65963a5364864c6a36a36a3356a8c8c5",
        "timestamp": 1481282448,
        "counter": 0,
        "difficulty": 21,
        "previous_block": null
    }
}

def worker():
    return True

def main():
    no_of_workers = int(sys.argv[1])
    print "Starting {0} workers".format(no_of_workers)

    for i in range(no_of_workers):
        t = Thread(target=worker, args=())
        t.daemon = True
        t.start()
        threads.append(t)



main()