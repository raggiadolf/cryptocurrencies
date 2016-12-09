from threading import Thread
import Queue
import sys

threads = []
q = Queue

someone_found_solution = False

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