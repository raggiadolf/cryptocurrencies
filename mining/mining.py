from threading import Thread
import Queue
import sys
from Crypto.Hash import SHA256, MD5
import time
from bitarray import bitarray
import json
from pprint import pprint

someone_found_solution = False
zero_mask_string = bitarray('0'*256)

blockchain = {
    "head": "80dacec51a15d70091306ae7175ce02ffeb36a6786c0d0fbef99617f29300000",
    "80dacec51a15d70091306ae7175ce02ffeb36a6786c0d0fbef99617f29300000": {
        "comment": "Satoshi",
        "nonce": "e928213b91945a5cd539c7057cb5860a",
        "timestamp": 1481288588,
        "counter": 0,
        "difficulty": 20,
        "previous_block": None
    }
}

def get_head_block():
    return blockchain[blockchain["head"]]

def update_blockchain(new_block):
    new_block_hash = SHA256.new(json.dumps(new_block)).hexdigest()
    blockchain["head"] = new_block_hash
    blockchain[new_block_hash] = new_block

def test_new_block(new_block, mask_string):
    #new_block["previous_block"] = SHA256.new(json.dumps(blockchain[blockchain["head"]])).hexdigest()
    new_block_hash = SHA256.new(json.dumps(new_block)).hexdigest()
    print "new_block", new_block
    print "new_block_hash", new_block_hash
    return test_bits(hash_to_bits(new_block_hash), mask_string)

def hash_to_bits(hash):
  bits = bitarray(format(int(hash, 16), '0256b'))
  return bits

def test_bits(bits, mask_string):
  result = (mask_string & bits)
  return result == zero_mask_string

def create_mask(mlen):
  mask = '1' * mlen
  mask_string = bitarray('0'*(256-mlen) + mask)
  return mask_string

def worker(block, tid, mask_str, q):
    print "Worker {0} started".format(tid)
    global someone_found_solution
    i = 0
    proposed_block = {}
    proposed_block["comment"] = str(tid)
    proposed_block["counter"] = block["counter"] + 1
    proposed_block["difficulty"] = block["difficulty"]
    proposed_block["previous_block"] = SHA256.new(json.dumps(block)).hexdigest()
    proposed_block["nonce"] = "" # Empty to begin with, will be set on the second iteration

    while True:
        if i % 1000 == 0:
            if someone_found_solution: return

        proposed_block["timestamp"] = int(time.time())
        proposed_block["nonce"] = MD5.new(json.dumps(proposed_block)).hexdigest()
        t = SHA256.new(json.dumps(proposed_block)).hexdigest()
        if test_bits(hash_to_bits(t), mask_str):
            print "Worker: q.full:", q.full()
            print "Returning block", proposed_block
            q.put(proposed_block)
            return
            #print "q after put", q, q.qsize()
        i = i + 1

def start_workers(block, mask_str, no_of_workers, threads, q):
    print "Foreman: Starting workers"
    for i in range(no_of_workers):
        t = Thread(target=worker, args=(block, i, mask_str, q))
        t.start()
        threads.append(t)

def main():
    no_of_workers = int(sys.argv[1])
    print "Starting {0} workers".format(no_of_workers)
    mask_str = create_mask(get_head_block()["difficulty"])

    threads = []
    q = Queue.Queue(1)

    while True:
        start_workers(get_head_block(), mask_str, no_of_workers, threads, q)

        new_block = q.get()
        print "Foreman: got a new block from q, block", new_block
        print "Foreman: got a new block from q, hash", SHA256.new(json.dumps(new_block)).hexdigest()
        if test_new_block(new_block, mask_str):
            print "Found a new solution", new_block
            global someone_found_solution
            someone_found_solution = True
            for t in threads:
                print "Waiting for ", t
                t.join()
            print "Threads stopped, updating blockchain"
            update_blockchain(new_block)
            del threads
            threads = []
            del q
            q = Queue.Queue(1)

            print "Status of blockchain:"
            pprint(blockchain)
        else:
            print "New solution not verified", new_block
            print "blockchain atm", blockchain


main()
