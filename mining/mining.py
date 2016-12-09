from threading import Thread
import Queue
import sys
from Crypto.Hash import SHA256, MD5
import time
from bitarray import bitarray
import json

someone_found_solution = False
zero_mask_string = bitarray('0'*256)

blockchain = {
    "head": "154971044876302db71bcd6d972dafc73b0f7ed385007d52be109b05c9800000",
    "154971044876302db71bcd6d972dafc73b0f7ed385007d52be109b05c9800000": {
        "comment": "Satoshi",
        "nonce": "65963a5364864c6a36a36a3356a8c8c5",
        "timestamp": 1481282448,
        "counter": 0,
        "difficulty": 16,
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
    new_block["previous_block"] = SHA256.new(json.dumps(blockchain[blockchain["head"]])).hexdigest()
    new_block_hash = SHA256.new(json.dumps(new_block)).hexdigest()
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

def worker(block, id, mask_str, q):
    global someone_found_solution
    i = 0
    proposed_block = {}
    proposed_block["comment"] = str(id)
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
            print "Worker: Found proposed new block, returning"
            q.put(proposed_block)
            print "q after put", q, q.qsize()
        i = i + 1

def start_workers(block, mask_str, no_of_workers, threads, q):
    for i in range(no_of_workers):
        t = Thread(target=worker, args=(block, i, mask_str, q))
        t.daemon = True
        t.start()
        threads.append(t)

def main():
    no_of_workers = int(sys.argv[1])
    print "Starting {0} workers".format(no_of_workers)
    mask_str = create_mask(get_head_block()["difficulty"])

    threads = []
    q = Queue.Queue()

    while True:
        start_workers(get_head_block(), mask_str, no_of_workers, threads, q)

        new_block = q.get()
        print "Foreman: got a new block from q"
        isBlockVerified = test_new_block(new_block, mask_str)
        print 'the new block was verified? ', isBlockVerified
        while not isBlockVerified:
            print "Found a new solution, restarting EVERYTHING"
            someone_found_solution = True
            for t in threads:
                t.join()
            update_blockchain(new_block)
            del threads
            threads = []
            del q
            q = Queue.Queue()


main()
