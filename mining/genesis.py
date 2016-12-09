from Crypto.Hash import SHA256, MD5
import time
from bitarray import bitarray
import json
import sys

difficulty = int(sys.argv[1])

block = {
    "previous_block": None,
    "comment": "Satoshi",
    "timestamp": "",
    "counter": 0,
    "difficulty": difficulty,
    "nonce": ""
}
zero_mask_string = bitarray('0'*256)

def hashtobits(hash):
  bits = bitarray(format(int(hash, 16), '0256b'))
  return bits

def testbits(bits, mask_string):
  result = (mask_string & bits)
  return result == zero_mask_string

def createmask(mlen):
  mask = '1' * mlen
  mask_string = bitarray('0'*(256-mlen) + mask)
  return mask_string

block["timestamp"] = int(time.time())
mask_str = createmask(block["difficulty"])

proposed_block = block
while True:
    proposed_block["nonce"] = MD5.new(json.dumps(proposed_block)).hexdigest()
    t = SHA256.new(json.dumps(proposed_block)).hexdigest()
    if testbits(hashtobits(t), mask_str):
        print "Found new block", proposed_block
        print hashtobits(t)
        print t
        break
