from Crypto.Hash import SHA256
import time
from bitarray import bitarray

magic_len = 20

mask = '1'*magic_len
mask_string = bitarray('0'*(256-magic_len) + mask)
zero_mask_string = bitarray('0'*256)

k = bitarray(128)
x = bitarray(128)

def hashtobits(hash):
  bits = bitarray(format(int(hash, 16), '0256b'))
  return bits

def testbits(bits):
  result = (mask_string & bits)
  return result == zero_mask_string

start = time.time()
while True:
  t = SHA256.new(k + x).hexdigest()
  hashtobitsstring = hashtobits(t)
  if testbits(hashtobitsstring):
    print "Found x: ", x, len(x)
    print "Hash to bits string: ", hashtobitsstring
    break
  newx = bin(int(x.to01(), 2) + 1)[2:]
  x = bitarray(newx)

end = time.time()
print(end - start)
