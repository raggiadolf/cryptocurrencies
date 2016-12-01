from Crypto.Hash import SHA256
import time
from bitarray import bitarray

magic_len = 20

mask = '1'*magic_len
mask_string = bitarray('0'*(256-magic_len) + mask)
zero_mask_string = bitarray('0'*256)

print('mask', mask)

k = bitarray(128)
x = bitarray(128)

def hashtobits(hash):
  #return bitarray(bin(int(hash, 16))[2:])
  i = int(hash, 16)
  # print format(i, '256b')
  bits = bitarray(format(int(hash, 16), '0256b'))
  return bits

def testbits(bits):
  # print 'mask_string len: ' + str(len(mask_string))
  # print 'bit len: ' + str(len(bits))
  result = (mask_string & bits)
  return result == zero_mask_string

start = time.time()
for i in range(10000):
  print 'x length: ', len(x)
  t = SHA256.new(k + x).hexdigest()
  hashtobitsstring = hashtobits(t)
  if testbits(hashtobitsstring):
    print "Found x: ", x, len(x)
    print "Number of iterations: ", i
    print "Hash to bits string: ", hashtobitsstring
    break
  x = x + bitarray('1')
  newx = bin(int(x.to01(), 2) + 1)[2:]
  # x = x.to01()
  # newx = '{:0{}b}'.format(long(x, 2) + 1, len(x))
  x = bitarray(newx)

end = time.time()
print(end - start)
