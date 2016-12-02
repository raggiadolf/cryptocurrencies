from Crypto.Hash import SHA256
import time
from bitarray import bitarray
import socket
import sys

host = ''
port = int(sys.argv[1])

zero_mask_string = bitarray('0'*256)

x = bitarray(128)

def hashtobits(hash):
  bits = bitarray(format(int(hash, 16), '0256b'))
  return bits

def testbits(bits, mask_string):
  result = (mask_string & bits)
  return result == zero_mask_string

def createmask(mlen):
  mask = '1' * mlen
  mask_string = bitarray('0'*(256-magic_len) + mask)
  return mask_string

def findsolution(x, pref, mask_str):
  while True:
    t = SHA256.new(pref + x).hexdigest()
    if testbits(hashtobits(t), mask_str):
      print "Found x: ", x, len(x)
      return x
      break
    newx = bin(int(x.to01(), 2) + 1)[2:]
    x = bitarray(newx)  

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  print('Socket created')
except socket.error as msg:
  print('Failed to create socket. Error code: ' + str(msg[0]) + ' Message: ' + msg[1])
  sys.exit()

try:
  s.bind((host, port))
except socket.error as msg:
  print('Bind failed. Error code: ' + str(msg[0]) + ' Message: ' + msg[1])
  sys.exit()

print('Socket bind complete')

msg = s.recvfrom(2048)
k = bitarray(msg[0])
addr = msg[1]
magic_len = int(s.recvfrom(2048)[0])
mask_str = createmask(magic_len)

start = time.time()
sol = findsolution(x, k, mask_str)

end = time.time()
print(end - start)

s.sendto(sol.to01(), addr)
