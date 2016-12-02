import socket
import sys
from bitarray import bitarray
from Crypto.Hash import SHA256

host = sys.argv[1]
port = int(sys.argv[2])
zero_mask_string = bitarray('0'*256)

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

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
	print 'Failed to create socket'
	sys.exit()

prefix = bitarray(128)
magic_len = 20

mask_str = createmask(magic_len)

s.sendto(prefix.to01(), (host, port))
s.sendto(str(magic_len), (host, port))

sol = bitarray(s.recvfrom(2048)[0])

t = SHA256.new(prefix + sol).hexdigest()

print "Solution: " + sol.to01()

#if testbits(hashtobits(t), mask_str):
#	print "Got a solution back:"
#	print hashtobits(t).to01()
#else:
#	print "Wrong solution."