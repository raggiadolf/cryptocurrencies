import socket
import sys
from bitarray import bitarray
from Crypto.Hash import SHA256

host = sys.argv[1]
#port = int(sys.argv[2])
zero_mask_string = bitarray('0'*256)

recv_host = '127.0.0.1'
recv_port = 59191
recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
recv_socket.connect((recv_host, recv_port))
print 'Socket connected to ' + recv_host

hostports = [
  59192,
  59193,
  59194,
  59195,
  59196,
  59197,
  59198,
  59199,
  59200,
  59201,
  59202
]

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

#prefix = bitarray(128)
#magic_len = 20

reply = recv_socket.recv(4096)
print reply
prefix = bitarray(bin(int(reply[:-2], base=16))[2:])
magic_len = int(reply[-2:])

mask_str = createmask(magic_len)

for p in hostports:
  s.sendto(prefix.to01(), (host, p))
  s.sendto(str(magic_len), (host, p))

sol = bitarray(s.recvfrom(2048)[0])

#t = SHA256.new(prefix + sol).hexdigest()

recv_socket.sendall(sol.to01())

print "Solution: " + sol.to01()
