import socket
import sys
from base64 import b64decode

from Crypto.PublicKey import RSA
from Crypto import Random
rng = Random.new().read

host = ''
port = 59191

'''
file_name = 'key.pem'
f = open(file_name, 'r')
key = RSA.importKey(f.read())
'''

key = RSA.generate(2048, rng)
public_key = key.publickey()

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

keymsg = s.recvfrom(1024)
alice_key = RSA.importKey(keymsg[0])
addr = keymsg[1]

s.sendto(public_key.exportKey(), addr)

while(True):
	d = s.recvfrom(1024)
	data = d[0]
	addr = d[1]

	if not data:
		break
		
	decoded_msg = key.decrypt(data)

	s.sendto(alice_key.encrypt(decoded_msg, 32)[0], addr)
	print 'Message[' + addr[0] + ':' + str(addr[1]) + '] - ' + decoded_msg.strip()

s.close()