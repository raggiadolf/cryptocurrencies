import socket
import sys
from base64 import b64decode
import cPickle

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
rng = Random.new().read

cert_text = "This is a text to sign and verify"

host = ''
port = 59191

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

keymsg = s.recvfrom(2048)
alice_key_obj = cPickle.loads(keymsg[0])
alice_key = RSA.importKey(alice_key_obj['key'])
alice_signature = alice_key_obj['signature']
addr = keymsg[1]

if alice_key.verify(SHA256.new(cert_text).digest(), alice_signature) is False:
	print("Not verified")
	s.sendto("Signature not verified.", addr)
	# Loop here and request a new signature

s.sendto(public_key.exportKey(), addr)

while(True):
	d = s.recvfrom(2048)
	data = d[0]
	addr = d[1]

	if not data:
		break
		
	decoded_msg = key.decrypt(data)

	s.sendto(alice_key.encrypt(decoded_msg, 32)[0], addr)
	print 'Message[' + addr[0] + ':' + str(addr[1]) + '] - ' + decoded_msg.strip()

s.close()
