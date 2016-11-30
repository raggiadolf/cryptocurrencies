import socket
import sys
from base64 import b64decode
import cPickle

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
rng = Random.new().read

cert_text = "This is a text to sign and verify"

key = RSA.generate(2048, rng)
public_key = key.publickey()
signature = key.sign(SHA256.new(cert_text).digest(), rng)

if len(sys.argv) is not 3:
	print 'Missing argument, exiting...'
	sys.exit()

host = sys.argv[1]
port = int(sys.argv[2])

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
	print 'Failed to create socket'
	sys.exit()

keysig_object = {
	'key': public_key.exportKey(),
	'signature': signature
}

s.sendto(cPickle.dumps(keysig_object), (host, port))
bob_key = RSA.importKey(s.recvfrom(2048)[0])

while(True):
	msg = raw_input('>> ')

	encoded_msg = bob_key.encrypt(msg, 32)

	try:
		s.sendto(encoded_msg[0], (host, port))

		d = s.recvfrom(2048)
		reply = d[0]
		addr = d[1]

		print 'Server reply : ' + key.decrypt(reply)

	except socket.error as msg:
		print('Error code: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()
