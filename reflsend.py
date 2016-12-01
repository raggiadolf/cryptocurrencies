import socket
from threading import Thread
import cPickle
import sys

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
rng = Random.new().read

cert_text = "This is a text to sign and verify"

key = RSA.generate(2048, rng)
public_key = key.publickey()
signature = key.sign(SHA256.new(cert_text).digest(), rng)

host = '127.0.0.1'
port = 59191

def decrypt(data):
	msg_obj = cPickle.loads(data)
	

def recv(s):
	while True:
		msg = s.recvfrom(2048)
		data = msg[0]
		addr = msg[1]
		if not data: sys.exit(0)
		print decrypt(data)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

keysig_object = {
	'key': public_key.exportKey(),
	'signature': signature
}

s.sendto(cPickle.dumps(keysig_object), (host, port))

Thread(target=recv, args=(s,)).start()

while True:
	msg = raw_input('>> ')
	s.sendto(msg, (host, port))
