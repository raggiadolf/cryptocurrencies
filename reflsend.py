import socket
from threading import Thread
import cPickle
import sys

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
rng = Random.new().read

cert_text = "This is a text to sign and verify"

host = '127.0.0.1'
port = 59191

recipient = {}

def gen_key(rng):
	key = RSA.generate(2048, rng)
	public_key = key.publickey()
	signature = key.sign(SHA256.new(cert_text).digest(), rng)
	return key, public_key, signature

def verify(key, signature):
	return key.verify(SHA256.new(cert_text).digest(), signature)

def decrypt(msg):
	return key.decrypt(msg)
	
def recv(s):
	while True:
		msg = s.recvfrom(2048)
		data = msg[0]
		addr = msg[1]
		if not data: sys.exit(0)
		print "\n" + decrypt(data)
		sys.stdout.write('>> ')
		sys.stdout.flush()

def init(s):
	recipient_obj = cPickle.loads(s.recvfrom(2048)[0])

	print "Received recipient info from server"

	return recipient_obj

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

key, public_key, signature = gen_key(rng)

keysig_object = {
	'key': public_key.exportKey(),
	'signature': signature
}

s.sendto(cPickle.dumps(keysig_object), (host, port))

print "Opening secure channel, waiting for recipient to join..."
recipient = init(s)

print "Verifying..."
if not verify(recipient['key'], recipient['signature']):
		print "Key signature not verified, exiting..."
		sys.exit()

print "Recipient info received and verified. Start chatting away."

t = Thread(target=recv, args=(s,))
t.daemon = True
t.start()

while True:
	msg = raw_input('>> ')
	s.sendto(recipient['key'].encrypt(msg, 32)[0], (host, port))
