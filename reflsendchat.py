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

def encrypt(message, remotePubKey):
	return remotePubKey.encrypt(message, 32)

def decrypt(message, key):
	return key.decrypt(message)

def verifyKey(rsakey, signature, key):
	return rsakey.verify(SHA256.new(cert_text).digest(), signature):

def recv(s, key):
	while True:
		msg = s.recvfrom(6144)
		data = cPickle.loads(msg[0])
		addr = msg[1]

		if not data: sys.exit(0)

		decryptedMessage = decrypt(data, key)
		print 'Remote says: ', decryptedMessage

def send(s, remotePubKey):
	while True:
		message = raw_input('>>')
		encryptedMessage = encrypt(message, remotePubKey)
		s.sendto(encryptedMessage[0], (host, port))

def getRemotePublicKey(initmessage, key):
	remotePubKey = ''
	if verifyKey(initmessage['key'], initmessage['signature'], key):
		remotePubKey = initmessage['key']
	else:
		print 'Key is not verified'
	return remotePubKey

def generateKey():
	return RSA.generate(2048, rng)

def generateKeySigObject(key):
	localPubKey = key.publickey()
	signature = key.sign(SHA256.new(cert_text).digest(), rng)

	keysig_object = {
		'key': localPubKey.exportKey(),
		'signature': signature
	}

	return keysig_object

def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	localKey = generateKey()

	s.sendto(cPickle.dumps(generateKeySigObject(localKey)), (host, port))
	initmessage = cPickle.loads(s.recvfrom(6144)[0])

	remotePubKey = getRemotePublicKey(initmessage, localKey)

	Thread(target=recv, args=(s, localKey)).start()
	Thread(target=send, args=(s, remotePubKey)).start()

main()
