import socket
from threading import Thread
import cPickle
import sys
import json
import uuid

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
rng = Random.new().read

cert_text = "This is a text to sign and verify"

bank_host = ''
bank_port = 59190
host = '127.0.0.1'
port = 59191

def query_bank(s, data):
    s.sendto(json.dumps(data), (bank_host, bank_port))
    return json.loads(s.recv(4096))

def processAuthorize():
	print "Input the amount to transfer"
	amount = int(raw_input('>> '))
	print "Input the recipients ID"
	recip_id = raw_input('>> ')
	auth_obj = {
		'payer_id': my_id,
		'receiver_id': recip_id,
		'amount': amount
	}

	resp = query_bank(s, auth_obj) # The response from BBB

	if resp['success']:
		print "Payment authorized"
		print "Transaction:", resp['transaction_id']
	else:
		print "Payment not authorized"

def processVerify():
	print "Input the amount to verify"
	amount = int(raw_input('>> '))
	print "Input the payer ID"
	payer_id = raw_input('>> ')
	print "Input the transaction ID"
	trans_id = raw_input('>> ')
	verify_obj = {
		'payer_id': payer_id,
		'receiver_id': my_id,
		'amount': amount,
		'transaction_id': trans_id
	}

	resp = query_bank(s, verify_obj) # The response from BBB

	if resp['success']:
		print "Transaction successfully verified by BBB"
	else:
		print "Transaction not verified by BBB"

def processSendId(my_id, s, remotePubKey):
	encryptedMessage = encrypt(str(my_id), remotePubKey)
	s.sendto(encryptedMessage[0], (host, port))

def processCommands():
	print "Available commands:"
	print "\t/authorize"
	print "\t\tAuthorize a payment to Big Brother Bank"
	print "\t/verify"
	print "\t\tVerify a payment from Big Brother Bank"
	print "\t/sendid"
	print "\t\tSend your ID to your chat recipient"
	print "\t/q (quit/exit)"
	print "\t\tExit this program"

def processCmd(cmd, my_id, s, remotePubKey):
	if cmd.lower() == 'commands':
		processCommands()
	elif cmd.lower() == 'authorize':
		processAuthorize()
	elif cmd.lower() == 'verify':
		processVerify()
	elif cmd.lower() == 'sendid':
		processSendId(my_id, s, remotePubKey)
	elif cmd.lower() == 'exit' or cmd.lower() == 'quit' or cmd.lower() == 'q':
		print "Exiting..."
		sys.exit()
	else:
		print "Command not recognized."

def encrypt(message, remotePubKey):
	return remotePubKey.encrypt(message, 32)

def decrypt(message, key):
	return key.decrypt(message)

def verifyKey(rsakey, signature, key):
	return rsakey.verify(SHA256.new(cert_text).digest(), signature)

def recv(s, key, my_id):
	while True:
		msg = s.recvfrom(6144)
		data = cPickle.loads(msg[0])
		addr = msg[1]

		if not data: sys.exit(0)

		decryptedMessage = decrypt(data, key)
		print 'Remote says: ', decryptedMessage

def send(s, remotePubKey, my_id):
	while True:
		message = raw_input('>> ')
		if message.startswith('/'):
			processCmd(message[1:], my_id, s, remotePubKey)
			continue
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

def generateId():
	return uuid.uuid4()

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
	my_id = generateId()

	s.sendto(cPickle.dumps(generateKeySigObject(localKey)), (host, port))
	initmessage = cPickle.loads(s.recvfrom(6144)[0])

	remotePubKey = getRemotePublicKey(initmessage, localKey)

	print "Type /commands for a list of available commands, or start typing away to chat."

	recv_thread = Thread(target=recv, args=(s, localKey, my_id))
	recv_thread.daemon = True
	recv_thread.start()

	send(s, remotePubKey, my_id)

main()
