import socket
from threading import Thread
import sys
import json
import base64

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
rng = Random.new().read

cert_text = "This is a text to sign and verify"

host = sys.argv[1]
port = int(sys.argv[2])
bank_host = sys.argv[3]
bank_port = int(sys.argv[4])

bank_key = None

# Returns a json object including the information received from BBB
def query_bank(s, data, my_id, key):
	obj = {
		'id': my_id,
		'message': data
	}

	encrypted_msg = encrypt(obj, bank_key)
	s.sendto(encrypted_msg, (bank_host, bank_port))

def processAuthorize(s, my_id):
	print "Input the amount to transfer"
	amount = int(raw_input('>> '))
	print "Input the recipients ID"
	recip_id = raw_input('>> ')
	auth_obj = {
		'type': 'authorize',
		'payer_id': my_id,
		'receiver_id': recip_id,
		'amount': amount
	}

	query_bank(s, auth_obj, my_id, bank_key)

def processVerify(s, my_id):
	print "Input the amount to verify"
	amount = int(raw_input('>> '))
	print "Input the payer ID"
	payer_id = raw_input('>> ')
	print "Input the transaction ID"
	trans_id = raw_input('>> ')
	verify_obj = {
		'type': 'verify',
		'payer_id': payer_id,
		'receiver_id': my_id,
		'amount': amount,
		'transaction_id': trans_id
	}

	query_bank(s, verify_obj, my_id, bank_key)

def processSendId(my_id, s, remotePubKey):
	encryptedMessage = encrypt(str(my_id), remotePubKey)
	s.sendto(encryptedMessage[0], (host, port))

def printTransactions(transactions):
	for k, v in transactions.iteritems():
		print "Transaction id: " + k
		for kk, vv in t['transactions'][k].iteritems():
			print "\t" + kk + ": " + str(vv)

def processGetTransactions(my_id):
	trans_obj = {
		'type': 'gettransactions',
		'payer_id': my_id
	}

	resp = query_bank(s, trans_obj, my_id, bank_key)
	if not resp['success']:
		print "No transactions found for this id."
		return
	printTransactions(resp['transactions'])

def sendInitMessageToBank(s):
	init_obj = {
		'type': 'init'
	}

	s.sendto(json.dumps(init_obj), (bank_host, bank_port))

def processCreateClient(my_id, my_pub_key, s):
	create_obj = {
		'type': 'create',
		'id': my_id,
		'key': my_pub_key.exportKey()
	}

	query_bank(s, create_obj, my_id, bank_key)

def processCommands():
	print "Available commands:"
	print "\t/authorize"
	print "\t\tAuthorize a payment to Big Brother Bank"
	print "\t/verify"
	print "\t\tVerify a payment from Big Brother Bank"
	print "\t/sendid"
	print "\t\tSend your ID to your chat recipient"
	print "\t/gettransactions"
	print "\t\tGet your transactions from Big Brother Bank"
	print "\tcreateclient"
	print "\t\tCreates a client with BBB using your generated ID"
	print "\t/quit"
	print "\t\tExit this program"

def processCmd(cmd, my_id, s, remotePubKey, my_pub_key):
	if cmd.lower() == 'commands':
		processCommands()
	elif cmd.lower() == 'authorize':
		processAuthorize(s, my_id)
	elif cmd.lower() == 'verify':
		processVerify(s, my_id)
	elif cmd.lower() == 'sendid':
		processSendId(my_id, s, remotePubKey)
	elif cmd.lower() == 'gettransactions':
		processGetTransactions(my_id)
	elif cmd.lower() == 'createclient':
		sendInitMessageToBank(s)
	elif cmd.lower() == 'exit' or cmd.lower() == 'quit' or cmd.lower() == 'q':
		print "Exiting..."
		sys.exit()
	else:
		print "Command not recognized."

def string_to_chunks(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def encrypt(message, pub_key):
	messages = list(string_to_chunks(json.dumps(message), 256))
	messages_encrypted = [base64.b64encode(pub_key.encrypt(m, 32)[0]) for m in messages]
	return json.dumps(messages_encrypted)

def decrypt(message, key):
	list_decrypted = [key.decrypt(base64.b64decode(chunk)) for chunk in json.loads(message)]
	return json.loads(''.join(list_decrypted))

def verifyKey(rsakey, signature, key):
	return rsakey.verify(SHA256.new(cert_text).digest(), signature)

def handleBankMsg(key, my_id, data, s):
	json_data = json.loads(data)

	if type(json.loads(data)) is not list:
		resp = json_data
	else:
		resp = decrypt(json_data, key)

	msg_type = resp['type']

	msg_type = resp['type']
	if msg_type == 'authorize':
		if resp['success']:
			print "Payment authorized"
			print "Transaction:", resp['transaction_id']
		else:
			print "Payment not authorized"
	elif msg_type == 'verify':
		if resp['success']:
			print "Transaction successfully verified by BBB"
		else:
			print "Transaction not verified by BBB"
	elif msg_type == 'create':
		if resp['success']:
			print "Account with BBB successfully created."
		else:
			print "Could not create account with BBB."
	elif msg_type == 'init':
		if resp['success']:
			global bank_key
			bank_key = RSA.importKey(resp['key'])
			processCreateClient(my_id, key.publickey(), s)
	else:
		print "Unkown type received from BBB", resp


def recv(s, key, my_id):
	while True:
		msg = s.recvfrom(6144)
		addr = msg[1]
		if addr != (host, port):
			# Shitty hack to check whether the message came from the chat server or BBB
			handleBankMsg(key, my_id, msg[0], s)
			continue
		data = msg[0]

		if not data: sys.exit(0)

		decryptedMessage = decrypt(data, key)
		print 'Remote says: ', decryptedMessage['msg']

def send(s, remotePubKey, my_id, my_pub_key):
	while True:
		message = raw_input('>> ')
		if message.startswith('/'):
			processCmd(message[1:], my_id, s, remotePubKey, my_pub_key)
			continue
		msg_obj = {
			'msg': message
		}
		encryptedMessage = encrypt(msg_obj, remotePubKey)
		s.sendto(encryptedMessage, (host, port))

def getRemotePublicKey(initmessage, key):
	remotePubKey = ''
	if verifyKey(RSA.importKey(initmessage['key']), initmessage['signature'], key):
		remotePubKey = RSA.importKey(initmessage['key'])
	else:
		print 'Key is not verified'
	return remotePubKey

def generateKey():
	return RSA.generate(2048, rng)

def generateId(key):
	return SHA256.new(key.exportKey()).hexdigest()

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
	my_id = generateId(localKey.publickey())

	s.sendto(json.dumps(generateKeySigObject(localKey)), (host, port))
	initmessage = json.loads(s.recvfrom(6144)[0])

	remotePubKey = getRemotePublicKey(initmessage, localKey)

	print "Type /commands for a list of available commands, or start typing away to chat."

	recv_thread = Thread(target=recv, args=(s, localKey, my_id))
	recv_thread.daemon = True
	recv_thread.start()

	send(s, remotePubKey, my_id, localKey.publickey())

main()
