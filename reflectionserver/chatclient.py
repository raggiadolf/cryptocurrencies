import socket
from threading import Thread
import sys
import json
import base64
import getpass
import time
import pprint

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from ast import literal_eval as make_tuple
rng = Random.new().read

cert_text = "This is a text to sign and verify"

host = sys.argv[1]
port = int(sys.argv[2])
bank_host = sys.argv[3]
bank_port = int(sys.argv[4])

bank_key = None
connected_to_bank = False

# Returns a json object including the information received from BBB
def query_bank(s, data, my_id, key):
	'''Sends a query object to bigbrotherbank

	Args:
		s: The socket to send data on
		data: The data we want to send to the bank
		my_id: Our hashed public key, used as ID towards the bank
		key: The key used to encrypt the message
	'''
	obj = {
		'id': my_id,
		'message': data
	}

	global connected_to_bank
	if not connected_to_bank:
		print "C'mon man, what about the kittens?"
		print "Please use /connect and then reissue your command."
		return

	encrypted_msg = encrypt(obj, bank_key)
	s.sendto(encrypted_msg, (bank_host, bank_port))

def receive_input(participant_count, message, client):
  '''Prompts the user for info each participants

  Args:
  	participant_count: the no. of participants in this input/output list
  	message: What we want the user to input
  	client: The client the info is relevant to

  Returns:
  	A data list including info relating to each participant in auth_obj
  	particular transaction
  '''
  data = []
  for i in range(participant_count):
    print "Input the {0} for {1} #{2}".format(message, client, i + 1)
    input_message = raw_input('>> ')
    data.append(input_message)
  return data

def generate_authorization_object_info(clients_info, additional_info):
  '''Generates a transaction to send to the bank

  Args:
  	clients_info: A list with the info for each client involved in the transaction
  	additional_info:

  Returns:
  	A list of data to send to the bank relating to a transaction
  '''
  data = []
  for i in range(clients_info['count']):
  	data.append({
  	            'id': clients_info['ids'][i],
  	            'amount': clients_info['amounts'][i]
  	            #'signature': make_tuple(clients_info['signatures'][i]) # make_tuple used because the signatures need to be a tuple
  	            })
  return data

def get_authorization_info_from_input(initial_message, client_message):
	'''Prompts the user for info relating to a transaction

	Args:
		initial_message: What we are prompting the user for
		client_message:

	Returns:
		A clients info object relevant to the client involved in a transaction
	'''
	clients_info = {}
	print "Input the number of {0}".format(initial_message)
	clients_count = int(raw_input('>> '))
	clients_info['count'] = clients_count
	clients_info['amounts'] = map(int, receive_input(clients_count, "amount", client_message))
	clients_info['ids'] = receive_input(clients_count, "ID", client_message)

	#clients_info['signatures'] = receive_input(clients_count, "signature", client_message)
	return clients_info

def process_authorize(s, my_id):
	'''Get payers / receivers information from input

	Args:
		s: The socket to send data on
		my_id: My current id; SHA256 hash of my public key
	'''
	payers_info = get_authorization_info_from_input("participants (payers)", "payer")
	receivers_info = get_authorization_info_from_input("receivers of the money", "receiver")

	auth_obj = {
    'type': 'authorize',
    'input': generate_authorization_object_info(payers_info, receivers_info),
    'output':   generate_authorization_object_info(receivers_info, payers_info)
	}
	query_bank(s, auth_obj, my_id, bank_key)

def process_verify(s, my_id):
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

def process_send_id(my_id, s, remotePubKey):
	'''Send our id to our current chat opponent
	'''
	encryptedMessage = encrypt(str(my_id), remotePubKey)
	s.sendto(encryptedMessage[0], (host, port))

def printTransactions(transactions):
	for k, v in transactions.iteritems():
		print "Transaction id: " + k
		for kk, vv in t['transactions'][k].iteritems():
			print "\t" + kk + ": " + str(vv)

def process_get_transactions(my_id):
	trans_obj = {
		'type': 'gettransactions',
		'payer_id': my_id
	}

	resp = query_bank(s, trans_obj, my_id, bank_key)
	if not resp['success']:
		print "No transactions found for this id."
		return
	printTransactions(resp['transactions'])

def send_init_message_to_bank(s):
	'''Send an init message to the bank, prompting the bank
		to send us his public key
	'''
	init_obj = {
		'type': 'init'
	}

	s.sendto(json.dumps(init_obj), (bank_host, bank_port))

def processCreateClient(my_id, my_pub_key, s):
	'''Send the bank our id and public key
	'''
	create_obj = {
		'type': 'create',
		'id': my_id,
		'key': my_pub_key.exportKey()
	}

	query_bank(s, create_obj, my_id, bank_key)

def process_get_public_key(s, my_id):
	'''Constructs a query object containing the ID used to query for a public key
		from the bank
	'''
	print "Input the ID to query for"
	ID = raw_input('>> ')
	query_obj = {
		'type': 'getpublickey',
		'id': ID
	}

	query_bank(s, query_obj, my_id, bank_key)

def process_head(s, my_id):
	'''Constructs a query object asking the bank for the hash pointer to the current
		head of the blockchain
	'''
	query_obj = {
		'type': 'gethead'
	}

	query_bank(s, query_obj, my_id, bank_key)

def process_get_block(s, my_id):
	'''Requests a block from the bank with a particular id
	'''
	print "Input the hash pointer for the block to query for"
	ID = raw_input('>> ')
	query_obj = {
		'type': 'getblock',
		'id': ID
	}

	query_bank(s, query_obj, my_id, bank_key)

def process_put_block(s, my_id):
	'''Constructs a new block to send to the bank for verification
	'''

	payers_info = get_authorization_info_from_input("participants (payers)", "payer")
	receivers_info = get_authorization_info_from_input("receivers of the money", "receiver")

	# This next part, setting the previous_block and counter, could be hidden from the user
	# but we keep it explicit for now so that we can manifacture error cases

	print "Input the current head of the blockchain for the previous_block field in the new block"
	previous_block = raw_input('>> ')
	print "Input the counter for the new block"
	counter = int(raw_input('>> '))

	block = {
		'input': generate_authorization_object_info(payers_info, receivers_info),
		'output':   generate_authorization_object_info(receivers_info, payers_info),
		'previous_block': previous_block,
		'comment': my_id,
		'counter': counter,
		'timestamp': int(time.time())
	}

	query_obj = {
		'type': 'putblock',
		'block': block
	}

	query_bank(s, query_obj, my_id, bank_key)

def process_start_transaction(s, remotePubKey):
	'''Starts a transaction session: Gets input/output information from the user,
		then sends the transaction over to the peer for his signature,
		if the signature received is valid, we send the transaction to bbb
	'''
	payers_info = get_authorization_info_from_input("participants (payers)", "payer")
	receivers_info = get_authorization_info_from_input("receivers of the money", "receiver")

	transaction = {
		'input': generate_authorization_object_info(payers_info, receivers_info),
		'output': generate_authorization_object_info(receivers_info, payers_info)
	}

	msg_obj = {
		'type': 'transaction',
		'transaction': transaction
	}

	encrypted_message = encrypt(msg_obj, remotePubKey)
	s.sendto(encrypted_message, (host, port))

def process_commands():
	'''Prints a tooltip for the user with the available commands for the chatclient
	'''
	print "Please use /connect to connect to the bank before issuing any commands to the bank, otherwise bad things will happen to kittens."
	print "Available commands:"
	print "\t/connect"
	print "\t\tConnects to BBB"
	print "\t/getpublickey"
	print "\t\tGet a public key for a particular ID from BBB"
	print "\t/gethead"
	print "\t\tGet the hash pointer for the current head of the blockchain"
	print "\t/getblock"
	print "\t\tGet a block with a particular hash pointer from BBB"
	print "\t/putblock"
	print "\t\tAttempt to put a block onto the blockchain at BBB"
	print "\t/authorize"
	print "\t\tAuthorize a payment to Big Brother Bank"
	print "\t/verify"
	print "\t\tVerify a payment from Big Brother Bank"
	print "\t/sendid"
	print "\t\tSend your ID to your chat recipient"
	print "\t/quit"
	print "\t\tExit this program"

def process_cmd(cmd, my_id, s, remotePubKey, my_pub_key):
	'''Handles the commands available to the user
	'''
	if cmd.lower() == 'commands':
		process_commands()
	elif cmd.lower() == 'starttransaction':
		process_start_transaction(s, remotePubKey)
	elif cmd.lower() == 'putblock':
		process_put_block(s, my_id)
	elif cmd.lower() == 'getblock':
		process_get_block(s, my_id)
	elif cmd.lower() == 'getpublickey':
		process_get_public_key(s, my_id)
	elif cmd.lower() == 'gethead':
		process_head(s, my_id)
	elif cmd.lower() == 'authorize':
		process_authorize(s, my_id)
	elif cmd.lower() == 'verify':
		process_verify(s, my_id)
	elif cmd.lower() == 'sendid':
		process_send_id(my_id, s, remotePubKey)
	elif cmd.lower() == 'gettransactions':
		process_get_transactions(my_id)
	elif cmd.lower() == 'connect':
		send_init_message_to_bank(s)
	elif cmd.lower() == 'exit' or cmd.lower() == 'quit' or cmd.lower() == 'q':
		print "Exiting..."
		sys.exit()
	elif cmd.lower() == 'yes' or cmd.lower() == 'y' or cmd.lower() == 'no' or cmd.lower() == 'n':
		print "Are you sure? /yes /no"
	else:
		print "Command not recognized."

def string_to_chunks(string, length):
	'''Splits a particular string into chunks of 'length', the remainder of
    	the string will be in the last index of the list

    	Args:
      		string: The string to split
      		length: Length of each individual chunk

    	Returns:
      		A list containing the string split into chunks
  		'''
	return (string[0+i:length+i] for i in range(0, len(string), length))

def encrypt(message, pub_key):
	'''Encrypts a data for a particular client

  	Args:
    	data: The data to encrypt
    	client_id: The client which should receive the data

  	Returns:
    	An encrypted string representing 'data'
  	'''
	messages = list(string_to_chunks(json.dumps(message), 256))
	messages_encrypted = [base64.b64encode(pub_key.encrypt(m, 32)[0]) for m in messages]
	return json.dumps(messages_encrypted)

def decrypt(message, key):
	'''Decrypts data received from a socket using the banks private key

  	Args:
    	key: Our private key used for decryption
    	message: The data to decrypt

  	Returns:
    	A json object with the decrypted data
  	'''
	list_decrypted = [key.decrypt(base64.b64decode(chunk)) for chunk in message]
	return json.loads(''.join(list_decrypted))

def verify_key(rsakey, signature, key):
	return rsakey.verify(SHA256.new(cert_text).digest(), signature)

def handle_bank_msg(key, my_id, data, s):
	json_data = json.loads(data)

	if type(json_data) is not list:
		resp = json_data
	else:
		resp = decrypt(json_data, key)

	msg_type = resp['type']
	if msg_type == 'authorize':
		if resp['success']:
			print "Payment authorized\n>>"
			print "Transaction:", resp['transaction_id']
		else:
			print "Payment not authorized\n>> "
	elif msg_type == 'verify':
		if resp['success']:
			print "Transaction successfully verified by BBB\n>> "
		else:
			print "Transaction not verified by BBB\n>> "
	elif msg_type == 'create':
		if resp['success']:
			print "Account with BBB successfully created.\n>> "
		else:
			print "Connected to BBB.\n>> "
	elif msg_type == 'init':
		global connected_to_bank
		connected_to_bank = True
		if resp['success']:
			global bank_key
			bank_key = RSA.importKey(resp['key'])
			processCreateClient(my_id, key.publickey(), s)
	elif msg_type == 'getpublickey':
		if resp['success']:
			print "Key received: {0}\n>>".format(resp['key'])
		else:
			print "Did not receive a key from BBB with that ID\n>>"
	elif msg_type == 'gethead':
		if resp['success']:
			print "Current head of the blockchain: {0}\n>>".format(resp['head'])
		else:
			print "Bank could not supply us with the current head of the chain"
	elif msg_type == 'getblock':
		if resp['success']:
			print "Requested transaction: {0}\n>>".format(resp['transaction'])
		else:
			print "Bank did not find a transaction with that hash pointer"
	elif msg_type == 'putblock':
		if resp['success']:
			print "Successfully placed the block on the blockchain, hash pointer: {0}\n>>".format(resp['hash'])
		else:
			print "Could not place the block on the blockchain"

	else:
		print "Unkown type received from BBB", resp

def sign_transaction(transaction, verify_obj, key, my_id):
	entry = filter(lambda i:i['id'] == my_id, transaction['input'])

	if not entry:
		entry = filter(lambda o:o['id'] == my_id, transaction['output'])

	if not entry:
		print "Did not find my id in the transaction, can't sign it."
		return

	entry[0]['signature'] = key.sign(json.dumps(verify_obj), 42)[0]
	return transaction

def transaction_from_peer(s, key, my_id, remotePubKey, transaction):
	msg_obj = {
		'type': 'transaction_response'
	}
	print "\nReceived a transaction from peer"
	pp = pprint.PrettyPrinter(indent=4)
	pp.pprint(transaction)
	print "Would you like to sign this transaction? /yes /no"
	while True:
		resp = raw_input('>> ')
		if resp.lower() == '/y' or resp.lower() == '/yes':
			msg_obj['transaction'] = sign_transaction(transaction, transaction, key, my_id)
			if msg_obj['transaction']:
				msg_obj['success'] = True
			else:
				msg_obj['success'] = False
			break
		elif resp.lower() == '/n' or resp.lower() == '/no':
			msg_obj['success'] = False
			break
		else:
			print "Please input either '/yes' or '/no'"
			continue

	encrypted_message = encrypt(msg_obj, remotePubKey)
	s.sendto(encrypted_message, (host, port))

def transaction_response_from_peer(transaction, key, my_id, s):
	verify_obj = { # Pick out the information needed for the signatures
    	'input': [{ 'id': i['id'], 'amount': i['amount'] } for i in transaction['input']],
    	'output': [{ 'id': i['id'], 'amount': i['amount'] } for i in transaction['output']]
  	}
	transaction = sign_transaction(transaction, verify_obj, key, my_id)

	print "Input the current head of the blockchain for the previous_block field in the new block"
	previous_block = raw_input('>> ')
	print "Input the counter for the new block"
	counter = int(raw_input('>> '))

	block = {
		'input': transaction['input'],
		'output':   transaction['output'],
		'previous_block': previous_block,
		'comment': my_id,
		'counter': counter,
		'timestamp': int(time.time())
	}

	query_obj = {
		'type': 'putblock',
		'block': block
	}

	query_bank(s, query_obj, my_id, bank_key)


def recv(s, key, my_id, remotePubKey):
	while True:
		msg = s.recvfrom(6144)
		addr = msg[1]
		if addr != (host, port):
			# Shitty hack to check whether the message came from the chat server or BBB
			handle_bank_msg(key, my_id, msg[0], s)
			continue
		data = msg[0]

		if not data: sys.exit(0)

		decrypted_message = decrypt(json.loads(data), key)
		if decrypted_message['type'] == 'message':
			print 'Remote says: ', decrypted_message['msg']
		elif decrypted_message['type'] == 'transaction':
			transaction_from_peer(s, key, my_id, remotePubKey, decrypted_message['transaction'])
		elif decrypted_message['type'] == 'transaction_response':
			if decrypted_message['success']:
				transaction_response_from_peer(decrypted_message['transaction'], key, my_id, s)
			else:
				print "Peer did not sign transaction"

def send(s, remotePubKey, my_id, my_pub_key):
	while True:
		message = raw_input('>> ')
		if message.startswith('/'):
			process_cmd(message[1:], my_id, s, remotePubKey, my_pub_key)
			continue
		msg_obj = {
			'type': 'message',
			'msg': message
		}
		encryptedMessage = encrypt(msg_obj, remotePubKey)
		s.sendto(encryptedMessage, (host, port))

def get_remote_public_key(initmessage, key):
	remotePubKey = ''
	if verify_key(RSA.importKey(initmessage['key']), initmessage['signature'], key):
		remotePubKey = RSA.importKey(initmessage['key'])
	else:
		print 'Key is not verified'
	return remotePubKey

def generate_key():
	return RSA.generate(2048, rng)

def generate_id(key):
	return SHA256.new(key.exportKey()).hexdigest()

def generate_key_sig_object(key):
	localPubKey = key.publickey()
	signature = key.sign(SHA256.new(cert_text).digest(), rng)

	keysig_object = {
		'key': localPubKey.exportKey(),
		'signature': signature
	}
	return keysig_object

def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	print "Input '1' to use a generated key, input '2' to use your own key (which should be located in the pwd named 'key.pem'"
	option = raw_input('>> ')

	if option == "1":
		localKey = generate_key()
		print "New key generated just for this session"
	elif option == "2":
		print "Input name of the .pem keyfile"
		keyfile = raw_input('>> ')
		f = open(keyfile, 'r')
		print "Input passphrase"
		passphrase = getpass.getpass('>> ')
		localKey = RSA.importKey(f.read(),  passphrase=passphrase)
		f.close()
		print "Private key imported from", keyfile
	else:
		print "Please input either 1 or 2, exiting."
		sys.exit()
	my_id = generate_id(localKey.publickey())

	print "Establishing connection to host..."
	s.sendto(json.dumps(generate_key_sig_object(localKey)), (host, port))
	initmessage = json.loads(s.recvfrom(6144)[0])

	remotePubKey = get_remote_public_key(initmessage, localKey)

	print "Connected."
	print "Type /commands for a list of available commands, or start typing away to chat."

	recv_thread = Thread(target=recv, args=(s, localKey, my_id, remotePubKey))
	recv_thread.daemon = True
	recv_thread.start()

	send(s, remotePubKey, my_id, localKey.publickey())

main()
