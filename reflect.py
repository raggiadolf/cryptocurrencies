import socket
import sys
from threading import Thread
import cPickle
from Crypto.PublicKey import RSA

host = ''
clients = []

def send_client_info(recipient, client):
	conn.sendto(cPickle.dumps(client), (recipient['host'], recipient['port']))

def reflect(conn, clients):
	msg = conn.recvfrom(2048)
	data = msg[0]
	addr = msg[1]
	print "Received: (" + msg[0] + ") from: [" + addr[0] + ":" + str(addr[1]) + "]" # This should be encrypted you pigs!
	recipient = filter(lambda client: client['host'] != addr[0] or client['port'] != addr[1], clients)
	sender = filter(lambda client: client['host'] == addr[0] and client['port'] == addr[1], clients)
	if not recipient:
		print "Error, can't find recipient?"
		return
	#msg_to_send = {
	#	'msg': msg[0],
	#	'client': sender[0]
	#}
	conn.sendto(data, (recipient[0]['host'], recipient[0]['port']))

def initiate(conn, clients):
	print "Waiting for first client..."
	get_init_msg(conn, clients)

	print "Waiting for second client..."
	get_init_msg(conn, clients)

	print "Both clients connected, distributing client info..."
	send_client_info(clients[0], clients[1])
	send_client_info(clients[1], clients[0])

	print "Client info distributed..."

def get_init_msg(conn, clients):
	msg = conn.recvfrom(2048)
	data = msg[0]
	addr = msg[1]
	new_client = {
		'host': addr[0],
		'port': addr[1]
	}
	c = filter(lambda client: client['host'] == new_client['host'] and client['port'] == new_client['port'], clients)
	if not c:
		print "Adding new client to client list (" + new_client['host'] + ":" + str(new_client['port']) + ")"
		key_obj = cPickle.loads(data)
		key = RSA.importKey(key_obj['key'])
		sig = key_obj['signature']
		new_client['key'] = key
		new_client['signature'] = sig
		clients.append(new_client)
	else:
		print "Not adding new client"
		return

port = int(sys.argv[1])
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
conn.bind(('', port))

initiate(conn, clients)

print "Connections initated, starting reflection..."

while True:
	reflect(conn, clients)

print "Finished reflecting.. Exiting."