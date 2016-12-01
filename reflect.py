import socket
import sys
from threading import Thread

host = ''
clients = []

def reflect(conn, clients):
	msg = conn.recvfrom(1024)
	data = msg[0]
	addr = msg[1]
	print "Received: (" + msg[0] + ") from: [" + addr[0] + ":" + str(addr[1]) + "]"
	recipient = filter(lambda client: client['host'] != addr[0] or client['port'] != addr[1], clients)
	if not recipient:
		print "Error, can't find recipient?"
		return
	conn.sendto(msg[0], (recipient[0]['host'], recipient[0]['port']))

def get_init_msg(conn, clients):
	msg = conn.recvfrom(1024)
	data = msg[0]
	addr = msg[1]
	new_client = {
		'host': addr[0],
		'port': addr[1]
	}
	c = filter(lambda client: client['host'] == new_client['host'] and client['port'] == new_client['port'], clients)
	if not c:
		print "Adding new client to client list (" + new_client['host'] + ":" + str(new_client['port']) + ")"
		clients.append(new_client)
	else:
		return

port = int(sys.argv[1])
conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
conn.bind(('', port))
while len(clients) < 2:
	get_init_msg(conn, clients)

while True:
	reflect(conn, clients)

print "Finished reflecting.. Exiting."