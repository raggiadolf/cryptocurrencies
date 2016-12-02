import socket
import sys
import os
import binascii
from threading import Thread

host = ''
port = 59191

connections = []

def accept_conns(s):
	while True:
		conn, addr = s.accept()
		print "Accepted connection from: ", addr
		connections.append({
				'conn': conn,
				'addr': addr
			})

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(20)

Thread(target=accept_conns, args=(s,)).start()

msg = raw_input('>> ')
if msg == 'start':
	rand_bytes = binascii.b2a_hex(os.urandom(16))
	magic_len = "20"
	for c in connections:
		c['conn'].sendall(rand_bytes + magic_len)