import socket
from threading import Thread

host = '52.28.126.187'
port = 59191

def recv(s):
	while True:
		msg = s.recvfrom(1024)
		data = msg[0]
		addr = msg[1]
		if not data: sys.exit(0)
		print data

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.sendto("init", (host, port))

Thread(target=recv, args=(s,)).start()

while True:
	msg = raw_input('>> ')
	s.sendto(msg, (host, port))