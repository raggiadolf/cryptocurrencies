import socket
import sys

from Crypto.PublicKey import RSA

f = open('key.pem', 'r')
key = RSA.importKey(f.read())

print(key.encrypt("This is hopefully a encrypted message", 32)[0])

'''
while(True):
	msg = raw_input('>> ')

	encoded_msg = bob_key.encrypt(msg, 32)

	try:
		s.sendto(encoded_msg[0], (host, port))

		d = s.recvfrom(1024)
		reply = d[0]
		addr = d[1]

		print 'Server reply : ' + key.decrypt(reply)

	except socket.error as msg:
		print('Error code: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()
'''