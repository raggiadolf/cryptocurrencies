import socket
import sys
from Crypto.Cipher import AES
from Crypto import Random 

key_size = 16
salt_size = 16
block_size = 16

def sxor(s1,s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def repeat_to_length(string_to_expand, length):
   return (string_to_expand * ((length/len(string_to_expand))+1))[:length]

def encrypt(msg, cipher):
	salt = Random.get_random_bytes(salt_size)
	padded_msg = pad_text(msg, block_size)
	salted_msg = padded_msg + salt
	return cipher.encrypt(salted_msg)

def decrypt(msg, cipher):
	salted_msg = cipher.decrypt(msg)
	desalted_msg = salted_msg[:-salt_size]
	return unpad_text(desalted_msg)

def pad_text(text, multiple):
    extra_bytes = len(text) % multiple
    padding_size = multiple - extra_bytes
    padding = chr(padding_size) * padding_size
    padded_text = text + padding
    return padded_text

def unpad_text(padded_text):
    padding_size = ord(padded_text[-1])
    text = padded_text[:-padding_size]
    return text

if len(sys.argv) is not 3:
	print 'Missing argument, exiting...'
	sys.exit()

host = sys.argv[1]
port = int(sys.argv[2])

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
	print 'Failed to create socket'
	sys.exit()

key = Random.get_random_bytes(key_size)
iv = '0000000000000000'
#key = raw_input('Enter the key to send: ')
cipher = AES.new(bytes(key), AES.MODE_CFB, iv)
s.sendto(key, (host, port))
accept_msg = s.recvfrom(1024)[0]
print 'Server accept message: ' + decrypt(accept_msg, cipher)

while(True):
	msg = raw_input('>> ')

	'''
	new_key = key
	if len(msg) > key_size:
		new_key = repeat_to_length(key, len(msg))
	encoded_msg = sxor(msg, new_key)
	'''
	encoded_msg = encrypt(msg, cipher)

	try:
		s.sendto(encoded_msg, (host, port))

		d = s.recvfrom(1024)
		reply = d[0]
		addr = d[1]

		#print 'Server reply : ' + sxor(reply, new_key)
		print 'Server reply : ' + decrypt(reply, cipher)

	except socket.error as msg:
		print('Error code: ' + str(msg[0]) + ' Message ' + msg[1])
		sys.exit()
