import socket
import sys

from Crypto.Cipher import AES
from Crypto import Random

host = ''
port = 59191
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

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print('Socket created')
except socket.error as msg:
	print('Failed to create socket. Error code: ' + str(msg[0]) + ' Message: ' + msg[1])
	sys.exit()

try:
	s.bind((host, port))
except socket.error as msg:
	print('Bind failed. Error code: ' + str(msg[0]) + ' Message: ' + msg[1])
	sys.exit()

print('Socket bind complete')

iv = '0000000000000000'

keymsg = s.recvfrom(1024)
key = keymsg[0]
addr = keymsg[1]

cipher = AES.new(bytes(key), AES.MODE_CFB, iv)

reply = 'Key received...'
s.sendto(encrypt(reply, cipher), addr)

while(True):
	d = s.recvfrom(1024)
	data = d[0]
	addr = d[1]

	if not data:
		break

	#new_key = key

	#if len(data) > len(key):
	#	new_key = repeat_to_length(key, len(data))

	#decoded_msg = sxor(data, new_key)

	decoded_msg = decrypt(data, cipher)

	#s.sendto(sxor(decoded_msg, new_key), addr)
	s.sendto(encrypt(decoded_msg, cipher), addr)
	print 'Message[' + addr[0] + ':' + str(addr[1]) + '] - ' + decoded_msg.strip()

s.close()
