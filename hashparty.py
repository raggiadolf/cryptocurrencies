from Crypto.Hash import SHA256
import time
from bitarray import bitarray

magic_len = 4

mask = '11111111'
mask_string = bitarray('0'*248 + mask)
#print mask_string

k = bitarray(128)
x = bitarray(128)

e = bitarray(256)

def hashtobits(hash):
	#return bitarray(bin(int(hash, 16))[2:])
	i = int(hash, 16)
	print format(i, '256b')
	bits = bitarray(format(int(hash, 16), '0256b'))
	print bits.length()
	return bits

def testbits(bits):
	print 'mask_string len: ' + str(len(mask_string))
	print 'bit len: ' + str(len(bits))
	result = (mask_string & bits)
	return result == '00000000'

def test(hashedvalue):
	return (int(hashedvalue, 16) % (2 ** magic_len)) == 0

start = time.time()
for i in range(100000):
	print 'x length: ' + str(x.length())
	t = SHA256.new(k + x).hexdigest()
	#print(hashtobits(t))
	#if testbits(hashtobits(t)) is True:
	if testbits(hashtobits(t)) is True:
		print "Found x: " + str(x)
		break
	#x = x + bitarray('1')
	newx = bin(int(x.to01(), 2) + 1)[2:]
	print newx
	x = bitarray(newx)
end = time.time()
print(end - start)