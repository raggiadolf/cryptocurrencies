import math
import sys
import binascii
import numpy as np

from random import randint
from ast import literal_eval
from bitarray import bitarray

prime = 251

def get_shares(secret, n, k):
  ''' Split the secret integer value into n number of shares

  Args:
    s: Integer value to be split into shares
    n: Number of shares to be shared
    k: Number of shares needed to reconsturct the secret from shares
    prime: Prime number used for mod calculations
  '''
  coef = [secret]
  shares = []
  for i in range(k - 1):
    coef.append(math.floor(randint(0, prime - 1)))

  for i in range(n):
    x = i + 1
    share = coef[0]
    for j in range(k - 1):
      exp = j + 1
      share = (share + (coef[exp] * (pow(x, exp) % prime) % prime)) % prime
    shares.append((x, share))
  return prime, shares

def e_gcd(a, b):
  ''' Calculate the Greatest Common Divisor of a and b.
      g = egcd(a, b)  and xa + yb = g

  Args:    a: The first number of the gcd calculations
    b: The second number of the gcd calculations
  '''
  if a == 0:
    return (b, 0, 1)
  else:
    g, x, y = e_gcd(b % a, a)
    return (g, y - (b // a) * x, x)

def mod_inverse(b, prime):
  ''' Calculates the multiplicative inverse of b mod prime.

  Args:
    b: Integer to mod
    prime: The prime number used for the mod
  '''
  g, x, _ = e_gcd(b, prime)
  if g == 1:
    return x % prime

def combine(shares, p):
  ''' Combines the share into an integer value using Lagrange

  Args:
    shares: the subset needed of the distibuted secret shares to find the secret
    p: a prime number specifying which modulus to work with

  Returns:
    The original secret
  '''
  secret = 0

  x = [x[0] for x in shares]
  y = [y[1] for y in shares]

  for i in range(len(x)): #number of polynomials L_k(x).
    numerator = 1.0 # resets numerator such that a new numerator can be created for each i.
    denominator = 1.0 #resets denumerator such that a new denumerator can be created for each i.
    for j in range(len(x)):
      start_position = x[i]
      next_position = x[j]
      if i != j:
        numerator = (numerator * -next_position) % prime #finds numerator for L_i
        denominator = (denominator * (start_position - next_position)) % prime #finds denumerator for L_i
    secret = (prime + secret + (y[i] * numerator * mod_inverse(denominator, prime))) % prime #linear combination

  return secret

def char_to_binary(char):
  #Char to binary. Returns a representation of an ASCII char on 8 bits with leading 0
  ret = bin(ord(char)) # convert char to binary
  ret = ret[2:len(ret)] #remove leading '0b'
  for i in xrange(len(ret), 8): #pad zeroes to make each representation 1 byte long
    ret = "0" + ret
  return ret

def secret_to_ascii(b):
  #Converts binary string into ascii character
  S = chr(int(b,2))
  return S

def dist_shares(secret, n, k):
  prime_hex = hex(251)[2:]
  shares = {}
  points = {}
  for s in range(n):
    shares[s+1]=str(k)+'|'
  for i in range(len(secret)): # for every char in the secret
    c2b = char_to_binary(secret[i])
    bin_to_int = int(c2b, 2)
    prime, sub_secret = get_shares(bin_to_int, n, k) # generate shares for this char
    testc  =int(combine(sub_secret, prime))
    for j in range(n):
      x = j + 1
      temp = '{0:02x}'.format(int(sub_secret[j][1]))
      if len(temp) == len(prime_hex):
        shares[x] += temp
      else:
        shares[x] += temp + (len(prime_hex) - len(temp)) * '#'
  return shares

def recover_secret(input_share):
  shares = {}
  req_shares = 0
  for x in input_share:
    share_index = x
    split_input = input_share[x].split('|')
    req_shares = int(split_input[0])
    share = split_input[1]
    if len(input_share) != req_shares:
      return "Not enough shares to recover the secret!"
    shares[share_index] = share

  final_secret = ''
  index = 1
  word_size = 2
  tuple_shares = []
  for key in shares:
    temp_arr = []
    for i in range(0, len(shares[key]), word_size):
      share = shares[key][i:i+2]
      temp_arr.append((key, int(share, 16)))
    tuple_shares.append(temp_arr)

  new_shares = []
  for i in range(len(tuple_shares[0])):
    temp_arr2 = []
    for j in range(req_shares):
      temp_arr2.append((tuple_shares[j][i]))
    new_shares.append(temp_arr2)

  for k in new_shares:
    temp = int(combine(k, prime))
    temp = secret_to_ascii(bin(temp)[2:])
    final_secret += temp
    index += index
  return final_secret

def main():
  print"Input '1' to get shares for a secret, input '2' to combine secret shares."
  option = raw_input('>> ')
  if option == "1":
    print"Input the secret you want to get shares for."
    secret = raw_input('>> ')
    print"Input the number of component you want to split the secret to"
    n = int(raw_input('>> '))
    print"Input the number of parts sufficient to construct the original secret."
    k = int(raw_input('>> '))
    shares = dist_shares(secret, n, k)
    print"Your shares are: ", shares
    print"n is: ", n
    print"k is: ", k
    print"The prime number used was: ", prime
  elif option == "2":
    print"Input the array of secrets you want combined."
    secrets_to_combine = literal_eval(raw_input('>> '))
    recovered_secret = recover_secret(secrets_to_combine)
    print"The original secret is: ", recovered_secret
  else:
    print"Please input either 1 or 2, exiting."
  sys.exit()

if __name__ == "__main__":
  main()
