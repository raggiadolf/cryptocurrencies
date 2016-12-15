import math
import sys
import binascii
from random import randint
from bitarray import bitarray
from bitarray import bitarray

prime = 257

def get_shares(s, n, k, prime):
  ''' Split the secret integer value into n number of shares

  Args:
    s: Integer value to be split into shares
    n: Number of shares to be shared
    k: Number of shares needed to reconsturct the secret from shares
    prime: Prime number used for mod calculations
  '''
  coef = [s]
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
        numerator = (numerator * next_position) % prime #finds numerator for L_i
        denominator = (denominator * (start_position - next_position)) % prime #finds denumerator for L_i
    secret = (prime + secret + (y[i] * numerator * mod_inverse(denominator, prime))) % prime #linear combination
  return secret

def main():
  print"Input '1' to get shares for a secret, input '2' to combine secret shares."
  option = raw_input('>> ')
  if option == "1":
    print"Input the secret you want to get shares for."
    secret = raw_input('>> ')
    print"Input the number of parts sufficient to construct the original secret."
    k = int(raw_input('>> '))
    print"Input the number of component you want to split the secret to"
    n = int(raw_input('>> '))

    for j in range(len(secret)):
      bit_arr = bin(int(binascii.hexlify(secret[j]), 16))
      sliced_bit_arr = bit_arr[2:]
      integer_bit = int(sliced_bit_arr, 2)
      prime_used, shares = get_shares(integer_bit, n, k, prime)
      print"Your shares are: ", shares
      print"n is: ", n
      print"k is: ", k
      print"j is: ", j
      print"The prime number used was: ", prime
  elif option == "2":
    print"Input the array of secrets you want combined."
    secrets_to_combine = eval(raw_input('>> '))
    original_secret = int(combine(secrets_to_combine, prime))
    print"The original secret is: ", binascii.unhexlify('%x' % original_secret)
  else:
    print"Please input either 1 or 2, exiting."
    sys.exit()

if __name__ == "__main__":
  main()
