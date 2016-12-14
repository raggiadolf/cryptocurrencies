import math
import scipy

from random import randint

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

  Args:
    a: The first number of the gcd calculations
    b: The second number of the gcd calculations
  '''
  if a == 0:
    return (b, 0, 1)
  else:
    g, x, y = e_gcd(b % a, a)
    return (g, y - (b // a) * x, x)

def mod_inverse(b, prime):
  ''' Gives the multiplicative inverse of b mod prime.

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
  '''
  secret = 0

  x = scipy.array([x[0] for x in shares])
  y = scipy.array([y[1] for y in shares])

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
  s = 129
  prime_used, shares = get_shares(s, 6, 3, prime)

  combined_shares = combine([shares[2], shares[4], shares[5]], prime_used)

  print('The secret is!: ', combined_shares)

if __name__ == '__main__':
  main()
