import socket
import sys
import json

def verify():
  return {
    'success': True
  }

def authorize():
  # check if payer has enough money
  return {
    'success': True,
    'transaction_id': 1
  }

def main():
  host = ''
  port = 59191

  with open('config.json') as data_file:
      config = json.load(data_file)

  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print('socket created')
  except socket.error as msg:
    print('Failed to create socket. Error code: ', str(msg[0]), ' Message: ', msg[1])
    sys.exit()

  try:
    s.bind((host, port))
  except socket.error as msg:
    print('Failed to create socket. Error code: ', str(msg[0]), ' Message: ', msg[1])

  print('Socket bind complete')

  while(True):
    d = s.recvfrom(4096)
    print('d', d)
    data = json.loads(d[0].decode('utf-8'))
    addr = d[1]


    response = ''
    if not data.get('transaction_id'):
      response = authorize()
    else:
      response = verify()

    if not data:
      break
    print('response', response)
    s.sendto(json.dumps(response), addr)

main()
