import socket
import sys
import json
import uuid

def verify(verify_obj):
  with open('config.json') as data_file:
    config = json.load(data_file)
  transactions = config['transactions']
  success = False
  if transactions.get(verify_obj['transaction_id']):
    transaction_to_verify = transactions[verify_obj['transaction_id']]
    if transaction_to_verify['payer_id'] == verify_obj['payer_id'] and transaction_to_verify['receiver_id'] == verify_obj['receiver_id'] and transaction_to_verify['amount'] == verify_obj['amount']:
        success = True
  return {
    'success': success
  }

def authorize(auth_obj):
  with open('config.json') as data_file:
    config = json.load(data_file)
  clients = config['clients']
  payer_id = auth_obj['payer_id']
  payer_balance = clients[payer_id]['amount']
  print 'payer balance', payer_balance, 'amount to charge', auth_obj['amount']

  success = False
  if payer_balance >= auth_obj['amount']:
    success = True
    # TODO: check if this transaction number is already in the "table"
    transaction_id = str(uuid.uuid4())
    transferFunds(auth_obj, transaction_id)
    return {
      'success': True,
      'transaction_id': transaction_id
    }
  else:
    return {
      'success': False
    }

def verifyClients(data):
  with open('config.json') as data_file:
    config = json.load(data_file)
  clients = config['clients']
  payer_id = data['payer_id']
  receiver_id = data['receiver_id']

  isClientVerified = False
  if clients.get(payer_id) and clients.get(receiver_id) and (payer_id != receiver_id):
    isClientVerified = True
  return isClientVerified

def transferFunds(auth_obj, transaction_id):
  with open('config.json', 'r') as f:
    config = json.load(f)
    # exchange funds
    config['clients'][auth_obj['payer_id']]['amount'] = config['clients'][auth_obj['payer_id']]['amount'] - auth_obj['amount']
    config['clients'][auth_obj['receiver_id']]['amount'] = config['clients'][auth_obj['payer_id']]['amount'] + auth_obj['amount']
    # store transaction
    config['transactions'][transaction_id] = createTransactionObject(auth_obj)

  with open('config.json', 'w') as f:
    f.write(json.dumps(config))

def createTransactionObject(auth_obj):
  return {
    "amount": auth_obj['amount'],
    "payer_id": auth_obj['payer_id'],
    "receiver_id": auth_obj['receiver_id']
  }

def main():
  host = ''
  port = 59191

  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print 'socket created'
  except socket.error as msg:
    print 'Failed to create socket. Error code: ', str(msg[0]), ' Message: ', msg[1]
    sys.exit()

  try:
    s.bind((host, port))
  except socket.error as msg:
    print 'Failed to create socket. Error code: ', str(msg[0]), ' Message: ', msg[1]

  print 'Socket bind complete'

  while(True):
    d = s.recvfrom(4096)
    data = json.loads(d[0].decode('utf-8'))
    addr = d[1]

    if not data:
      break

    print('data..', data)

    response = ''
    if verifyClients(data):
      if data['type'] == 'authorize':
        response = authorize(data)
      else:
        response = verify(data)
    else:
      response = {
        'success': False
      }

    s.sendto(json.dumps(response), addr)

main()
