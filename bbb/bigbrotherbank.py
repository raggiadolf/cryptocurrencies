import socket
import sys
import json
import uuid
import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
rng = Random.new().read

from pprint import pprint
from threading import Thread

bank_public_key = None

def generateKey():
  return RSA.generate(2048, rng)

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

def generateId():
  return str(uuid.uuid4())

def generateTransactionId(transactions):
  transaction_id = generateId()
  if validateTransactionId(transactions, transaction_id):
    return transaction_id
  else:
    generateTransactionId(transactions)

def validateTransactionId(transactions, transaction_id):
  if transactions.get(transaction_id):
    return False
  else:
    return True

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
    transaction_id = generateTransactionId(config['transactions'])
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

def createClient(data):
  config = openConfigFile()
  clients = config['clients']

  success = False

  if not clients.get(data['id']):
    new_client = {
      'amount': 0.0,
      'key': data['key']
    }
    config[data['id']] = new_client
    with open('config.json', 'w') as f:
      f.write(json.dumps(config))

    success = True

  return {
    'success': success
  }

def init(bank_key):
  return {
    'success': True,
    'key': bank_key.publickey().exportKey(),
    'type': 'init'
  }

def getClientInfo(client_id):
  clients = openConfigFile['clients']

  client_info = clients[client_id]

  if not client_info:
    print "Could not find client info"
    return

  return client_info

def decrypt(bank_key, data):
  list_decrypted = [bank_key.decrypt(base64.b64decode(chunk)) for chunk in json.loads(data)]
  return json.loads(''.join(list_decrypted))

def encrypt(data, client_id):
  client_info = getClientInfo(client_id)
  client_key = RSA.importKey(client_info['key'])

  return client_key.encrypt(data, 32)[0]

def is_json(json_obj):
  try:
    json.loads(json_obj)
  except ValueError, e:
    return False
  return True

def recv(s, bank_key):
  while True:
    d = s.recvfrom(6144)
    encrypted_data = d[0]
    addr = d[1]

    if not encrypted_data: break

    if type(json.loads(encrypted_data)) is not list:
      # Shitty hack to intercept the first init msg
      response = init(bank_key)
      s.sendto(json.dumps(response), addr)
      continue

    data_id = decrypt(bank_key, encrypted_data)
    client_id = data_id['id']
    data = data_id['message']

    response = ''
    if verifyClients(data):
      if data['type'] == 'authorize':
        print "Received authorize request"
        response = authorize(data)
        response['type'] = 'authorize'
      elif data['type'] == 'verify':
        response = verify(data)
        response['type'] = 'verify'
      elif data['type'] == 'create':
        response = createClient(data)
        response['type'] = 'create'
      else:
        response = getAllTransactions()
    else:
      response = {
        'success': False
      }

    encrypted_response = encrypt(response, client_id)
    s.sendto(json.dumps(encrypted_response), addr)

def openConfigFile():
  with open('config.json') as data_file:
    return json.load(data_file)

def printClientTransactions(client, is_payer):
  transactions = openConfigFile()['transactions']
  client_id = 'receiver_id'
  if is_payer:
    client_id = 'payer_id'
  has_transactions = False
  for k, v in transactions.iteritems():
    if v[client_id] == client:
      has_transactions = True
      print "Transaction id " + k
      for kk, vv in transactions[k].iteritems():
        print "\t" + kk + ": " + str(vv)
  if not has_transactions:
    print 'The ' + client_id + ' has no transactions'

def printAllTransactions():
  transactions = openConfigFile()['transactions']
  for k, v in transactions.iteritems():
    print "Transaction id: " + k
    for kk, vv in transactions[k].iteritems():
      print "\t" + kk + ": " + str(vv)

def getClientTransactions(isPayer):
  if isPayer:
    print 'Input the payer ID'
    payer_id = raw_input('>> ')
    printClientTransactions(payer_id, True)
  else:
    print 'Input the receiver ID'
    receiver_id = raw_input('>> ')
    printClientTransactions(receiver_id, False)

def commandLine():
  while True:
    cmd = raw_input('>> ')
    if cmd.lower() == 'getalltransactions':
      printAllTransactions()
    elif cmd.lower() == 'payer':
      getClientTransactions(True)
    elif cmd.lower() == 'receiver':
      getClientTransactions(False)
    elif cmd.lower() == 'q' or cmd.lower() == 'quit' or cmd.lower() == 'exit': # Quit
      print "Exiting..."
      sys.exit()
    else:
      print "Command not recognized"

def main():
  host = ''
  port = int(sys.argv[1])

  bank_key = generateKey()
  bank_public_key = bank_key.publickey()

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

  recv_thread = Thread(target=recv, args=(s, bank_key,))
  recv_thread.daemon = True
  recv_thread.start()

  commandLine()

main()
