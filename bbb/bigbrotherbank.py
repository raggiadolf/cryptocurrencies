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

def find_last_client_output(transactions, client_id):
  for t in transactions:
    c = filter(lambda client: client['id'] == client_id, t['output'])
    if c:
      return t, c

  return None

def check_transaction_in_out_amount(inputs, outputs):
  in_sum = sum(i['amount'] for i in inputs)
  out_sum = sum(o['amount'] for o in outputs)

  return in_sum == out_sum

def check_if_clients_are_valid(bank_clients, inputs, outputs):
  for i in inputs:
    c = filter(lambda client: client['id'] == i['id'], bank_clients)
    if not c:
      return False

  for o in outputs:
    c = filter(lambda client: client['id'] == o['id'], bank_clients)
    if not c:
      return False

  return True

def check_input_balance(transactions, inputs):
  for i in inputs:
    if get_client_balance(transactions, i['id']) < i['amount']:
      return False

  return True

def get_client_balance(transactions, client_id):
  last_transaction, last_output = find_last_client_output(transactions, client_id)
  if last_output:
    return last_output['amount']
  return 0

def verify_client_signature(bank_clients, auth_obj, client_id, signature):
  c = filter(lambda client: client['id'] == client_id, bank_clients)
  if not c:
    # Could not find a reference to this client, something went wrong!
    return False

  client_key = RSA.importKey(c['key'])
  return client_key.verify(json.dumps(auth_obj, signature))

def authorize(auth_obj):
  config = openConfigFile()
  clients = config['clients']
  transactions = config['transactions']

  if not check_transaction_in_out_amount(auth_obj['input'], auth_obj['output']):
    # In/Out amounts not equal, return error msg?
    print "Transaction in and out amount not equal"
    return {
      'success': False
    }

  if not check_if_clients_are_valid(clients, auth_obj['input'], auth_obj['output']):
    # Some client(s) participating in the transaction are not clients of the bank
    print "Some client in the transaction not validated in the system"
    return {
      'success': False
    }

  if not check_input_balance(transactions, auth_obj['input']):
    # Some payer does not have the neccessary funds available
    print "Some payer does not have the neccessary funds available"
    return {
      'success': False
    }

  transaction_id = generateTransactionId(transactions)
  transaction_input = []
  transaction_output = []

  for i in auth_obj['input']:
    if not verify_client_signature(clients, auth_obj, i['id'], i['signature']):
      # This client's signature does not check out with this transaction
      print "Some clients signature does not match"
      return {
        'success': False
      }
    client_balance = get_client_balance(transactions, i['id'])
    prev_amount = client_balance
    new_amount = client_balance - i['amount']

    new_input_obj = {
      "id": i['id'],
      "amount": prev_amount,
      "signature": i['signature']
    }
    transaction_input.append(new_input_obj)

    new_output_obj = {
      "id": i['id'],
      "amount": new_amount,
      "signature": i['signature']
    }
    transaction_output.append(new_output_obj)

  for o in auth_obj['output']:
    if not verify_client_signature(clients, auth_obj, o['id'], o['signature']):
      # This client's signature does not check out with this transaction
      print "Some clients signature does not match"
      return {
        'success': False
      }
    client_balance = get_client_balance(transactions, i['id'])
    prev_amount = client_balance
    new_amount = client_balance + i['amount']

    new_input_obj = {
      "id": i['id'],
      "amount": prev_amount,
      "signature": i['signature']
    }
    transaction_input.append(new_input_obj)

    new_output_obj = {
      "id": i['id'],
      "amount": new_amount,
      "signature": i['signature']
    }
    transaction_output.append(new_amount)

  transactions.insert(0, {
      "id": transaction_id,
      "input": transaction_input,
      "output": transaction_output
    })
  config['transactions'] = transactions


  with open('config.json', 'w') as f:
    f.write(json.dumps(config))

  return {
    'success': True,
    'transaction_id': transaction_id
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

  # See if we already have a client with this id
  client = filter(lambda client: client['id'] == data['id'], clients)
  if not client:
    # No client found in our config file with this id
    clients.append({
        'id': data['id'],
        'key': data['key']
      })
    config['clients'] = clients
    with open('config.json', 'w') as f:
      f.write(json.dumps(config))
    success = True
  else:
    # We found a client with this id, don't add him to the config file
    success = False

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
  clients = openConfigFile()['clients']

  client_info = filter(lambda client: client['id'] == client_id, clients)

  if not client_info:
    print "Could not find client info"
    return

  return client_info[0]

def string_to_chunks(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def decrypt(bank_key, data):
  list_decrypted = [bank_key.decrypt(base64.b64decode(chunk)) for chunk in json.loads(data)]
  return json.loads(''.join(list_decrypted))

def encrypt(data, client_id):
  client_info = getClientInfo(client_id)
  client_key = RSA.importKey(client_info['key'])

  messages = list(string_to_chunks(json.dumps(data), 256))
  messages_encrypted = [base64.b64encode(client_key.encrypt(m, 32)[0]) for m in messages]
  return json.dumps(messages_encrypted)

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

    encrypted_response = encrypt(response, client_id)
    s.sendto(encrypted_response, addr)

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
