import socket
import sys
import json
import uuid

from pprint import pprint
from threading import Thread

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

def recv(s):
  while True:
    d = s.recvfrom(6144)
    data = json.loads(d[0].decode('utf-8'))
    addr = d[1]

    if not data: break

    response = ''
    if verifyClients(data):
      if data['type'] == 'authorize':
        response = authorize(data)
      elif data['type'] == 'verify':
        response = verify(data)
      else:
        response = getAllTransactions()
    else:
      response = {
        'success': False
      }

    s.sendto(json.dumps(response), addr)

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

  recv_thread = Thread(target=recv, args=(s,))
  recv_thread.daemon = True
  recv_thread.start()

  commandLine()

main()
