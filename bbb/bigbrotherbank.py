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
  '''Generates a 2048bit RSA key. rng parameter to RSA.generate() is ignored.

  Returns:
    An RSA key object.
  '''
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
  '''Generates a unique id using the uuid python module.

  Returns:
    A string representation of a uuid
  '''
  return str(uuid.uuid4())

def generateTransactionId(transactions):
  '''Generates a unique ID for a transaction.

  We look up a generated ID in our transactions to see if it's already in use,
  if not, we return it, otherwise we generate a new ID.

  Args:
    transactions: The transactions currently in use in the blockchain

  Returns:
    A unique uuid
  '''
  transaction_id = generateId()
  if validateTransactionId(transactions, transaction_id):
    return transaction_id
  else:
    generateTransactionId(transactions)

def validateTransactionId(transactions, transaction_id):
  '''Checks if a given transaction ID is already in use

  Args:
    transactions: The transactions currently in use in the blockchain
    transaction_id: The newly generated transaction ID to validate

  Returns:
    True if a transaction ID is currently not being used, otherwise False.
  '''
  if transactions.get(transaction_id):
    return False
  else:
    return True

def find_last_client_output(transactions, client_id):
  '''Looks through the blockchain for the last time a particular 
    client appeared in the output

    Args:
      transactions: The transactions currently in use in the blockchain
      client_id: The client we want to find the last output transaction for

    Returns:
      A tuple containing both the transaction and the particular output the client 
      was involved in, we return the output as well just so that we don't need to
      look for it again when we want to query the amount.

      If no transaction is found we return None
      Should perhaps be (None, None) for compatability?
  '''
  t = transactions[transactions['head']]
  while t:
    c = filter(lambda client:client['id'] == client_id, t['output']) # Returns a list of output lines if client_id is present
    if c:
      return t, c[0] # We should only ever receive a single output line, so we simply return the first one found
    prev_block = t['previous_block'] # Traverse the blockchain
    if not prev_block: # The genesis block returns None, means we're at the start of the block
      break
    t = transactions[prev_block]

  return None

def check_transaction_in_out_amount(inputs, outputs):
  '''Sums up the inputs and outputs of a particular transaction 
    and checks if the sums match

  Args:
    inputs: The list of inputs to compare against the output list
    outputs: The list of outputs to compare against the input list

  Returns:
    True if the sums match, otherwise False
  '''
  in_sum = sum(i['amount'] for i in inputs)
  out_sum = sum(o['amount'] for o in outputs)

  return in_sum == out_sum

def check_if_clients_are_valid(bank_clients, inputs, outputs):
  '''Checks if all clients involved in a particular transactions have already
    got a client id with the bank.

    Args:
      bank_clients: A list of all clients currently registered with the bank
      inputs: A list of inputs in a particular transaction
      ouptuts: A list of outputs in a particular transaction

    Returns:
      True if all involved clients are registered with the bank, otherwise False.
  '''
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
  '''Checks whether all the input participants in a particular transaction have the
    neccessary funds available for that particular transaction

  Args:
    transactions: The transactions currently in use in the blockchain
    inputs: All inputs in a particular transaction

  Returns:
    True if all participants of the transaction can afford it, otherwise False.
  '''
  for i in inputs:
    if get_client_balance(transactions, i['id']) < i['amount']:
      return False

  return True

def get_client_balance(transactions, client_id):
  '''Gets the balance (the last output transaction) of a particular client

  Args:
    transactions: The transactions currently in use in the blockchain
    client_id: The ID of the client we want to look up the balance for

  Returns:
    The amount for the clients last output transaction; the clients current balance
  '''
  last_transaction, last_output = find_last_client_output(transactions, client_id) or (None, None)
  if last_output:
    return last_output['amount']
  return 0

def verify_client_signature(bank_clients, verify_obj, client_id, signature):
  '''Verify that a client signed a particular transaction

  Args:
    bank_clients: A list of all clients currently registered with the bank
    verify_obj: The transaction to verify, stripped of everything but the input+output lists
    client_id: The client whos signature we want to verify, used to look up the public key
    signature: The signature to verify

  Returns:
    True if the signature is successfully verified, otherwise False.
  '''
  c = filter(lambda client: client['id'] == client_id, bank_clients)
  if not c:
    # Could not find a reference to this client, something went wrong!
    return False
  client_key = RSA.importKey(c[0]['key'])
  return client_key.verify(json.dumps(verify_obj), signature)

def authorize(auth_obj):
  '''Authorizes a payment and attaches it to the blockchain
    Performs all the neccessary checks to make sure that the transaction is legit:
      Checks that the total input/output amounts match
      Checks if all the clients involved in the transaction are registered with the bank
      Checks if all the clients have the neccessary funds needed for the transaction

  Args:
    auth_obj: The transaction to authorize

  Returns:
    An object including the new transaction's ID if the transaction is successful,
    otherwise an object indicating failure.
  '''
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

  verify_obj = { # Pick out the information needed for the signatures
    'input': [{ 'id': i['id'], 'amount': i['amount'] } for i in auth_obj['input']],
    'output': [{ 'id': i['id'], 'amount': i['amount'] } for i in auth_obj['output']]
  }

  transaction_id = generateTransactionId(transactions)
  transaction_input = []
  transaction_output = []

  for i in auth_obj['input']:
    # Since we're looping through the inputs/outputs, we piggyback the verifications
    # on these loops
    if not verify_client_signature(clients, verify_obj, i['id'], i['signature']):
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
    if not verify_client_signature(clients, verify_obj, o['id'], o['signature']):
      # This client's signature does not check out with this transaction
      print "Some clients signature does not match"
      return {
        'success': False
      }
    client_balance = get_client_balance(transactions, o['id'])
    prev_amount = client_balance
    new_amount = client_balance + o['amount']

    new_input_obj = {
      "id": o['id'],
      "amount": prev_amount,
      "signature": o['signature']
    }
    transaction_input.append(new_input_obj)

    new_output_obj = {
      "id": o['id'],
      "amount": new_amount,
      "signature": o['signature']
    }
    transaction_output.append(new_output_obj)

  new_transaction = {
    "id": transaction_id,
    "input": transaction_input,
    "output": transaction_output,
    "previous_block": transactions['head']
  }
  new_transaction_hash = SHA256.new(json.dumps(new_transaction)).hexdigest()
  transactions[new_transaction_hash] = new_transaction
  transactions['head'] = new_transaction_hash

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
  '''Adds a new client to the banks config file

  Args:
    data: the ID (hashed publick key) and the public key for a new client

  Returns: An object indicating success if the client was added, 
    otherwise indicating failure.

    A client is not added to the config if his hashed public key is already
    present in the config.
  '''
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
  '''Used when initializing a clients connection with the bank

  Args:
    bank_key: The bank's private key

  Returns:
    An object containing the banks public key
  '''
  return {
    'success': True,
    'key': bank_key.publickey().exportKey(),
    'type': 'init'
  }

def getClientInfo(client_id):
  '''Looks up a particular clients info from the config file

  Args: 
    client_id: The ID for the client we want the info for

  Returns:
    The client info for the particular client (ID and public key)
  '''
  clients = openConfigFile()['clients']

  client_info = filter(lambda client: client['id'] == client_id, clients)

  if not client_info:
    print "Could not find client info"
    return

  return client_info[0]

def string_to_chunks(string, length):
  '''Splits a particular string into chunks of 'length', the remainder of
    the string will be in the last index of the list

    Args:
      string: The string to split
      length: Length of each individual chunk

    Returns:
      A list containing the string split into chunks
  '''
  return (string[0+i:length+i] for i in range(0, len(string), length))

def decrypt(bank_key, data):
  '''Decrypts data received from a socket using the banks private key

  Args:
    bank_key: The banks private key
    data: The data to decrypt

  Returns:
    A json object with the decrypted data
  '''
  list_decrypted = [bank_key.decrypt(base64.b64decode(chunk)) for chunk in json.loads(data)]
  return json.loads(''.join(list_decrypted))

def encrypt(data, client_id):
  '''Encrypts a data for a particular client

  Args:
    data: The data to encrypt
    client_id: The client which should receive the data

  Returns:
    An encrypted string representing 'data'
  '''
  client_info = getClientInfo(client_id)
  client_key = RSA.importKey(client_info['key'])

  messages = list(string_to_chunks(json.dumps(data), 256))
  messages_encrypted = [base64.b64encode(client_key.encrypt(m, 32)[0]) for m in messages]
  return json.dumps(messages_encrypted)

def getpublickey(data):
  '''Returns the public key associated with a given ID
  '''
  client_info = getClientInfo(data['id'])

  if not client_info:
    return {
      "success": False
    }

  return {
    "success": True,
    "key": client_info['key']
  }

def gethead(data):
  '''Returns current the head of the blockchain
  '''
  head = openConfigFile()['transactions']['head']
  if head:
    return {
      'success': True,
      'head': head
    }
  
  return {
    'success': False
  }

def getblock(data):
  '''Returns a block from the blockchain to the client

  Args:
    data: an object containing the id we need to look up
  '''
  transactions = openConfigFile()['transactions']
  transaction_id = data['id']

  if transactions.get(transaction_id):
    t = transactions[transaction_id]
    return {
      'success': True,
      'transaction': t
    }

  return {
    'success': False
  }

def test_new_block(transactions, block):
  '''Performs the needed tests to validate a block before it's added to the blockchain

  Args:
    transactions: The current state of the blockchain
    block: The block to test

  Returns:
    True if the new block is valid and can be added to the blockchain, otherwise False.
  '''
  return block["previous_block"] == transactions["head"] and block["counter"] == (transactions[transactions["head"]]["counter"] + 1)

def update_blockchain(transactions, block):
  '''Inserts a new block at the head of the block chain and points the "head"
    pointer to that new block

  Args:
    block: The block to insert at the head of the blockchain

  Returns:
    The SHA256 hash hex representation of the block which was added to the block chain
  '''
  new_block_hash = SHA256.new(json.dumps(block)).hexdigest()
  transactions["head"] = new_block_hash
  transactions[new_block_hash] = block

  return new_block_hash

def putblock(data):
  '''Tries to add a received block to the blockchain

  Args:
    data: A JSON object containing the proposed block

  Returns:
    An object indicating success and containing a hash pointer to the new block
      if insertion was successful, an object indicating failure otherwise.
  '''
  transactions = openConfigFile()['transactions']

  if test_new_block(transactions, data['block']):
    block_hash = update_blockchain(transactions, block)
    return {
      'success': True,
      'hash': block_hash
    }

  return {
    'success': False
  }

def recv(s, bank_key):
  '''Receives data over a socket and handles it appropriately depending on
    the data received

  Args:
    s: The socket to listen for data on
    bank_key: The banks private key

  Stays in an infinite loop receiving data and sending back a response
  '''
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
    elif data['type'] == 'getpublickey':
      response = getpublickey(data)
      response['type'] = 'getpublickey'
    elif data['type'] == 'gethead':
      response = gethead(data)
      response['type'] = 'gethead'
    elif data['type'] == 'getblock':
      response = getblock(data)
      response['type'] = 'getblock'
    elif data['type'] == 'putblock':
      response = putblock(data)
      response['type'] = 'putblock'
    else:
      response = getAllTransactions()

    encrypted_response = encrypt(response, client_id)
    s.sendto(encrypted_response, addr)

def openConfigFile():
  '''Opens the current config file for the banks

  Returns:
    A JSON object representing the current config file
  '''
  with open('config.json') as data_file:
    return json.load(data_file, strict=False)

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
  '''Processes command lines from stdin
  '''
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
