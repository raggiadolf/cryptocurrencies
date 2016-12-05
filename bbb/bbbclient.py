import socket
import sys
import json

host = sys.argv[1]
port = int(sys.argv[2])

my_id = 'asdf'

def send_and_receive(s, data):
    s.sendto(json.dumps(data), (host, port))
    return json.loads(s.recv(4096))

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
    print 'Failed to create socket'
    sys.exit()

while True: # Loop for input until user quits
    print "Input either 'authorize' for a payment authorization, or 'verify' for a payment verification"
    cmd = raw_input('>> ')

    if cmd.lower() == 'authorize': # Send a transaction
        print "Input the amount to transfer"
        amount = int(raw_input('>> '))
        print "Input the recipients ID"
        recip_id = raw_input('>> ')
        auth_obj = {
            'payer_id': my_id,
            'receiver_id': recip_id,
            'amount': amount
        }

        resp = send_and_receive(s, auth_obj) # The response from BBB

        if resp['success']:
            print "Payment authorized"
            print "Transaction:", resp['transaction_id']
        else:
            print "Payment not authorized"

    elif cmd.lower() == 'verify': # Verify a transaction
        print "Input the amount to verify"
        amount = int(raw_input('>> '))
        print "Input the payer ID"
        payer_id = raw_input('>> ')
        print "Input the transaction ID"
        trans_id = raw_input('>> ')
        verify_obj = {
            'payer_id': payer_id,
            'receiver_id': my_id,
            'amount': amount,
            'transaction_id': trans_id
        }

        resp = send_and_receive(s, verify_obj) # The response from BBB

        if resp['success']:
            print "Transaction successfully verified by BBB"
        else:
            print "Transaction not verified by BBB"

    elif cmd.lower() == 'q' or cmd.lower() == 'quit' or cmd.lower() == 'exit': # Quit
        print "Exiting..."
        sys.exit()
    else:
        print "Command not recognized"