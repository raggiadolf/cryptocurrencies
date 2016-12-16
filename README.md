# Cryptocurrencies

## How to test
The 'easiest' way to test the bbb protocol is to generate two private keys and have them both in .pem files in the reflectionserver dir, and then having each chat client use separate keys. Then you can /connect both clients to the bank, establishing a connection to the bank and having the bank generate clients in his config file. Then one of the clients can use /starttransaction and input the amounts+ids for the transaction. The other client then accepts signing the transaction using /yes (twice, because reasons). The first client then inputs the current head of the transaction (twice) and the counter for the block to be posted to bbb (twice). (twice in both cases, because we have two threads listening for input on stdin with no way of flushing it. In part because of bad structuring on our part, and in part because python.) The first client then sends the block to the bbb, which verifies the block, and of the block is valid, puts it on the block chain and returns the hashpointer to the block. This of course requires the genesis block to be set up such that the client paying in this transaction actually has some money transferred to him in the genesis block.

## Big Brother Bank
Stored in the bbb dir. bigbrotherbank.py includes all the logic for the bank, start it up with the port you want to host from as a parameter, f.ex: 'python bigbrotherbank.py 59190'.

To interact with BBB you need to start up chatserver.py in the reflection dir, again with the port as a parameter (python chatserver.py 59191). Then you start two instances of chatclient.py (located in reflectionserver dir). These instances require the host+port of the BBB server and the chatserver as parameters (python chatclient.py 127.0.0.1 59191 127.0.0.1 59190)

Once you have two chatclients connected to the chatserver they can send encrypted messages between them by simply writing to stdin. If you are connected to the bank as well, you need to start by connecting to the bank using /connect. Then the bank will send the client an init message including the public key to use for the remainder of your interaction with the bank, as well as creating a client entry for your public key (generated or imported) in the bank's config file.

## Reflection chat server
Stored in the reflectionserver dir. Start chatserver.py up first, giving it the port to listen on as an argument, f.ex: 'python chatserver.py 59191'.

Then start two chat clients using chatclient.py, giving then the host+port of the BBB server and the chatserver as parameters (python chatclient.py 127.0.0.1 59191 127.0.0.1 59190).

The reflection server simply relays messages between two connected clients.

## Hash party
The nonce finding app we made in the first? week is in hashparty.py in the cwd. The multiple implementation which spawns many workers and uses the first ones answer is in the multihash dir.

## Shamir'r Secret Sharing Scheme
Stored in the secretsharing dir. There are two possible ways of using the scheme, to generate or recover shares.

To generate shares for a secret, use the command: 'python secretsharing.py generate data.txt'
The shares for the secret will be printed to the file data.txt and each share is on the form:
j-prime|k|n|hexpairsstring an example share is:
1-251|5|15|dbe9a219254ca9236beac3b7acbfbfc5d514aade5e29

To recover the original secretm use the command: 'python secretsharing.py recover secret.txt input.txt'

input.txt should have shares that will be used to recover the secret on the form j-prime|k|n|hexpairsstring. The shares are in the same format as the shares in the data.txt file so they can be copy/paste-ed between files.

The original secret is saved to the secret.txt file. If there are not enough shares to generate the secret, an error message is saved to the secret.txt file

Of course other filenames can be used than data.txt, input.txt and secret.txt

In the secretsharing dir there are example data.txt and input.txt wich can be used to generate a secret to the secret.txt file.
