# Cryptocurrencies

## Big Brother Bank
Stored in the bbb dir. bigbrotherbank.py includes all the logic for the bank, start it up with the port you want to host from as a parameter, f.ex: 'python bigbrotherbank.py 59190'.

To interact with BBB you need to start up chatserver.py in the reflection dir, again with the port as a parameter (python chatserver.py 59191). Then you start two instances of chatclient.py (located in reflectionserver dir). These instances require the host+port of the BBB server and the chatserver as parameters (python chatclient.py 127.0.0.1 59191 127.0.0.1 59190)

Once you have two chatclients connected to the chatserver they can send encrypted messages between them simply using stdin. If you are connected to the bank as well, you need to start by connecting to the bank using /createclient. Then the bank will send the client an init message including the public key to use for the remainder of your interaction with the bank, as well as creating a client entry for your public key (generated or imported) in the bank's config file. You can then use /authorize to construct a transaction object to send to the bank for authorization.

### TODO List
- [x] Single authorization
- [x] Multiple authorization
- [ ] Verification
- [x] Encryption between clients & bank
- [x] Encrypted chat between clients
- [x] Allow users to create a unique client with the bank
- [ ] Allow users to create multiple clients with the bank
- [ ] Allow a user to request transactions he is involved in with the bank
- [x] Move the banks config to a blockchain style transaction system
- [ ] Create an audit method within the bank
- [ ] Create a client side audit which requests the blockchain from the bank and verifies it
- [x] Signatures between client and bank
- [x] Signatures between multiple clients
- [x] Don't allow clients to start transactions before creating a client
- [x] Make bank reject authorizations which include negative values