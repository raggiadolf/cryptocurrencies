# Blockchain mining

To generate a new valid genesis block (f.ex. if you want to change the difficulty), run genesis.py with the desired difficulty level as a parameter. It will then output the hash of the new genesis block, which you can copy into mining.py along with the new block as a new starting point for the blockchain.

mining.py is then simply started with the desired number of miners as a parameter.

A really simple implementation of a mining system. The main thread simply spawns a number of workers(threads), and once a single worker returns a valid block to add to the blockchain, the main thread stops all other workers, updates the chain, and then restarts the workers with the new blockchain head.

The simple protocol will not absolutely not scale without being re-written. It can however handle really low difficulties, since the main thread is the ultimate authority on what gets added to the blockchain, thus avoiding any conflicts between miners.