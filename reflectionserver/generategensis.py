import json
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
rng = Random.new().read
import time

f = open('key.pem', 'r')
localKey = RSA.importKey(f.read(), passphrase="")
f.close()

verif_obj = {
    'input': [
    ],
    'output': [
        {
            'id': 'f0f0bf2a6dd1a5d2c16312b2b720fda0d0b3267b3204956db2482bb4202e721e',
            'amount': 1000
        }
    ]
}

sig = localKey.sign(json.dumps(verif_obj), rng)

print "signature", sig

genesis = {
    "previous_block": None,
    "comment": "Satoshi",
    "timestamp": int(time.time()),
    "counter": 0,
    "input": [
    ],
    "output": [
        {
            "id": "f0f0bf2a6dd1a5d2c16312b2b720fda0d0b3267b3204956db2482bb4202e721e",
            "amount": 1000,
            "signature": sig
        }
    ]
}

print "genesis", genesis
h = SHA256.new(json.dumps(genesis)).hexdigest()
print "hash", h
