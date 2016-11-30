import gnupg
from pprint import pprint

gpg = gnupg.GPG(gnupghome='/tmp/raggiadolf/gpghome')
key_data = open('RUkey.asc').read()
import_result = gpg.import_keys(key_data)
pprint(import_result)

with open('security.png', 'rb') as f:
	status = gpg.encrypt_file(
		f, recipients=['jonathan@poritz.net'],
		output='supersecretpic.gpg',
		always_trust=True)

print 'ok: ', status.ok
print 'status: ', status.status
print 'stderr: ', status.stderr
