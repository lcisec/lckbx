#!/usr/bin/env python3

# You will need to `pip install argon2-cffi` first.

import base64
import hashlib

from argon2 import PasswordHasher

# Derive basekey
salt = hashlib.blake2b('user'.encode(), digest_size=32)
ph = PasswordHasher()
eh = ph.hash("This is just right.".encode(), salt=salt.digest())
raw = base64.b64decode('{0}='.format(eh.split('$')[5]))
bk = 'bk_{0}'.format(base64.b32encode(raw).decode()).strip('=')

print('Base Key: {0}'.format(bk))


# Derive AuthKey
ah = hashlib.blake2b(key=raw, digest_size=32)
ah.update('This key will be used for authentication.'.encode())
ak = 'ak_{0}'.format(base64.b32encode(ah.digest()).decode()).strip('=')

print('AuthKey: {0}'.format(ak))


# Derive CryptKey
ch = hashlib.blake2b(
	'This key will be used for encryption.'.encode(),
	key=raw,
	digest_size=32)
ck = 'ck_{0}'.format(base64.b32encode(ch.digest()).decode()).strip('=')

print('CryptKey: {0}'.format(ck))


# Derive Salted CryptKey
sch = hashlib.blake2b(
	b'\x1f\x22\xb6\xd2\x13\xb7\xc8\x06\x08\x29\x7d\x6b\xc4\x7a\x8f\x06\x1e\x95\xd5\xe6\x59\x12\x36\x40\x28\x71\xb3\xeb\x8d\x17\x6d\x4f',
	key=raw,
	digest_size=32)
sck = 'ck_{0}'.format(base64.b32encode(sch.digest()).decode()).strip('=')

print('Salted CryptKey: {0}'.format(sck))


# Derive AuthToken
ath = hashlib.blake2b(
	'ut_D4RLNUQTW7EAMCBJPVV4I6UPAYPJLVPGLEJDMQBIOGZ6XDIXNVHQ'.encode(),
	key=raw,
	digest_size=32)
at = 'at_{0}'.format(base64.b32encode(ath.digest()).decode()).strip('=')

print('AuthToken: {0}'.format(at))