from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import hashlib


password = b'master'
data = b'ovo zelim nazad'
salt = get_random_bytes(32)
keys = PBKDF2(password, salt, 32, count=10000, hmac_hash_module=SHA256)
key1 = keys[:16]
key2 = keys[16:]

print(key1)
print(key2)

iv = get_random_bytes(16);
print(iv)

cipher = AES.new(key1, AES.MODE_GCM)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data)

cipher = AES.new(key1, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)

mac = HMAC.new(key2, digestmod=SHA256)
