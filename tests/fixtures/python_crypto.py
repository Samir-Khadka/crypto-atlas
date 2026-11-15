"""True positives: every Python rule fires on this file."""
import hashlib
import random
import ssl

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# rule 1: RSA key generation (2048 -> weakness 4)
key_2048 = rsa.generate_private_key(public_exponent=65537,
                                    key_size=2048)
# rule 1: RSA key generation, too small (1024 -> weakness 5)
key_1024 = RSA.generate(bits=1024)
# rule 2: ECC key generation (P-256 -> weakness 4)
ec_key = ec.generate_private_key(ec.SECP256R1())
# rule 3: weak hash
digest = hashlib.md5(b"hello").hexdigest()
digest2 = hashlib.sha1(b"hello").hexdigest()
# rule 4: weak cipher (ECB)
cipher = AES.new(b"0123456789abcdef", AES.MODE_ECB)
# rule 5: weak randomness for a secret
token = random.randbytes(32)
# rule 6: hardcoded key
key = AES.new(b"this-is-a-hardcoded-key-1234567890", AES.MODE_CBC,
              b"0123456789abcdef")
# rule 7: TLS verification disabled
ctx = ssl._create_unverified_context()
ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
