
import base64
n = 0x00bbcc67e6218f02a9b5e358cf36cf1ef3ea76f32bb3645f1de2212beba2f6fd181cdc855ba681c301bfeac7dbbf1c783a578f0568d1869a310c2e40fc9fab5579
e = 3

signature = open('sig.b64').read()
signature = int.from_bytes(base64.b64decode(signature), byteorder="big")
pkcs = pow(signature, e, n)
print(f'{pkcs:0128x}')
import hashlib
m = hashlib.sha256()
m.update(b"EECS 388 rul3z!")
print(m.hexdigest())