from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def pad(message):
    n = AES.block_size - len(message) % AES.block_size
    if n == 0:
        n = AES.block_size
    return message + bytes([n]*n)

def unpad(message):
    print(message)
    n = message[-1]
    if n < 1 or n > AES.block_size or message[-n:] != bytes([n]*n):
        raise Exception('invalid_padding')
    return message[:-n]

def encrypt(message, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(message))

def decrypt(ciphertext, key):
    if len(ciphertext) % AES.block_size:
        raise Exception('invalid_length')
    if len(ciphertext) < 2 * AES.block_size:
        raise Exception('invalid_iv')
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size:]))

def hmac(message, mac_key):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(message)
    return h.digest()

def verify(message, mac, mac_key):
    if mac != hmac(message, mac_key):
        raise Exception('invalid_mac')

def macThenEncrypt(message, key, mac_key):
    return encrypt(message + hmac(message, mac_key), key)

def decryptThenVerify(ciphertext, key, mac_key):
    plaintext = decrypt(ciphertext, key)
    message, mac = plaintext[:-SHA256.digest_size], plaintext[-SHA256.digest_size:]
    print(message)
    verify(message, mac, mac_key)
    return message

""" @app.route('/verify', methods=['POST'])
def dec_oracle_route():
    ciphertext = bytes.fromhex(request.form['message'])
    try:
        decryptThenVerify(ciphertext, KEY, MAC_KEY)
    except(e):
        return {'status': e}
    return {'status': 'valid'} """

def mains():
    k = bytes.fromhex("12345443344334344334433223456787")
    mackey = bytes.fromhex("1234543223456787")
    message = bytes.fromhex("4325567837")
    c = macThenEncrypt(message, k, mackey)
    print(c.hex())
    d = decryptThenVerify(c, k, mackey)
    print(d == message)
