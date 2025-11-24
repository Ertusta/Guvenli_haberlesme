from Crypto.Cipher import DES
import base64

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt_message(key, msg):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    return base64.b64encode(des.encrypt(pad(msg).encode())).decode()

def decrypt_message(key, enc_msg):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    return des.decrypt(base64.b64decode(enc_msg)).decode().strip()
