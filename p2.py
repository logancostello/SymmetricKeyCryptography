from main import encrypt_cbc_args
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random


key = random.randbytes(16)  # key size is 128 bits == 16 bytes
iv = random.randbytes(16)  # iv size is 1 block = 128 bits = 8 bytes

def submit(userString, key, iv):
    # URL encode illegal character
    formattedStr = userString.replace("=", "%3D").replace(";", "%3B")
    paddedStr = "userid=456; userdata=" + formattedStr + ";session-id=31337"

    eString = encrypt_cbc_args(paddedStr, key, iv)

    return eString


def verify(cipherText, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(cipherText)
    plaintext = unpad(plaintext, 16).decode()
    check = ";admin=true;"

    return check in plaintext

def combination(text):
    key = random.randbytes(16)  # key size is 128 bits == 16 bytes
    iv = random.randbytes(16)  # iv size is 1 block = 128 bits = 8 bytes

    eString = submit(text, key, iv)

    # Gotta do shit here

    contains = verify(eString, key, iv)

    return contains
