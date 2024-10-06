from main import encrypt_cbc_args
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random
from base64 import b64decode
from base64 import b64encode


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
    plaintext = unpad(plaintext, 16)
    print(plaintext)
    check = ";admin=true;"

    return check in str(plaintext)

def combination(text):
    key = random.randbytes(16)  # key size is 128 bits == 16 bytes
    iv = random.randbytes(16)  # iv size is 1 block = 128 bits = 8 bytes

    eString = submit(text, key, iv)

    # Gotta do shit here
    # 49 - 55 - 60 "<admin-true<"
    eString = bytearray(eString)
    eString[17] = ord("f") ^ ord(";") ^ eString[17]
    eString[23] = ord("f") ^ ord("=") ^ eString[23]
    eString[28] = ord("f") ^ ord(";") ^ eString[28]
    eString = bytes(eString)

    contains = verify(eString, key, iv)

    return contains

print(combination("dontcaredontfadminftruef"))
