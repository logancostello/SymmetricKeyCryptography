import random
from Crypto.Cipher import AES

# Takes a file, and returns the encrypted version using ECB block cipher
def encrypt_ecb(file_name):
    image_file = open(f"test_images/{file_name}", "rb")
    encrypted_file = open(f"test_images/ecb_encrypted_{file_name}", "wb")
    header = image_file.read(54) # 54 bytes is header size
    encrypted_file.write(header) # the header does not get encrypted

    key = random.randbytes(16) # key size is 128 bits == 16 bytes

    # Read and encrypt blocks until there is no more data left
    while True:
        data = image_file.read(16) # 1 block == 128 bits == 16 bytes

        if not data:
            break # No more data to read

        # Need to pack the block if it is not 16 bytes
        if len(data) < 16:
            data = pad(data)

        # Encrypt the block
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(data)

        # Write to encrypted file
        encrypted_file.write(encrypted_data)

    image_file.close()
    encrypted_file.close()

# Takes a file, and returns the encrypted version using CBC block cipher
def encrypt_cbc(file_name):
    image_file = open(f"test_images/{file_name}", "rb")
    encrypted_file = open(f"test_images/cbc_encrypted_{file_name}", "wb")
    header = image_file.read(54)  # 54 bytes is header size
    encrypted_file.write(header)  # the header does not get encrypted

    key = random.randbytes(16)  # key size is 128 bits == 16 bytes
    IV = random.randbytes(16)  # IV size is 1 block = 128 bits = 8 bytes

    # Read and encrypt blocks until there is no more data left
    while True:
        data = image_file.read(16)  # 1 block == 128 bits == 16 bytes

        if not data:
            break  # No more data to read

        # Need to pack the block if it is not 16 bytes
        if len(data) < 16:
            data = pad(data)

        # XOR data with the previous block
        data = (int.from_bytes(data, byteorder="big") ^ int.from_bytes(IV, byteorder="big")).to_bytes(16, byteorder="big")

        # Encrypt the block
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(data)

        # Write to encrypted file
        encrypted_file.write(encrypted_data)

        # Set IV to this block so the next one can use it
        IV = encrypted_data

    image_file.close()
    encrypted_file.close()


# Returns padded version of input_data, following PKCS#7 padding
def pad(input_data):
    pad_value = 16 - len(input_data) # how many bytes need to be filled, and also what to fill them with

    pad_mask = 0
    for _ in range(pad_value):
        pad_mask |= pad_value
        pad_mask <<= 8
    result = pad_mask & int.from_bytes(input_data, byteorder="big")
    return result.to_bytes(16, byteorder="big")

# Simpler padding for new encrypt func
def pad2(numPadding):
    padding = bytes([numPadding] * numPadding)
    return padding

# CB that takes IV and key as input
def encrypt_cbc_args(text, key, iv):
    length = len(text)
        
    # Read and encrypt blocks until there is no more data left
    byteIndex = 0
    text = text.encode()
    encryptedString = b""
    while byteIndex < length:
        print(byteIndex, text[byteIndex: byteIndex + 16])

        data = bytes(text[byteIndex: byteIndex + 16])
        # Need to pack the block if it is not 16 bytes
        if len(data) < 16:
            data += pad2(16 - len(data))

        # XOR data with the previous block
        data = (int.from_bytes(data, byteorder="big") ^ int.from_bytes(iv, byteorder="big")).to_bytes(16, byteorder="big")

        # Encrypt the block
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(data)

        # Set IV to this block so the next one can use it
        iv = encrypted_data
        encryptedString += encrypted_data

        byteIndex += 16
    return encryptedString


if __name__ == '__main__':
    encrypt_cbc("mustang.bmp")
