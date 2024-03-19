# Step 1
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import sys

# Step 2
helloWorld = b'Hello World'
paddedHelloWorld = pad(helloWorld, 8)

# Step 3
myKey = b'poaisfun'
myIV = b'\x00' * 8
myCipher = DES.new(myKey, DES.MODE_CBC, myIV)
helloCiphertext = myCipher.encrypt(paddedHelloWorld)

# Step 4
myDecryptor = DES.new(myKey, DES.MODE_CBC, myIV)
helloDecryptedWithPadding = myDecryptor.decrypt(helloCiphertext)
helloUnpadded = unpad(helloDecryptedWithPadding, 8)

# Step 5
def xor(x, y, z):
    xorResult = x[0] ^ y[0] ^ z[0]
    resultAsBytes = bytes([xorResult])
    return resultAsBytes

# Step 6
def oracle(ciphertext, key, iv):
    try:
        decryptor = DES.new(key, DES.MODE_CBC, iv)
        decryptedPaddedText = decryptor.decrypt(ciphertext)
        unpaddedDecryptedText = unpad(decryptedPaddedText, 8)
        return True
    except ValueError:
        return False

# Step 7
c = b'\x00\x00\x00\x00\x00\x00\x00\x00\xd3\x63\x42\xb3\x92\x0b\xe6\x56'

# Step 8
for byte in range(1, 256):
    cByteArray = bytearray(c)
    cByteArray[7] = byte
    cIncremented = bytes(cByteArray)
    if (oracle(cIncremented, myKey, myIV)):
        break

# Step 9 + Step 10
def findByte(index, key, iv, cipherBlock, prevBlockVal, decryptedBytes, decryptedBytesPrevBlockVals):
    correctBtye = b'\x00'
    expectedPadding = (8 - index).to_bytes(1, byteorder='big')
    for byte in range(1, 256):
        # Start with a zeroed out X_j
        X_j = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00')
        # Add appropriate values for previously decryped indexes
        i = 1
        for decByte, decByteVal in zip(decryptedBytes, decryptedBytesPrevBlockVals):
            expectedByte = xor(expectedPadding, decByteVal, decByte)
            X_j[-i] = int.from_bytes(expectedByte, byteorder="big")
            i += 1
        X_j[index] = byte
        X_j = bytes(X_j)
        X_jWithCipher = X_j + cipherBlock
        if (oracle(X_jWithCipher, key, iv)):
            correctBtye = byte.to_bytes(1, byteorder='big')
            break
    decrytedIthByte = xor(expectedPadding, prevBlockVal, correctBtye)
    return decrytedIthByte

# Step 11
def revealBlock(block, prevBlock, key, iv):
    prevBlockArray = bytearray(prevBlock)
    decryptedBytes = []
    decryptedBytesPrevVals = []
    for i in range(7, -1, -1):
        decByte = findByte(i, key, iv, block, bytes([prevBlockArray[i]]), decryptedBytes, decryptedBytesPrevVals)
        decryptedBytes.append(decByte)
        decryptedBytesPrevVals.append(bytes([prevBlockArray[i]]))
    return decryptedBytes


# Step 12
def revealCiphertext(ciphertext, key, iv):
    plaintext = []
    cipherBlocks = [ciphertext[i : i + 8] for i in range(0, len(ciphertext), 8)]
    prevBlock = iv
    for block in cipherBlocks:
        decryptedText = revealBlock(block, prevBlock, key, iv)
        for i in range(7, -1, -1):
            plaintext.append(decryptedText[i])
        prevBlock = block
    # Remove the padding bytes
    numOfPaddingBytes = int.from_bytes(plaintext[-1], 'big')
    plaintext = plaintext[:-numOfPaddingBytes]
    plaintextString = b''.join(plaintext).decode()
    return plaintextString


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Invalid num of args")
        sys.exit()
    ciphertext = bytes.fromhex(sys.argv[1])
    key = bytes.fromhex(sys.argv[2])
    iv = bytes.fromhex(sys.argv[3])
    key = b'poaisfun'
    iv = b'\x00' * 8
    ciphertext = "Hello World"
    padded_message = pad_message(message)
    cipher_text = encrypt_padded_msg(padded_message, key, iv)
    print(revealCiphertext(ciphertext, key, iv))