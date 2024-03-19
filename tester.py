# Step 1
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import sys

# Step 2
plaintext = b'David is the best'
paddedHelloWorld = pad(plaintext, 8)

# Step 3
myKey = b'angryroa'
myIV = b'\x20' * 8
myCipher = DES.new(myKey, DES.MODE_CBC, myIV)
ciphertext = myCipher.encrypt(paddedHelloWorld)

print(ciphertext.hex() + " " + myKey.hex() + " " + myIV.hex())