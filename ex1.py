import sys
from binascii import hexlify
# part 1
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad


def pad_message(message):
    block_size = 8  # DES block size is 8 bytes
    padding_bytes = block_size - (len(message) % block_size)
    padded_message = message.ljust(len(message) + padding_bytes, chr(padding_bytes))
    return padded_message.encode('utf-8')


def encrypt_padded_msg(padded_message, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext


def decrypt_unpad_cipher(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    unpadded_text = unpad(decrypted_text, DES.block_size)
    return unpadded_text.decode('utf-8')

# part 5
def xor(a: int, b: int, c: int) -> bytes:
    result = bytes([a ^ b ^ c])
    return result

# part 6
def oracle(ciphertext: bytes, key: bytes, iv: bytes) -> bool:
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return True
    except ValueError:
        return False


def part8(key: bytes, iv: bytes, c, index=7):
    d = c.copy()
    for i in range(256):
        d[index] = i
        modified_d = bytes(d)
        if oracle(modified_d, key, iv):
            return hex(i)


def part9(p=b'0x01', byte_prev_block=b'\x7b', part8=b'\x7f'):
    return xor(int(p, 16), int(byte_prev_block, 16), int(part8, 16))


def part10(p=b'0x02', byte_prev_block=b'0x7b', part8=b'0x05'):
    return xor(int(p, 16), int(byte_prev_block, 16), part8)


def part11(key: bytes, iv: bytes, c,next_block):
    next_block_cipher = bytearray(next_block)
    c = bytearray(c)
    # blue
    p = '0x01'
    result_of_decryption = c.copy()
    new_block = bytearray([0] * 8)

    for i in range(7, -1, -1):
        # green
        i_place = hex(next_block_cipher[i])
        #new red
        result8 = part8(key, iv,new_block + c, i)
        # puprple
        result9 = part9(p, i_place, result8)
        # b'\x05' to 0x05
        result9 = int.from_bytes(result9, byteorder='big')
        p = hex(int(p, 16) + 1)
        result_of_decryption[i] = result9
        new_block[i] = result9
        for j in range(8,i,-1):
            # red
            j_place = hex(next_block_cipher[j-1])
            result10 = part10(p, j_place, result_of_decryption[j-1])
            result10 = int.from_bytes(result10, byteorder='big')
            new_block[j-1] = result10
    return result_of_decryption

def part12(key: bytes, iv: bytes, encrypted_text):
    plaintext = []
    cipherBlocks = [encrypted_text[i: i + 8] for i in range(0, len(encrypted_text), 8)]
    prevBlock = iv
    for block in cipherBlocks:
        decryptedText = part11(key,iv,block,prevBlock)
        plaintext= bytearray(plaintext) + decryptedText
        prevBlock = block
    plaintest_string = unpad(plaintext,8)
    return bytes(plaintest_string).decode('utf-8')




if __name__ == '__main__':
    # part 2
    message = "Hello World"
    padded_message = pad_message(message)
    # part 3
    key = b'poaisfun'
    iv = b'\x00' * 8
    cipher_text = encrypt_padded_msg(padded_message, key, iv)
    # part 4
    decrypted_text = decrypt_unpad_cipher(cipher_text, key, iv)
    # print(decrypted_text)

    # part 7
    hex_cipher_text = hexlify(cipher_text)
    block_size = 16
    block2_start = block_size
    block2_end = 2 * block_size
    ciphertext_block2 = hex_cipher_text[block2_start:block2_end]
    ciphertext_block1 = hex_cipher_text[0:block2_start]
    zeros_block = 8 * b'00'
    c = zeros_block + ciphertext_block2
    #print(c)

    if len(sys.argv) != 4:
        print("Invalid num of args")
        exit(1)
    encrypted_text = bytes.fromhex(sys.argv[1])
    #key = sys.argv[2].encode('utf-8')
    key = bytes.fromhex(key)
    iv = bytes.fromhex(sys.argv[3])
    print(part12(key, iv, encrypted_text))
