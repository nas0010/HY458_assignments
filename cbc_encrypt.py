import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_ecb_encrypt(key, block):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

def aes_cbc_encrypt(key, iv, plaintext):
    block_size = 16  # AES block size is 128 bits (16 bytes)

    # Pad the plaintext if needed
    if len(plaintext) % block_size != 0:
        padding_length = block_size - len(plaintext) % block_size
        plaintext += bytes([padding_length] * padding_length)

    ciphertext = b""
    previous_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]

        # XOR the block with the previous ciphertext block or IV
        xor_block = bytes([a ^ b for a, b in zip(block, previous_block)])
        print(f"XOR Block: {xor_block.hex()}")

        # Encrypt the XORed block using AES-128-ECB
        encrypted_block = aes_ecb_encrypt(key, xor_block)
        print(f"Encrypted Block: {encrypted_block.hex()}")

        # Append the encrypted block to the ciphertext
        ciphertext += encrypted_block

        # Update the previous block with the current encrypted block
        previous_block = encrypted_block

    return ciphertext

def main():
    parser = argparse.ArgumentParser(description="AES-128-CBC Encryption")
    parser.add_argument("-p", "--plaintext", required=True, help="The plaintext, encoded in hexadecimal format")
    parser.add_argument("-k", "--key", required=True, help="The key, encoded in hexadecimal format")
    parser.add_argument("-iv", "--iv", required=True, help="The IV, encoded in hexadecimal format")
    args = parser.parse_args()

    plaintext = bytes.fromhex(args.plaintext)
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    print(f"Plaintext: {args.plaintext}")
    print(f"Key: {args.key}")
    print(f"IV: {args.iv}")

    ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    print("\nFinal Ciphertext:", ciphertext.hex())

if __name__ == "__main__":
    main()