import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_128_ecb_encrypt(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def aes_128_ecb_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def aes_128_cbc_decrypt(key, iv, ciphertext):
    block_size = 16
    num_blocks = len(ciphertext) // block_size

    plaintext = b''

    print("Decryption Steps:")
    # XOR the IV with the first block of ciphertext
    prev_block = iv
    for i in range(num_blocks):
        block_start = i * block_size
        block_end = block_start + block_size
        block = ciphertext[block_start:block_end]

        decrypted_block = aes_128_ecb_decrypt(key, block)
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))

        print(f"Step {i + 1} - Block {i + 1} decrypted: {decrypted_block.hex()}")
        print(f"Step {i + 1} - XOR result with IV/Previous block: {plaintext_block.hex()}")

        plaintext += plaintext_block
        prev_block = block

    return plaintext

def main():
    parser = argparse.ArgumentParser(description='AES-128-CBC Decryption')
    parser.add_argument('-c', '--ciphertext', required=True, help='The ciphertext in hexadecimal format')
    parser.add_argument('-k', '--key', required=True, help='The key in hexadecimal format')
    parser.add_argument('-iv', '--iv', required=True, help='The IV in hexadecimal format')

    args = parser.parse_args()

    ciphertext = bytes.fromhex(args.ciphertext)
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    decrypted_text = aes_128_cbc_decrypt(key, iv, ciphertext)
    print("\nDecrypted Text (Hex):", decrypted_text.hex())

if __name__ == '__main__':
    main()