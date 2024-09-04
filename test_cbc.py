import argparse
from cbc_encrypt import aes_cbc_encrypt
from cbc_decrypt import aes_128_cbc_decrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def verify_encryption_decryption(plaintext, key, iv):
    print("Original Plaintext:", plaintext.hex())
    print("Key:", key.hex())
    print("IV:", iv.hex())

    # Encrypt using the provided encryption function
    my_ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    print("\nMy Implementation - Ciphertext:", my_ciphertext.hex())

    # Decrypt using the provided decryption function
    my_decrypted_text = aes_128_cbc_decrypt(key, iv, my_ciphertext)
    print("My Implementation - Decrypted Text (Hex):", my_decrypted_text.hex())

    # Encrypt using Cryptography library
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cryptography_ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    print("\nCryptography Implementation - Ciphertext:", cryptography_ciphertext.hex())

    # Decrypt using Cryptography library
    decryptor = cipher.decryptor()
    cryptography_decrypted_text = decryptor.update(cryptography_ciphertext) + decryptor.finalize()
    print("Cryptography Implementation - Decrypted Text (Hex):", cryptography_decrypted_text.hex())

    # Verify that the ciphertexts match
    assert my_ciphertext == cryptography_ciphertext, "Ciphertexts do not match"

    # Verify that the decrypted texts match
    assert my_decrypted_text == cryptography_decrypted_text, "Decrypted texts do not match"

    print("\nEncryption and Decryption verification successful.")

def main():
    parser = argparse.ArgumentParser(description="AES-128-CBC Encryption and Decryption Verification")
    parser.add_argument("-p", "--plaintext", required=True, help="The plaintext, encoded in hexadecimal format")
    parser.add_argument("-k", "--key", required=True, help="The key, encoded in hexadecimal format")
    parser.add_argument("-iv", "--iv", required=True, help="The IV, encoded in hexadecimal format")
    args = parser.parse_args()

    plaintext = bytes.fromhex(args.plaintext)
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    verify_encryption_decryption(plaintext, key, iv)

if __name__ == "__main__":
    main()