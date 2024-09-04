import argparse
from cbc_decrypt import aes_128_ecb_decrypt

def aes_128_cbc_decrypt_block(key, iv, ciphertext, block_index):
    block_size = 16
    num_blocks = len(ciphertext) // block_size

    if block_index < 1 or block_index > num_blocks:
        raise ValueError("Invalid block index")

    # Identify the block to decrypt
    block_start = (block_index - 1) * block_size
    block_end = block_start + block_size
    block = ciphertext[block_start:block_end]

    # Decrypt the identified block using AES-128-ECB
    decrypted_block = aes_128_ecb_decrypt(key, block)

    # If it's the first block, XOR with the IV
    if block_index == 1:
        decrypted_block = bytes(x ^ y for x, y in zip(decrypted_block, iv))
    else:
        # XOR with the previous ciphertext block
        previous_block_start = (block_index - 2) * block_size
        previous_block_end = previous_block_start + block_size
        previous_block = ciphertext[previous_block_start:previous_block_end]
        decrypted_block = bytes(x ^ y for x, y in zip(decrypted_block, previous_block))

    return decrypted_block

def main():
    parser = argparse.ArgumentParser(description="Demonstration of CBC Random Access Property")
    parser.add_argument("-c", "--ciphertext", required=True, help="The ciphertext in hexadecimal format")
    parser.add_argument("-k", "--key", required=True, help="The key in hexadecimal format")
    parser.add_argument("-iv", "--iv", required=True, help="The IV in hexadecimal format")
    parser.add_argument("-i", "--block-index", type=int, required=True, help="The index of the block to decrypt")
    args = parser.parse_args()

    ciphertext = bytes.fromhex(args.ciphertext)
    key = bytes.fromhex(args.key)
    iv = bytes.fromhex(args.iv)

    block_index_to_decrypt = args.block_index
    decrypted_block = aes_128_cbc_decrypt_block(key, iv, ciphertext, block_index_to_decrypt)

    # Print the decrypted block in hexadecimal format
    print(f"Decrypted Block {block_index_to_decrypt}:", decrypted_block.hex())

if __name__ == "__main__":
    main()