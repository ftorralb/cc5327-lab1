from utils import (
    send_message,
    create_socket,
    split_blocks,
    hex_to_bytes,
    join_blocks,
    bytes_to_hex,
)
import copy

CONNECTION_ADDR_A = ("cc5327.hackerlab.cl", 5312)
CONNECTION_ADDR_B = ("cc5327.hackerlab.cl", 5313)


def decipher_byte(C, byte_index, P_i, sock_input, sock_output) -> None:
    """Deciphers the byte with index byte_index of the ciphertext in blocks C
    and stores it in the array P, that represents a block of the deciphered text.

    Args:
        C (list[bytearray]): Ciphertext separated in blocks of 16 bytes each
        byte_index (int): Index of the byte to decipher
        P_i (list[int]): A block of the plaintext P to store the deciphered byte
        sock_input (socket): Socket input to communicate with server B
        sock_output (socket): Socket output to communicate with server B
    """
    pad = 16 - byte_index
    for guess in range(256):
        if guess == C[-2][15]:
            continue
        C_mod = copy.deepcopy(C)

        # set all known bytes to produce pad-value padding
        for k in range(15, byte_index, -1):
            C_mod[-2][k] = P_i[k] ^ pad ^ C[-2][k]

        # guess the current byte
        C_mod[-2][byte_index] = guess

        msg = bytes_to_hex(join_blocks(C_mod))
        ans = send_message(sock_input, sock_output, msg)

        if "invalid padding" not in ans:
            P_i[byte_index] = guess ^ pad ^ C[-2][byte_index]
            print(f"Deciphered byte {byte_index}: {repr(chr(P_i[byte_index]))}")
            return

    print(
        "Couldn't find C' that decrypts to valid padding.\nUsing original byte instead."
    )
    P_i[byte_index] = pad ^ C[-2][byte_index] ^ C[-2][byte_index]
    print(f"Deciphered byte {byte_index}: {repr(chr(P_i[byte_index]))}")


def decipher_last_block(C, P_i, sock_input, sock_output) -> None:
    """Deciphers the last block of the ciphered text in blocks C and stores the
    result in the given plaintext_block.

    Args:
        C (list[bytearray]): Ciphertext separated in blocks of 16 bytes each 
        P_i (list[int]): A block of the plaintext P to store the deciphered block
        sock_input (socket): Socket input to communicate with server B
        sock_output (socket): Socket output to communicate with server B
    """
    for byte_index in range(15, -1, -1):
        decipher_byte(C, byte_index, P_i, sock_input, sock_output)

    deciphered_block = bytes(P_i).decode(errors="replace")
    print(f"Deciphered block: {repr(deciphered_block)}")


def decipher_encrypted_message(ciphertext: str) -> str:
    """Deciphers the given ciphertext.

    Args:
        ciphertext (str): Ciphertext in hexadecimal format.

    Returns:
        str: The deciphered text of the input.
    """
    sock_input, sock_output = create_socket(CONNECTION_ADDR_B)

    C = split_blocks(hex_to_bytes(ciphertext), 16)
    block_length = len(C) - 1  # subtract one because of IV
    P = [[0] * 16 for _ in range(block_length)]

    for i in range(block_length - 1, -1, -1):
        print(f'Deciphering block with index {i}...')
        decipher_last_block(C, P[i], sock_input, sock_output)
        C = C[:-1]

    return bytes([b for block in P for b in block]).decode(errors="replace")



if __name__ == "__main__":
    sock_input, sock_output = create_socket(CONNECTION_ADDR_A)
    while True:
        try:
            response = input("send a message: ")
            print('[Client] "{}"'.format(response))
            resp = send_message(sock_input, sock_output, response)
            print('[Server A] "{}"'.format(resp))

            # decipher last block from server A's response
            plaintext = decipher_encrypted_message(resp)
            print(f'Deciphered message: {plaintext}')
            print(f'Deciphered message with padding: {repr(plaintext)}')

        except Exception as e:
            print(e)
            print("closing...")
            break
