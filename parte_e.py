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


def decipher_byte(C, i, P_n, sock_input, sock_output) -> None:
    """Deciphers the byte with index i of the ciphertext in blocks C
    and stores it in the array P_n, that represents the last block of
    the deciphered text.

    Args:
        C (list[bytearray]): Ciphertext separated in blocks of 16 bytes each
        i (int): Index of the byte to decipher
        P_n (list[int]): Array where deciphered bits are stored
        sock_input (socket): Socket input to communicate with server B
        sock_output (socket): Socket output to communicate with server B
    """
    print(f"Deciphering byte {i}...")
    pad = 16 - i
    for guess in range(256):
        if guess == C[-2][15]:
            continue
        C_mod = copy.deepcopy(C)

        # set all known bytes to produce pad-value padding
        for k in range(15, i, -1):
            C_mod[-2][k] = P_n[k] ^ C[-2][k] ^ pad

        # guess the current byte
        C_mod[-2][i] = guess

        msg = bytes_to_hex(join_blocks(C_mod))
        ans = send_message(sock_input, sock_output, msg)

        if "invalid padding" not in ans:
            P_n[i] = pad ^ C_mod[-2][i] ^ C[-2][i]
            print(f"Deciphered byte {i}: {repr(chr(P_n[i]))}")
            return


def decipher_last_block(ciphertext: str) -> str:
    """Deciphers the last block of the given ciphertext and returns it.

    Args:
        ciphertext (str): The ciphertext to be deciphered

    Returns:
        str: The deciphered last block of the given input
    """
    # create a connection with server B
    sock_input, sock_output = create_socket(CONNECTION_ADDR_B)

    # split ciphertext into 16-byte blocks
    C = split_blocks(hex_to_bytes(ciphertext), 16)

    # array to store the plaintext bytes of the last block
    P_n = [0] * 16

    # recover bytes from position 15 to 0
    for i in range(15, -1, -1):
        decipher_byte(C, i, P_n, sock_input, sock_output)
        print("-----------------------------")

    return bytes(P_n).decode(errors="replace")


if __name__ == "__main__":
    sock_input, sock_output = create_socket(CONNECTION_ADDR_A)
    while True:
        try:
            response = input("send a message: ")
            print('[Client] "{}"'.format(response))
            resp = send_message(sock_input, sock_output, response)
            print('[Server A] "{}"'.format(resp))

            # decipher last block from server A's response
            last_block = decipher_last_block(resp)
            print(f"Deciphered last block: {repr(last_block)}")

        except Exception as e:
            print(e)
            print("closing...")
            break
