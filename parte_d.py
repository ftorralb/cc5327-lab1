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


def decipher_last_character(ciphertext: str) -> str:
    """Deciphers the last character of the given ciphertext

    Args:
        ciphertext (str): Ciphertext to be deciphered.

    Returns:
        str: A single character, being the deciphered last byte of the input
    """
    # create a connection with server B
    sock_input, sock_output = create_socket(CONNECTION_ADDR_B)

    # first, split ciphertext into blocks
    C = split_blocks(hex_to_bytes(ciphertext), 16)

    # a value of the last byte of C'[n-1] that decrypts to a message
    # with a correct padding (of 1 one byte) should exist
    for guess in range(256):
        # we only care when the modified message is actually different
        # from the original ciphertext
        if guess == C[-2][15]:
            continue
        # we also need a copy of C to modify it
        C_prime = copy.deepcopy(C)

        # we modify the last byte of C'[n-1]
        C_prime[-2][15] = guess

        # create new message to send
        msg = bytes_to_hex(join_blocks(C_prime))
        ans = send_message(sock_input, sock_output, msg)
        print('[Server B] "{}"'.format(ans))

        if "invalid padding" not in ans:
            P_n_15 = 0x01 ^ C_prime[-2][15] ^ C[-2][15]
            return chr(P_n_15)


if __name__ == "__main__":
    sock_input, sock_output = create_socket(CONNECTION_ADDR_A)
    while True:
        try:
            response = input("send a message: ")
            print('[Client] "{}"'.format(response))
            resp = send_message(sock_input, sock_output, response)
            print('[Server A] "{}"'.format(resp))

            # to test the function
            last_character = decipher_last_character(resp)
            print(f"Deciphered last character: {repr(last_character)}")
        except Exception as e:
            print(e)
            print("Closing...")
            input.close()
            break
