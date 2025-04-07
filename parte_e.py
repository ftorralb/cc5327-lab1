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


def decipher_last_block(ciphertext: str):
    # create a connection with server B
    sock_input, sock_output = create_socket(CONNECTION_ADDR_B)

    # split ciphertext into 16-byte blocks
    C = split_blocks(hex_to_bytes(ciphertext), 16)

    # array to store the plaintext bytes of the last block
    P_n = [0] * 16

    # first, recover the last byte (pad = 0x01)
    print("Deciphering byte 15...")
    found = False
    for guess in range(256):
        if guess == C[-2][15]:
            continue
        C_mod = copy.deepcopy(C)
        C_mod[-2][15] = guess

        msg = bytes_to_hex(join_blocks(C_mod))
        ans = send_message(sock_input, sock_output, msg)

        if "invalid padding" not in ans:
            P_n[15] = guess ^ 0x01 ^ C[-2][15]
            print(f"Deciphered byte 15: {repr(chr(P_n[15]))}")
            found = True
            break

    if not found:
        P_n[15] = 0x01 ^ C[-2][15] ^ C[-2][15]
        print(
            "Couldn't find C' that decrypts to valid padding.\nUsing original byte instead."
        )
        print(f"Deciphered byte 15: {repr(chr(P_n[15]))}")

    print("-----------------------------")

    # recover bytes from position 14 to 0
    for i in range(14, -1, -1):
        pad = 16 - i
        print(f"Deciphering byte {i}...")

        found = False
        for guess in range(256):
            if guess == C[-2][15]:
                continue
            C_mod = copy.deepcopy(C)

            # set all known bytes to produce pad-value padding
            for k in range(15, i, -1):
                C_mod[-2][k] = P_n[k] ^ pad ^ C[-2][k]

            # guess the current byte
            C_mod[-2][i] = guess
            msg = bytes_to_hex(join_blocks(C_mod))
            ans = send_message(sock_input, sock_output, msg)

            if "invalid padding" not in ans:
                P_n[i] = guess ^ pad ^ C[-2][i]
                print(f"Deciphered byte {i}: {repr(chr(P_n[i]))}")
                found = True
                break

        if not found:
            P_n[i] = pad ^ C[-2][i] ^ C[-2][i]
            print(
                "Couldn't find C' that decrypts to valid padding.\nUsing original byte instead."
            )
            print(f"Deciphered byte {i}: {repr(chr(P_n[i]))}")

        print("-----------------------------")

    return bytes(P_n).decode(errors="replace")


if __name__ == "__main__":
    sock_input, sock_output = create_socket(CONNECTION_ADDR_A)
    while True:
        try:
            response = input("send a message: ")
            print('[client] "{}"'.format(response))
            resp = send_message(sock_input, sock_output, response)
            print('[server A] "{}"'.format(resp))

            # decipher last block from server A's response
            last_block = decipher_last_block(resp)
            print(f"Deciphered last block: {repr(last_block)}")

        except Exception as e:
            print(e)
            print("closing...")
            break
