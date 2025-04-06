import utils
import random
CONNECTION_ADDR_A = ("cc5327.hackerlab.cl", 5312)
CONNECTION_ADDR_B = ("cc5327.hackerlab.cl", 5313)


if __name__ == "__main__":
    sock_input_A, sock_output_A = utils.create_socket(CONNECTION_ADDR_A)
    sock_input_B, sock_output_B = utils.create_socket(CONNECTION_ADDR_B)

    zero_last = False
    flip_random = True

    while True:
        try:
            # Read a message from standard input
            msg = input("send a message: ")
            # You need to use encode() method to send a string as bytes.
            print("[Client] \"{}\"".format(msg))
            resp_A = utils.send_message(sock_input_A, sock_output_A, msg)
            print("[Server A] \"{}\"".format(resp_A))

            if flip_random:
                bytes_A = utils.hex_to_bytes(resp_A)

                # We ignore the first 16 bytes as they are from the IV
                rand_index = random.randint(16, len(bytes_A) - 1)
                print("index:", rand_index)

                # XOR with 1,
                # this results in a flip of the least significant bit
                bytes_A[rand_index] ^= -1

                # We turn the modified bytes back into a hex
                resp_A = utils.bytes_to_hex(bytes_A)

            if zero_last:
                bytes_A = utils.hex_to_bytes(resp_A)
                bytes_A[-1] = 0x00
                resp_A = utils.bytes_to_hex(bytes_A)

            resp_B = utils.send_message(sock_input_B, sock_output_B, resp_A)
            print("[Server B] \"{}\"".format(resp_B))
            
            # Wait for a response and disconnect.
        except Exception as e:
            print(e)
            print("Closing...")
            input.close()
            break