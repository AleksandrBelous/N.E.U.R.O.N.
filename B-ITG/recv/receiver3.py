import socket
from params import src, dst


def main():
    # creating the socket
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # binding the socket to the port 7456
    # notice that bind() take a tuple as argument
    sck.bind((src.ip, src.port))

    # now is time to say, I'm ready for connection OS, could you let me please?
    # the 1 specified how many connection it will queue up, until
    # start rejecting attempts of connections.
    sck.listen(1)

    print(f"[Receiver] I'm listening on {src.port} ...")

    # accepting the incoming connection
    client_sock, address = sck.accept()
    while True:
        # 1024 is a magic number used on every networking tutorial out there
        # so here I also make use of it. Also in this case means that the socket
        # will process up to 1024 bytes of the incoming message from the client
        msg = client_sock.recv(1024)
        if not msg:
            break
        # print(f"FROM: {address} MSG: {msg}")

    # goodbye socket
    client_sock.close()


if __name__ == "__main__":
    main()
