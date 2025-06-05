# receiver.py
import socket
from socketserver import TCPServer, StreamRequestHandler
from params import src


class ReusableTCPServer(TCPServer):
    allow_reuse_address = True  # Разрешаем повторное использование порта
    address_family = socket.AF_INET


class ReceiverHandler(StreamRequestHandler):
    def handle(self):
        print(f"[Receiver] Connection from {self.client_address}")
        try:
            while True:
                data = self.rfile.read(1024)
                if not data:
                    break
                # print(f"Received: {data.decode('utf-8')}")
        except (ConnectionResetError, BrokenPipeError):
            print("[Receiver] Client disconnected abruptly")


def main():
    server = ReusableTCPServer((src.ip, src.port), ReceiverHandler)
    try:
        print(f"[Receiver] Listening on {src.port}...")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Receiver] Shutting down server...")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
