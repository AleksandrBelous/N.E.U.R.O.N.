import socket
from socketserver import TCPServer, UDPServer, ThreadingMixIn, BaseRequestHandler
from rich import print
from params import src

color_receiver = f"[magenta][Receiver][/magenta]"
color_tcp = f"[blue][TCP][/blue]"
color_udp = f"[orange3][UDP][/orange3]"
color_error = f"[red]Error[/red]"


class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    address_family = socket.AF_INET

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class ThreadedUDPServer(ThreadingMixIn, UDPServer):
    allow_reuse_address = True
    address_family = socket.AF_INET

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class TCPHandler(BaseRequestHandler):
    def handle(self):
        print(f"{color_receiver} {color_tcp} Connection from {self.client_address}")
        while True:
            try:
                data = self.request.recv(1024)
                if not data:
                    break
                # print(f"{color_receiver} {color_tcp} Received: {data.decode()[:50]}...")
            except (ConnectionResetError, Exception) as e:
                print(f"{color_receiver} {color_tcp} Client disconnected! {color_error}: {e}")
                break


class UDPHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request[0], self.request[1]
        print(f"{color_receiver} {color_udp} Connection from {self.client_address}")  #: {data.decode()[:50]}...")


def start_server(server_class, handler_class, port):
    server = server_class((src.ip, port), handler_class)
    try:
        print(f"{color_receiver} Starting {handler_class.__name__} on port {port}")
        server.serve_forever()
    except OSError as e:
        print(f"{color_receiver} Failed to start server on port {port}. {color_error}: {e}")
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
        print(f"{color_receiver} Сервер на порту {port} завершил работу.")


if __name__ == "__main__":
    import threading

    # Запуск TCP и UDP серверов в отдельных потоках
    tcp_thread = threading.Thread(
            target=start_server,
            args=(ThreadedTCPServer, TCPHandler, src.port),
            daemon=True,
            )

    udp_thread = threading.Thread(
            target=start_server,
            args=(ThreadedUDPServer, UDPHandler, src.port),
            daemon=True,
            )

    tcp_thread.start()
    udp_thread.start()

    tcp_thread.join()
    udp_thread.join()
