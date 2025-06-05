import socket
import time
from params import src, dst


def main():
    # creating the socket
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # just connecting
    sck.connect((dst.ip, dst.port))

    print("[Sender] Sending data ...")

    # Список, определяющий сколько пакетов отправлять за каждую секунду
    packets_per_second = [500]

    for count in packets_per_second:
        interval = 1.0 / count  # интервал между пакетами
        print(interval)
        print(f"[Sender] Отправляем {count} пакетов в течение следующей секунды...")
        start_time = time.time()
        for i in range(count):
            msg = f"Hello Server, count={count}, num={i + 1}"
            sck.sendall(msg.encode("utf-8"))
            # msg = sck.recv(1024)
            # if not msg:
            #     break
            # print(f"MSG: {msg}")
            time.sleep(interval)
        elapsed = time.time() - start_time
        print(f"Finished send at {elapsed:.6f} seconds")
        if elapsed < 1:
            time.sleep(1 - elapsed)

    # for i in range(10):
    #     msg = f"Hello Server, I'm {i}"
    #     sck.sendall(bytes(msg, "utf-8"))
    # I don't care about your response server, I'm closing
    sck.close()


if __name__ == "__main__":
    main()
