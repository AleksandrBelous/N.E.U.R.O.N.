# sender.py
import socket
import time
from params import dst


def send_packets_per_sec(sock, packets_per_second):
    packet_count = packets_per_second
    interval = 0.5 / packet_count

    start = time.perf_counter()
    for i in range(packet_count):
        msg = f"[Sender] Packet {i + 1}/{packet_count}"
        try:
            sock.sendall(msg.encode())
        except BrokenPipeError:
            print("[Sender] Connection closed by receiver")
            return
        next_time = start + (i + 1) * interval
        delay = next_time - time.perf_counter()
        # print(f"[Sender] Sleeping for {delay} seconds")
        if delay > 0:
            time.sleep(delay)

    real_duration = time.perf_counter() - start
    # delay = 0.5 - real_duration
    # if delay > 0:
    #     print(f"[Sender] Sleeping for {delay} seconds after real duration = {real_duration}")
    #     time.sleep(delay)
    print(f"[Sender] Sent {packet_count} packets in {real_duration:.3f}s ({packet_count / real_duration:.2f} pps)")


def main():
    try:
        repeat_cycles = 6
        speed_pattern = [500, 1000]
        count = 1
        full_sequence = []
        for _ in range(repeat_cycles):
            # Добавляем каждый элемент шаблона по count раз
            for speed in speed_pattern:
                full_sequence.extend([speed] * count)
        total_seconds = len(full_sequence)
        print(f"[Sender] Total transmission time: {total_seconds} seconds")

        with socket.create_connection((dst.ip, dst.port), timeout=5) as sock:
            print("[Sender] Connected to receiver")
            for packets_per_second in full_sequence:
                # packets_per_second = [500]
                send_packets_per_sec(sock, packets_per_second)
    except ConnectionRefusedError:
        print("[Sender] Connection refused. Is RECEIVER running?")
    except socket.timeout:
        print("[Sender] Connection timed out")


if __name__ == "__main__":
    main()
