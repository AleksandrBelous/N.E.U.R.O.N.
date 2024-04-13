#!/bin/python3
from statistics import stdev

from scapy.all import sniff, hexdump, rdpcap, ls


class Sniffer:

    def __init__(self):
        self.packets_list = list()
        self.filter = "ip and tcp"
        self.num_packets_to_sniff = 10
        self.last_time = None

    def set_default(self):
        self.packets_list = list()
        self.last_time = None

    def sniffing_packets(self, packet):
        self.packets_list.append(packet)

    def analyze_packets(self, packets):
        total_length = 0
        max_pkt_len = 0
        fwd_pkts_len = []
        fwd_ia_times = []
        fwd_header_len = 0

        for packet in packets:
            try:
                total_length += len(packet)
                max_pkt_len = max(max_pkt_len, len(packet))
                fwd_pkts_len.append(packet.len)
                if self.last_time is not None:
                    # print(f"a={self.last_time} b={packet.time} d=b-a={packet.time - self.last_time}")
                    fwd_ia_times.append(packet.time - self.last_time)
                self.last_time = packet.time
                fwd_header_len += packet.ihl * 4 + packet.dataofs * 4
            except Exception as e:
                print(e)
                print(f"can't analyze packet:")
                packet.show()
        try:
            avg_pkt_size = total_length / len(packets)
            flow_bytes_per_s = total_length / (packets[-1].time - packets[0].time)
            fwd_pkt_mean_len = sum(fwd_pkts_len) / len(fwd_pkts_len)
            fwd_iat_min = min(fwd_ia_times)
            tot_len_fwd_pkts = sum(fwd_pkts_len)
            fwd_iat_std = stdev(fwd_ia_times)
            flow_iat_mean = sum(fwd_ia_times) / len(fwd_ia_times)
            fwd_pkt_max_len = max(fwd_pkts_len)

            # Вывод результатов
            # print(len(fwd_ia_times), fwd_ia_times)
            print("Average Packet Size:", avg_pkt_size)
            print("Flow Bytes/s:", flow_bytes_per_s)
            print("Max Packet Length:", max_pkt_len)
            print("Fwd Packet Length Mean:", fwd_pkt_mean_len)
            print("Fwd IAT Min:", fwd_iat_min)
            print("Total Length of Fwd Packets:", tot_len_fwd_pkts)
            print("Fwd IAT Std:", fwd_iat_std)
            print("Flow IAT Mean:", flow_iat_mean)
            print("Fwd Packet Length Max:", fwd_pkt_max_len)
            print("Fwd Header Length:", fwd_header_len)
        except Exception as e:
            print(e)

    def start_sniffing(self):
        sniff(prn=self.sniffing_packets, filter=self.filter, count=self.num_packets_to_sniff)

    def read_pcap(self, file_name):
        packets = rdpcap(file_name)
        for pkt in packets[:10]:
            pkt.show()

    def print(self):
        for packet in self.packets_list:
            print(len(packet))
            print(packet)
            ...


if __name__ == '__main__':
    sn = Sniffer()
    # sn.start_sniffing()
    # sn.analyze_packets(sn.packets_list)
    # sn.set_default()
    sn.read_pcap('/media/nemo/disk_2_hdd/Projects/Pycharm/NetworkNNAnalyser/filtered_at_vi_1520_1530.pcapng')
    sn.analyze_packets(sn.packets_list)
    sn.set_default()
