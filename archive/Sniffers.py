import os
from statistics import stdev

import scapy.plist
from scapy.all import sniff, rdpcap, wrpcap


class Sniffer:

    def __init__(self):
        self._iface: str = 'lo'
        self._filter: str = 'icmp'
        self._count: int = 5
        self._packets = None  # scapy.plist.PacketList

    def set_iface(self, iface):
        self._iface = iface

    def get_iface(self):
        return self._iface

    def set_filter(self, filter):
        self._filter = filter

    def get_filter(self):
        return self._filter

    def set_count(self, count):
        self._count = count

    def get_count(self):
        return self._count

    # def analyze_10_packets(self, pkts):
    #     """
    #     analyze 10 _packets to get target network characteristics
    #     :param pkts: 10 target _packets, TCP/IP only !!!
    #     :return:
    #     - "Average Packet Size", the average length of the TCP/IP packet data field (hereinafter referred to as the packet length)
    #     - "Flow Bytes/s", the data flow rate
    #     - "Max Packet Length", the maximum packet length
    #     - "Fwd Packet Length Mean", the average length of _packets transmitted in the forward direction
    #     - "Fwd IAT Min", the minimum value of the inter-packet interval (IAT, inter-arrival time) in the forward direction
    #     - "Total Length of Fwd Packets", the total length of _packets transmitted in the forward direction
    #     - "Fwd IAT Std", the standard deviation of the value of the inter-packet interval in the forward direction of the _packets
    #     - "Flow IAT Mean", the average value of the batch interval
    #     - "Fwd Packet Length Max", the maximum length of a packet transmitted in the forward direction
    #     - "Fwd Header Length", the total length of the headers of _packets transmitted in the forward direction
    #     """
    #     total_length = 0
    #     max_pkt_len = 0
    #     fwd_pkts_len = []
    #     fwd_ia_times = []
    #     fwd_header_len = 0
    #
    #     for packet in pkts:
    #         try:
    #             total_length += len(packet)
    #             max_pkt_len = max(max_pkt_len, len(packet))
    #             fwd_pkts_len.append(packet.len)
    #             if self.last_time is not None:
    #                 # print(f"a={self.last_time} b={packet.time} d=b-a={packet.time - self.last_time}")
    #                 fwd_ia_times.append(packet.time - self.last_time)
    #             self.last_time = packet.time
    #             fwd_header_len += packet.ihl * 4 + packet.dataofs * 4
    #         except Exception as e:
    #             print(e)
    #             print(f"can't analyze packet:")
    #             packet.show()
    #     try:
    #         avg_pkt_size = float(round(total_length / len(pkts), 3))
    #         flow_bytes_per_s = float(round(total_length / (pkts[-1].time - pkts[0].time), 3))
    #         fwd_pkt_mean_len = float(round(sum(fwd_pkts_len) / len(fwd_pkts_len), 3))
    #         fwd_iat_min = float(round(min(fwd_ia_times) * 1000, 5))
    #         tot_len_fwd_pkts = sum(fwd_pkts_len)
    #         fwd_iat_std = float(round(stdev(fwd_ia_times), 5))
    #         flow_iat_mean = float(round(sum(fwd_ia_times) / len(fwd_ia_times), 5))
    #         fwd_pkt_max_len = max(fwd_pkts_len)
    #         # print(len(fwd_ia_times), fwd_ia_times)
    #         # print("Average Packet Size:", avg_pkt_size)
    #         # print("Flow Bytes/s:", flow_bytes_per_s)
    #         # print("Max Packet Length:", max_pkt_len)
    #         # print("Fwd Packet Length Mean:", fwd_pkt_mean_len)
    #         # print("Fwd IAT Min:", fwd_iat_min)
    #         # print("Total Length of Fwd Packets:", tot_len_fwd_pkts)
    #         # print("Fwd IAT Std:", fwd_iat_std)
    #         # print("Flow IAT Mean:", flow_iat_mean)
    #         # print("Fwd Packet Length Max:", fwd_pkt_max_len)
    #         # print("Fwd Header Length:", fwd_header_len)
    #         return (
    #                 avg_pkt_size,
    #                 flow_bytes_per_s,
    #                 max_pkt_len,
    #                 fwd_pkt_mean_len,
    #                 fwd_iat_min,
    #                 tot_len_fwd_pkts,
    #                 fwd_iat_std,
    #                 flow_iat_mean,
    #                 fwd_pkt_max_len,
    #                 fwd_header_len
    #                 )
    #     except Exception as e:
    #         print(e)

    def check_params(self):
        print(f'iface : {self.get_iface()}, {type(self.get_iface())}')
        print(f'filter : {self.get_filter()}, {type(self.get_filter())}')
        print(f'count : {self.get_count()}, {type(self.get_count())}')

    def start(self):
        """
        start sniffing with given params
        :return: None, put sniffed _packets at '_packets' attribute
        """
        self._packets = sniff(iface=self._iface, filter=self._filter, count=self._count)

    def show_packets(self):
        for packet in self._packets:
            packet.show()


class SnifferTransmitter(Sniffer):
    ...


class SnifferTeacher(Sniffer):
    ...
