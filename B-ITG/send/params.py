from scapy.interfaces import get_working_ifaces
from scapy.arch import get_if_hwaddr, get_if_addr, get_if_addr6


def get_full_info():
    """Получаем все адреса для каждого интерфейса"""
    for iface in get_working_ifaces():
        print(f"\nInterface: {iface}")
        mac = get_if_hwaddr(iface)
        ip = get_if_addr(str(iface))
        ip6 = get_if_addr6(iface)
        print(f"\t{mac}\t{ip}\t{ip6}")


class Src:
    def __init__(self):
        self.iface = 'ens33'
        self.mac = get_if_hwaddr(self.iface)
        self.ip = get_if_addr(str(self.iface))
        self.port = 12345

    def _show_params(self):
        print(f"iface: {self.iface}, ip: {self.ip}, port: {self.port}, mac: {self.mac}")


class Dst:
    def __init__(self):
        self.iface = 'ens33'
        self.mac = get_if_hwaddr(self.iface)  # None
        self.ip = "10.1.1.2"  # get_if_addr(str(self.iface))  # '172.16.63.152'
        self.port = 12345  # 58070  # 60308

    def _show_params(self):
        print(f"iface: {self.iface}, ip: {self.ip}, port: {self.port}, mac: {self.mac}")


src = Src()
dst = Dst()

if __name__ == '__main__':
    src = Src()
    dst = Dst()
    src._show_params()
    dst._show_params()
    get_full_info()
