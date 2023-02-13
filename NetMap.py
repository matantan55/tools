from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
import contextlib
import subprocess
import re
from pprint import pprint
import json
from tqdm import tqdm


class NetworkMapper:
    def __init__(self) -> None:
        """
        Object Constructor
        """
        self.hosts = self._find_hosts()

    def collect_info(self) -> None:
        self._add_ports()

    def _add_os(self) -> None:
        pass

    def _add_ports(self):
        pt = PortScanner()
        pt.scan_hosts(self.hosts)

    @staticmethod
    def _find_hosts() -> dict:
        """
        This function collects all the connected hosts in the network and maps them to their data
        :return: a dictionary with all the every host mapped to their mac address
        """
        out = subprocess.Popen(["arp -a"], stdout=subprocess.PIPE, shell=True).stdout.read().decode(
            "utf-8")
        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', out)
        macs = re.findall(r'\w*:\w*:\w*:\w*:\w*:\w*', out)
        return {ip: [mac] for ip, mac in zip(ips, macs)}


class PortScanner:
    def __init__(self) -> None:
        """
        Object Constructor
        """
        json_data: dict = json.load(open("config_files/ports.json", 'r'))
        self.ports = {int(key): value for key, value in json_data.items()}

    def ports_scan(self, host: str) -> dict:
        """
        This function checks what ports are open for the given host and returns a results dictionary with the port
        number as the key and a tuple with the port service and the port state as the value.
        :param host: the ip of the query host.
        :return: the result dictionary (dict).
        """
        open_ports = {}
        for dst_port in self.ports:
            src_port = RandShort()
            if response := sr1(
                    IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="S"),
                    timeout=1,
                    verbose=0,
            ):
                if response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        sr(
                            IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags='R'),
                            timeout=1,
                            verbose=0,
                        )
                        open_ports[dst_port] = (self.ports[dst_port], "open")
                elif response.haslayer(ICMP):
                    if int(response.getlayer(ICMP).type) == 3 and int(
                            response.getlayer(ICMP).code
                    ) in {1, 2, 3, 9, 10, 13}:
                        open_ports[dst_port] = (self.ports[dst_port], "filtered (silently dropped)")
        return open_ports

    def scan_hosts(self, hosts: dict[str:list]) -> None:
        """
        This function get a dictionary of hosts and their data and modify the dictionary by adding a dictionary of open
        ports (for every host) to each key value (value-type=list).
        :param hosts: dictionary of hosts and their data
        :return: None
        """
        for host in tqdm(hosts):
            response = sr1(IP(dst=host) / ICMP(), timeout=2, verbose=0)

            if response and int(response.getlayer(ICMP).type) != 3 and int(
                    response.getlayer(ICMP).code
            ) not in {1, 2, 3, 9, 10, 13}:
                hosts[host].append(self.ports_scan(host))


def main() -> None:
    nm = NetworkMapper()
    nm.collect_info()
    pprint(nm.hosts)


if __name__ == "__main__":
    main()
