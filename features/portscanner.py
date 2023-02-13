from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
import json


class PortScanner:
    def __init__(self) -> None:
        """
        Object Constructor
        """
        self.ports = json.load(open("ports.json", 'r'))

    def ports_scan(self, host: str) -> dict:
        """
        This function checks what ports are open for the given host and returns a results dictionary with the port
        number as the key and a tuple with the port service and the port state as the value.
        :param host: the ip of the query host.
        :return: the result dictionary (dict).
        """
        open_ports = {}
        for dst_port in self.ports:
            src_port = dst_port + 1
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
        for host in hosts:
            response = sr1(IP(dst=host) / ICMP(), timeout=2, verbose=0)

            if int(response.getlayer(ICMP).type) != 3 and int(
                    response.getlayer(ICMP).code
            ) not in {1, 2, 3, 9, 10, 13}:
                hosts[host].append(self.ports_scan(host))




