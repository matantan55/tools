from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.layers.inet6 import IPv6
from keyboard import is_pressed
import time

# needs administrator privileges

conf.sniff_promisc = True


class ArgumentError(Exception):
    pass


class Finder:
    def __init__(self, ip: str = None, mac: str = None, keystring: str = None) -> None:
        if all(i is None for i in [ip, mac, keystring]):
            raise ArgumentError("you have to enter at least one argument")
        self.ip = ip
        self.mac = mac
        self.keystring = keystring
        self.sniffer = AsyncSniffer(prn=self.printer)

    def packet_string_analysis(self, pkt: Packet, source: str, dest: str) -> str:
        if pkt.haslayer(DNSQR):
            q_name = pkt[DNSQR].qname
            if type(q_name) == bytes:
                q_name = q_name.decode()
            if self.keystring in q_name or q_name in self.keystring:
                yield f"{source} has made a DNS query for {self.keystring}"
        else:
            layers = list(pkt.layers())
            protocols = list(map(lambda x: str(x).split(".")[-1].replace("'>", ""), layers))
            layers_data = [pkt[layers[i]].show(dump=True) for i in range(len(layers))]
            for index, data in enumerate(layers_data):
                if self.keystring.lower() in str(data).lower():
                    yield f"'{self.keystring}' found in a {protocols[index]} packet, " \
                          f"the network entities involved in the connection: {source} as the source and " \
                          f"{dest} as the destination."

    def packet_analysis(self, pkt: Packet) -> str:
        if pkt.haslayer(ARP) and self.mac is not None:
            source = pkt[ARP].hwsrc
            if source == self.mac:
                yield f"{self.mac} detected trying to find {pkt[ARP].pdst} MAC Address (ARP)."
            source = pkt[ARP].psrc
            if source == self.ip:
                yield f"{self.ip} detected trying to find {pkt[ARP].pdst} MAC Address (ARP)."
        if pkt.haslayer(IP):
            source = pkt[IP].src
            dest = pkt[IP].dst
            if source == self.ip:
                if pkt.haslayer(TCP):
                    yield f"{self.ip} detected sending data on a tcp connection on port {pkt[TCP].sport} to " \
                          f"{pkt[IP].dst}:{pkt[TCP].dport}."
                elif pkt.haslayer(UDP):
                    if pkt.haslayer(DNS):
                        dns_type = "query" if pkt[DNS].opcode == 0 else "answer"
                        yield f"{self.ip} was found in a dns {dns_type} to {dest}"
                    else:
                        yield f"{self.ip} detected sending data on a udp connection on port " \
                              f"{pkt[UDP].sport} to {pkt[IP].dst}:{pkt[UDP].dport}."
            else:
                if self.keystring is None:
                    self.keystring = self.ip
                yield from self.packet_string_analysis(pkt, source, dest)
                if self.ip is not None:
                    tmp = self.keystring
                    self.keystring = self.ip
                    yield from self.packet_string_analysis(pkt, source, dest)
                    self.keystring = tmp
        if pkt.haslayer(Ether):
            source = pkt[Ether].src
            dest = pkt[Ether].dst
            if source == self.mac:
                yield f"Ethernet connection found between {self.mac} and {dest}."
            if pkt.haslayer(IPv6):
                if self.keystring is None:
                    self.keystring = self.mac
                yield from self.packet_string_analysis(pkt, source, dest)
                if self.mac is not None:
                    tmp = self.keystring
                    self.keystring = self.mac
                    yield from self.packet_string_analysis(pkt, source, dest)
                    self.keystring = tmp
            if pkt.haslayer(DHCP):
                dhcp_options = pkt[DHCP].options
                requested_ip, hostname = "", ""
                for item in dhcp_options:
                    if type(item) in [list, tuple]:
                        label, value = item
                        if label == 'requested_addr':
                            requested_ip = value
                        elif label == 'hostname':
                            hostname = value.decode()
                if source == self.mac:
                    yield f"{self.mac} has connected to the network and requested the ip address {requested_ip}"
                if self.keystring == hostname:
                    yield f"'{self.keystring}' was found in a DHCP packet as an hostname that requested the " \
                          f"ip address {requested_ip} for its mac address: {self.mac}"

    def printer(self, pkt: Packet) -> None:
        if detections := list(set(self.packet_analysis(pkt))):
            time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
            down = '\n'
            print(f"\033[4m{time_now}\033[0m\n{f'{down}'.join(detections)}")

    def listen(self):
        self.sniffer.start()
        while not is_pressed('q'):
            pass
        self.sniffer.stop()
        self.sniffer.join()


f = Finder(keystring="facebook")
f.listen()
