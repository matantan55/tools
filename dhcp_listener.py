from scapy.all import *
import time
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import Ether
from keyboard import is_pressed

# needs administrator privileges


class DHCPListener:
    def __init__(self) -> None:
        """
        Object Constractor
        """
        self.sniffer = AsyncSniffer(prn=self.print_packet, filter='udp and (port 67 or port 68)')

    def listen_dhcp(self) -> None:
        """
        this function start the sniffing for dhcp packets
        :return: None
        """
        # sniff(prn=self.print_packet, filter='udp and (port 67 or port 68)')
        self.sniffer.start()
        while not is_pressed('q'):
            pass
        self.sniffer.stop()
        self.sniffer.join()

    @staticmethod
    def print_packet(pkt: Packet) -> None:
        """
        this function displays the device details when given a DHCP packet (MAC address, hostname, vendor id number
        and requested ip)
        :param pkt: the current sniffed packet.
        :return: None
        """
        if not pkt.haslayer(DHCP):
            return
        # initialize these variables to None at first
        target_mac, requested_ip, hostname, vendor_id = [None] * 4
        # get the MAC address of the requester
        if pkt.haslayer(Ether):
            target_mac = pkt.getlayer(Ether).src
        # get the DHCP options

        dhcp_options = pkt[DHCP].options
        for item in dhcp_options:
            if type(item) in [list, tuple]:
                label, value = item
                if label == 'requested_addr':
                    # get the requested IP
                    requested_ip = value
                elif label == 'hostname':
                    # get the hostname of the device
                    hostname = value.decode()
                elif label == 'vendor_class_id':
                    # get the vendor ID
                    vendor_id = value.decode()
        if target_mac and vendor_id and hostname and requested_ip:
            # if all variables are not None, print the device details
            time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
            print(f"{time_now} : {target_mac}  -  {hostname} / {vendor_id} requested {requested_ip}")


if __name__ == "__main__":
    obj = DHCPListener()
    obj.listen_dhcp()