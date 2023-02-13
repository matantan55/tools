from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import pandas as pd


class HostsDiscoverer:
    def __init__(self) -> None:
        """
        Object Constractor
        """
        self.target_ip = f"{self.get_gateway_ip_address()}/24"
        self.broadcasting_mac = "ff:ff:ff:ff:ff:ff"
    # 
    def discover(self) -> list:
        """
        this function broadcast a packet and collects responses which contain info about the discovered hosts from the
        broadcast
        :return: a list of hosts
        """
        arp = ARP(pdst=self.target_ip)  # create an ARP packet to the target
        ether = Ether(dst=self.broadcasting_mac)  # create an Ether packet for broadcasting
        pkt = ether / arp  # stack the packets into one
        result = srp(pkt, timeout=15, verbose=0)[0]  # start discovering
        return [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]  # return  a list with all
        # the discovered hosts

    @staticmethod
    def get_gateway_ip_address() -> str:
        """
        this function returns the ip address of the gateway
        :return: the ip address of the gateway
        """
        return subprocess.Popen(["route -n get default | grep 'gateway' | awk '{print $2}'"],
                                stdout=subprocess.PIPE,
                                shell=True).stdout.read().decode().replace("\n", "")


class DeviceTable:
    def __init__(self, ips: list[str], macs: list[str]) -> None:
        """
        Object Constractor
        :param ips: list of ip addresses for the IP column
        :param macs: list of mac addresses for the MAC column
        """
        self.down = '\n'
        self.labels = ['IP', 'MAC']
        self.ips = ips
        self.macs = macs
        self.elements = self.generate_rows_list()

    def generate_rows_list(self) -> list:
        """
        this function generates a list that each element in it will be presented as a row,
        and makes sure every row has the save amount of element as the labels list.
        :return: a list of rows
        :rtype: list
        """
        ips, macs = len(self.ips), len(self.macs)
        max_length = max(ips, macs)
        default = ["NOT FOUND"]
        self.ips.extend(default * (max_length - ips))
        self.macs.extend(default * (max_length - ips))
        return list(map(list, zip(self.ips, self.macs)))

    def __str__(self) -> str:
        """
        Object's ToString function
        :return: a representation of the object
        :rtype: str
        """
        return pd.DataFrame(self.elements, columns=self.labels).to_string()


if __name__ == '__main__':
    hd = HostsDiscoverer()
    addresses = hd.discover()
    ips_a = [i['ip'] for i in addresses]
    macs_a = [i['mac'] for i in addresses]
    print(DeviceTable(ips_a, macs_a))
