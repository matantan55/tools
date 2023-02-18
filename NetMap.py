import multiprocessing
import socket
import subprocess
import re
from pprint import pprint
import json
from threading import Thread
from ipaddress import ip_network, IPv4Network, IPv4Address
import netifaces


class NetworkMapper:
    def __init__(self) -> None:
        """
        Object Constructor
        """
        self.hosts = self._find_hosts()

    def collect_info(self) -> None:
        self._add_ports()
        self._add_os()

    def _add_os(self) -> None:
        pass

    def _add_ports(self) -> None:
        """
        This function uses a PortScanner object to provide to each host (in the host's dictionary) its open ports.
        :return: None
        """
        pt = PortScanner()
        pt.turbo_scan(self.hosts)

    def _find_hosts(self) -> dict:
        """
        This function collects all the connected hosts in the network and maps them to their data
        :return: a dictionary with all the every host mapped to their mac address
        """
        out = subprocess.Popen(["arp -a"], stdout=subprocess.PIPE, shell=True).stdout.read().decode(
            "utf-8")
        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', out)
        macs = re.findall(r'\w*:\w*:\w*:\w*:\w*:\w*', out)
        network = [*self.get_network().hosts()]
        return {ip: [mac] for ip, mac in zip(ips, macs) if IPv4Address(ip) in network}

    @staticmethod
    def get_network() -> IPv4Network:
        """
        This function generates and returns a IPv4Network object which contains range of ip address in the current
        network.
        :return: IPv4Network object
        """
        gw = netifaces.gateways()
        router_ip, iface = gw["default"][2][0], gw["default"][2][1]
        netdata = netifaces.ifaddresses(iface)
        netmask = netdata[2][0]["netmask"]
        mask = IPv4Network(f'0.0.0.0/{netmask}').prefixlen
        subnet_musk = f"{router_ip}/{mask}"
        return ip_network(subnet_musk, False)


class PortScanner:
    def __init__(self) -> None:
        """
        Object Constructor
        """
        json_data: dict = json.load(open("config_files/ports.json", 'r'))
        self.ports = {int(key): value for key, value in json_data.items()}

    def _ports_scan(self, host: str) -> dict:
        """
        This function checks what ports are open for the given host and returns a results dictionary with the port
        number as the key and a tuple with the port service and the port state as the value.
        :param host: the ip of the query host. (str)
        :return: the result dictionary (dict).
        """
        open_ports = {}
        ports_threads = [Thread(target=self._scan_port, args=(host, port, open_ports), daemon=True) for port in
                         self.ports]
        for pt in ports_threads:
            pt.start()
        for pt in ports_threads:
            pt.join()
        return open_ports

    def _scan_port(self, host: str, port: int, open_ports: dict) -> None:
        """
        This function gets an ip, port number and a dictionary of open ports. checks if the given port is port in
        the given host and add the port to the dictionary as a key, and the ports service as the value if the port is
        indeed open.
        :param host: query host's ip (str)
        :param port: query port number (int)
        :param open_ports: dictionary of the open ports (dict)
        :return: None
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, port))
            open_ports[port] = self.ports[port]
        except (ConnectionError, TimeoutError, socket.timeout, OSError):
            pass
        finally:
            s.close()

    def scan_hosts(self, hosts: dict[str, list]) -> None:
        """
        This function get a dictionary of hosts and their data and modify the dictionary by adding a dictionary of open
        ports (for every host) to each key value (value-type=list).
        :param hosts: dictionary of hosts and their data (dict)
        :return: None
        """
        for host in hosts:
            hosts[host].append(self._ports_scan(host))

    def turbo_scan(self, hosts: dict[str, list]) -> None:
        """
        This function get a dictionary of hosts and their data and modify the dictionary by adding a dictionary of open
        ports (for every host) to each key value (value-type=list) with better performance by using multiprocessing.
        :param hosts: dictionary of hosts and their data (dict)
        :return: None
        """
        cores = multiprocessing.cpu_count()
        dict_size = len(hosts)
        chunk_size = dict_size // cores + 1
        keys = list(hosts.keys())
        chunks = [keys[i:i + chunk_size] for i in range(0, dict_size, chunk_size)]
        pool = multiprocessing.Pool(processes=cores)
        for d, h in zip(self._upack_list_of_lists(pool.map(self._scan_hosts, chunks)), hosts):
            hosts[h].append(d)
        pool.close()

    def _scan_hosts(self, hosts: list) -> list:
        """
        help function for turbo scan.
        :param hosts: list of hosts ips (list)
        :return: modified list where every index contain the results of the host that was in that same index in the
        given list.
        """
        for index in range(len(hosts)):
            hosts[index] = self._ports_scan(hosts[index])
        return hosts

    @staticmethod
    def _upack_list_of_lists(lol: list[list]) -> list:
        """
        help function for turbo scan. This function gets a list of lists and extracts all the element from every child
        list to the father list.
        :param lol: list of lists (list).
        :return: an unpack list (list).
        """
        packed_lst = []
        for lst in lol:
            packed_lst.extend(lst)
        return packed_lst


def main() -> None:
    nm = NetworkMapper()
    # s = time.time()
    nm.collect_info()
    # e = time.time()
    # print(e - s)
    pprint(nm.hosts)


if __name__ == "__main__":
    main()
