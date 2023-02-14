import socket
import subprocess
import re
import sys
from pprint import pprint
import json
from tqdm import tqdm
from threading import Thread


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
        :param host: the ip of the query host. (str)
        :return: the result dictionary (dict).
        """
        open_ports = {}
        ports_threads = [Thread(target=self.scan_port, args=(host, port, open_ports), daemon=True) for port in
                         self.ports]
        for pt in ports_threads:
            pt.start()
        for pt in ports_threads:
            pt.join()
        return open_ports

    def scan_port(self, host: str, port: int, open_ports: dict) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            s.connect((host, port))
            open_ports[port] = self.ports[port]
        except (ConnectionError, TimeoutError, socket.timeout, OSError):
            pass
        finally:
            s.close()

    def scan_hosts(self, hosts: dict[str:list]) -> None:
        """
        This function get a dictionary of hosts and their data and modify the dictionary by adding a dictionary of open
        ports (for every host) to each key value (value-type=list).
        :param hosts: dictionary of hosts and their data (dict)
        :return: None
        """
        for host in tqdm(hosts, file=sys.stdout):
            hosts[host].append(self.ports_scan(host))


def main() -> None:
    nm = NetworkMapper()
    nm.collect_info()
    pprint(nm.hosts)


if __name__ == "__main__":
    main()
