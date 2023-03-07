from nmap3 import Nmap
from NetMap import NetworkMapper
from pprint import pprint
from time import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm



class OSDetector:
    def __init__(self) -> None:
        """
        Object Constructor
        """
        self.HOSTS_OS = {}

    def scan_host(self, host: str) -> None:
        """
        This function finds the os of the given host and applies the results to the "results" dictionary.
        :param host: the ip address of the given host as a string (str).
        :return: None
        """
        scan = Nmap().nmap_os_detection(host)[host]['osmatch']
        if not scan:
            self.HOSTS_OS[host] = "UNKNOWN"
            return
        self.HOSTS_OS[host] = scan[0]['osclass']['osfamily']

    def scan_hosts(self, hosts: list[str]) -> None:
        """
        This function finds the os of all the given hosts in the list and applies the results to the "results"
        dictionary using a multithreading method.
        :param hosts: the list of ip addresses of the given hosts as strings (list).
        :return: None
        """
        size = len(hosts)
        with tqdm(total=size) as pbar:
            with ThreadPoolExecutor(max_workers=size) as ex:
                futures = [ex.submit(self.scan_host, host) for host in hosts]
                for future in as_completed(futures):
                    future.result()
                    pbar.update()


n = NetworkMapper()
o = OSDetector()
start = time()
o.scan_hosts(list(n.hosts.keys()))
end = time()
pprint(o.HOSTS_OS)
print(end - start)
