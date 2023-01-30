import random
import socket
import struct
from randmac import RandMac
from pprint import pprint
import pandas as pd


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
        ips_a, macs_a = len(self.ips), len(self.macs)
        max_length = max(ips_a, macs_a)
        default = ["NOT FOUND"]
        self.ips.extend(default * (max_length - ips_a))
        self.macs.extend(default * (max_length - ips_a))
        return list(map(list, zip(self.ips, self.macs)))

    def __str__(self) -> str:
        return pd.DataFrame(self.elements, columns=self.labels).to_string()


def ip_gen():
    return str(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))


if __name__ == '__main__':
    ips1 = [ip_gen() for _ in range(10)]
    macs1 = [str(RandMac()) for _ in range(10)]

    ips2 = [ip_gen() for _ in range(random.randint(5, 20))]
    macs2 = [str(RandMac()) for _ in range(random.randint(5, 20))]

    test_vector1 = DeviceTable(ips1, macs1)
    test_vector2 = DeviceTable(ips2, macs2)

    pprint(test_vector1.elements)
    print()
    pprint(test_vector2.elements)

    print()

    print(test_vector1)
    print()
    print(test_vector2)
