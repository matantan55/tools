import random
import socket
import struct
from randmac import RandMac
from faker import Faker
from pprint import pprint


class DeviceTable:
    def __init__(self, ips: list[str], macs: list[str], hostnames: list[str]) -> None:
        """
        Object Constractor
        :param ips: list of ip addresses for the IP column
        :param macs: list of mac addresses for the MAC column
        :param hostnames: list of hostnames for the HOSTNAME column
        """
        self.down = '\n'
        self.labels = ['No.', 'IP', 'MAC', 'HOSTNAME']
        self.title = f"| {' | '.join(self.labels)} |"
        self.ips = ips
        self.macs = macs
        self.hostnames = hostnames
        self.elements = self.generate_rows_list()
        self.formatted = self.format()
        max_string = len(max(self.formatted))
        self.line = "- " * (max_string // 2)

    def generate_rows_list(self) -> list:
        """
        this function generates a list that each element in it will be presented as a row,
        and makes sure every row has the save amount of element as the labels list.
        :return: a list of rows
        """
        ips_a, macs_a, hostnames_a = len(self.ips), len(self.macs), len(self.hostnames)
        max_length = max(ips_a, macs_a, hostnames_a)
        numbers = map(lambda x: f"{x}.", range(max_length))
        default = ["NOT FOUND"]
        self.ips.extend(default * (max_length - ips_a))
        self.macs.extend(default * (max_length - ips_a))
        self.hostnames.extend(default * (max_length - ips_a))
        return list(map(list, zip(numbers, self.ips, self.macs, self.hostnames)))

    @staticmethod
    def element_format(element: list[str]) -> str:
        """
        this function is used to format each row.
        :param element: a row as a list.
        :return: a string of the given row.
        """
        return f"| {' '.join(element)} |"

    def format(self) -> list:
        """
        this function is used to format all the rows to make the final table.
        :return: the formatted rows.
        """
        return [self.element_format(row) for row in self.elements]

    def __str__(self) -> str:
        return f"{self.line}\n{self.title}\n{self.line}\n{f'{self.down}'.join(self.format())}"


def ip_gen():
    return str(socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))))


def hostname_gen():
    return "".join(str(Faker().name()).split())


if __name__ == '__main__':
    ips1 = [ip_gen() for _ in range(10)]
    macs1 = [str(RandMac()) for _ in range(10)]
    hn1 = [hostname_gen() for _ in range(10)]

    ips2 = [ip_gen() for _ in range(random.randint(5, 20))]
    macs2 = [str(RandMac()) for _ in range(random.randint(5, 20))]
    hn2 = [hostname_gen() for _ in range(random.randint(5, 20))]

    test_vector1 = DeviceTable(ips1, macs1, hn1)
    test_vector2 = DeviceTable(ips2, macs2, hn2)

    pprint(test_vector1.elements)
    print()
    pprint(test_vector2.elements)

    print()

    pprint(test_vector1.format())
    print()
    pprint(test_vector2.format())

    print(test_vector1)
    print()
    print(test_vector2)
