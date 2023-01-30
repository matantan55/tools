import subprocess
import re


def get_subnet_mask() -> str:
    """
    this function return the subnet mask of the current network.
    :return: the subnet mask as an ip.
    """
    return subprocess.Popen(["ifconfig -a| grep -w inet|awk '{print $6}'"],
                            stdout=subprocess.PIPE,
                            shell=True).stdout.read().decode().replace("\n", "").replace("255", "0")


def get_hosts() -> list:
    """
    this function lists all the active hosts in the current network.
    :return: list of ip addresses.
    """
    return re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', subprocess.Popen(["arp -a -n"],
                                                                              stdout=subprocess.PIPE,
                                                                              shell=True).stdout.read().decode())


if __name__ == "__main__":
    print(get_subnet_mask())
    print(get_hosts())
