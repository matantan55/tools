from scapy.all import *
from scapy.layers.inet import traceroute


if __name__ == "__main__":
    res, unans = traceroute(["www.microsoft.com", "www.cisco.com", "www.yahoo.com", "www.wanadoo.fr", "www.pacsec.com"],
                            dport=[80, 443], maxttl=20, retry=-2)
    res.graph(target="> graph.svg")  # saved to file