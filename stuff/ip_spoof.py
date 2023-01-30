from scapy.all import *
from scapy.layers.inet import ICMP, IP


while True:
    packet = IP(src="192.168.1.249", dst="192.168.1.24") / ICMP()
    if answer := send(packet):
        answer.show()
