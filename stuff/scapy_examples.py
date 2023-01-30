from time import sleep
from scapy.all import *

# cap = sniff(count=10)
# print("\n")
# for i in cap:
#     print(i.command())

a = AsyncSniffer(prn=lambda x: x.summary)
a.start()
print("lol")
sleep(15)
a.stop()
print(a.results)
