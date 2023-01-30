import shodan
import json
import socket
from urllib.parse import urlparse


def get_ips_by_dns_lookup(target, port=443) -> list:
    """
        this function takes the passed target and optional port and does a dns
        lookup. it returns the ips that it finds to the caller.

        :param target:  the URI that you'd like to get the ip address(es) for
        :type target:   string
        :param port:    which port do you want to do the lookup against?
        :type port:     integer
        :returns ips:   all the discovered ips for the target
        :rtype ips:     list of strings

    """
    return list(map(lambda x: x[4][0], socket.getaddrinfo(f'{target}.', port, type=socket.SOCK_STREAM)))


def get_domain(url: str) -> str:
    return urlparse(url).netloc


api = shodan.Shodan('ore3Cq6538ecmPPkb5Bqprn3FKPkKbAq')
print(get_ips_by_dns_lookup(get_domain("https://stackoverflow.com/")))
# info = api.host("")
# with open("out.json", "w") as file:
#    json.dump(info, file, indent=4)
