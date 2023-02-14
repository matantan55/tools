import socket


def port_scan(host, port):
    s = socket.socket()
    try:
        s.connect((host, port))
    except ConnectionError:
        s.close()
        return False
    s.close()
    return True


print(port_scan("192.168.1.1", 5000))
