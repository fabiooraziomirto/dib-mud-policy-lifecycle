import argparse
import socket
import threading


def tcp(port: int) -> None:
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen()
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.sendall(connection.recv(4096))


def udp(port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", port))
    while True:
        payload, address = server.recvfrom(4096)
        server.sendto(payload, address)


parser = argparse.ArgumentParser()
parser.add_argument("--tcp", type=int, required=True)
parser.add_argument("--udp", type=int)
arguments = parser.parse_args()
if arguments.udp:
    threading.Thread(target=udp, args=(arguments.udp,), daemon=True).start()
tcp(arguments.tcp)
