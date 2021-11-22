import socket
import threading
import time

class Receiver:
    def __init__(self, port):
        self.message = ""
        self.path = ""
        self.file = ""

        # hostname = socket.gethostname()
        # local_ip = socket.gethostbyname(hostname)
        # print(local_ip)

        # UDP_IP = local_ip
        self.MY_IP = "127.0.0.1"
        self.MY_PORT = port

        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        self.sock.bind((self.MY_IP, self.MY_PORT))


    def create_ACK(self, SEQ):
        body = int.to_bytes(4, 1, "big")

        body += int.to_bytes(SEQ, 4, "big")
        return body

    def send_packet(self, body, addr):
        self.sock.sendto(body, addr)

    def get_type(self, body):
        return body[0]

    def get_SEQ(self, body):
        return int.from_bytes(body[1:5], "big")


    def waiting_for_packet(self):
        while True:
            data, addr = self.sock.recvfrom(1500)  # buffer size is 1024 bytes

            type = self.get_type(data)

            if type == 0: #SYN
                ack_P = self.create_ACK(self.get_type(data))
                self.send_packet(ack_P, addr)

                print("Komunikácia nadviazaná!")
                print("IP adresa odosielateľa: " + addr[0])
                print("Port odosielateľa: " + str(addr[1]))






