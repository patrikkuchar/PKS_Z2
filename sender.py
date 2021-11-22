import socket
import threading
import time


class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

    def create_SYN(self):
        body = int.to_bytes(0, 1, "big") #type
        body += int.to_bytes(0, 4, "big") #seq
        return body

    def create_KeepAlive(self, SEQ):
        body = int.to_bytes(5, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq

    def create_FIN(self, SEQ):
        body = int.to_bytes(6, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        return body

    def send_packet(self, body):
        self.sock.sendto(body, (self.TARGET_IP, self.TARGET_PORT))

    def waiting_for_packet(self):
        data, addr = self.sock.recvfrom(1500)
        print("Komunikácia nadviazaná!")
        print("IP adresa odosielateľa: " + addr[0])
        print("Port odosielateľa: " + str(addr[1]))



        print(data)
        print(addr)

    def establish_com(self):
        syn_P = self.create_SYN()

        self.TARGET_IP = "127.0.0.1"
        # UDP_IP = "192.168.0.130"
        self.TARGET_PORT = 5005

        #self.TARGET_IP = input("Zadajte IP adresu prijímateľa: ")
        #self.TARGET_PORT = input("Zadajte port prijímateľa: ")


        self.send_packet(syn_P)

        self.waiting_for_packet()










