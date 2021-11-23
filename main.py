import threading
import socket
import time

class Packet_creator:
    def set_MY_addr(self, IP, port):
        self.MY_IP = IP
        self.MY_PORT = port

    def set_TARGET_addr(self, IP, port):
        self.TARGET_IP = IP
        self.TARGET_PORT = port

    def get_MY_addr(self):
        return (self.MY_IP, self.MY_PORT)

    def get_TARGET_addr(self):
        return (self.TARGET_IP, self.TARGET_PORT)

    def changeInputMode(self, value):
        global inputMode
        inputMode = value

    def create_ACK(self, SEQ):
        body = int.to_bytes(4, 1, "big")
        body += int.to_bytes(SEQ, 4, "big")
        return body

    def create_SYN(self):
        body = int.to_bytes(0, 1, "big") #type
        body += int.to_bytes(0, 4, "big") #seq
        return body

    def create_KeepAlive(self, SEQ):
        body = int.to_bytes(5, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        return body

    def create_FIN(self, SEQ):
        body = int.to_bytes(6, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        return body

    def create_MSG(self, SEQ, message):
        body = int.to_bytes(7, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        body += bytes(message, "utf-8")
        return body


    def get_type(self, body):
        return body[0]

    def get_SEQ(self, body):
        return int.from_bytes(body[1:5], "big")

    def send_socket(self, socket):
        self.sck = socket

    def sendPacket(self, body, addr):
        self.sck.sendto(body, addr)

    def waitForPacket(self):
        return self.sck.recvfrom(1500)


class Receiver:
    def __init__(self, port):
        self.message = ""
        self.path = ""
        self.file = ""

        # hostname = socket.gethostname()
        # local_ip = socket.gethostbyname(hostname)
        # print(local_ip)

        # UDP_IP = local_ip
        #self.MY_IP = "127.0.0.1"
        self.MY_IP = "192.168.0.166"
        self.MY_PORT = port



        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        self.sock.bind((self.MY_IP, self.MY_PORT))

        self.receiverInput = True

        self.activeClass = True

        self.arrived_SEQ = 0

        self.synchronized = False


    def getReceiverInput(self):
        return self.receiverInput

    def setReceiverInput(self, value):
        self.receiverInput = value

    def setActiveClass(self, value):
        self.activeClass = value

    def send_packet(self, body, addr):
        packet_creator.sendPacket(body, addr)
        #self.sock.sendto(body, addr)

    def restart_listening(self):
        pass

    def cancel_waiting(self):
        self.activeClass = False
        self.synchronized = True
        packet_creator.sendPacket(int.to_bytes(255, 1, "big"), packet_creator.get_MY_addr())
        #self.sock.sendto(int.to_bytes(255, 1, "big"), (self.MY_IP, self.MY_PORT))

    def cancel_keepAlive_waiting(self):
        packet_creator.sendPacket(int.to_bytes(254, 1, "big"), packet_creator.get_MY_addr())
        #self.sock.sendto(int.to_bytes(254, 1, "big"), (self.MY_IP, self.MY_PORT))

    def exceeded_waiting_for_keepAlive(self, ex_SEQ):

        time.sleep(5.4)

        if ex_SEQ >= self.arrived_SEQ:
            self.cancel_keepAlive_waiting()


    def waiting_for_packet(self):
        self.activeClass = True
        while self.activeClass:
            if self.synchronized:
                data, addr = packet_creator.waitForPacket()
            else:
                data, addr = self.sock.recvfrom(1500)  # buffer size is 1024 bytes

            type = packet_creator.get_type(data)

            if type == 0: #SYN
                self.synchronized = True

                packet_creator.send_socket(self.sock)

                self.receiverInput = False
                ack_P = packet_creator.create_ACK(packet_creator.get_type(data))

                self.send_packet(ack_P, addr)

                #uložím si adresu
                packet_creator.set_TARGET_addr(addr[0], addr[1])
                packet_creator.set_MY_addr(self.MY_IP, self.MY_PORT)


                print("\n\nKomunikácia nadviazaná!")
                print("IP adresa odosielateľa: " + addr[0])
                print("Port odosielateľa: " + str(addr[1]) + "\n\n")

                print("Ako si prajete pokračovať:\na) Poslať správu\nb) Poslať súbor\nc) Ukončiť komunikáciu\n")

                packet_creator.changeInputMode(1) #poslanie suboru

                self.keepAlive_arrived = False
                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(0, )).start()


            if type == 5: #KeepAlive
                print("KeepAlive packet prijatý")

                SEQ = packet_creator.get_SEQ(data)

                self.arrived_SEQ = SEQ

                self.keepAlive_arrived = True

                ack_P = packet_creator.create_ACK(SEQ)
                self.send_packet(ack_P, addr)

                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(SEQ, )).start()

            if type == 7: #sprava
                print("Sprava dorazila")
                print(data[5:])




            if type == 254: #KeepAlive not arrived
                #print("KeepAlive packet nedorazil")
                print("\nKomunikácia prerušená!\n")
                break











class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        self.SEQ_num = 0

        self.message = ""
        self.path = ""
        self.file = ""

    def set_TARGET_ADDR(self, addr):
        self.TARGET_IP = addr[0]
        self.TARGET_PORT = addr[1]

    def get_SEQ(self, body):
        return int.from_bytes(body[1:5], "big")

    def send_packet(self, body):
        packet_creator.sendPacket(body, (self.TARGET_IP, self.TARGET_PORT))
        #self.sock.sendto(body, (self.TARGET_IP, self.TARGET_PORT))

    def send_message(self, message):
        self.message = message

        self.SEQ_num += 1
        msg_P = packet_creator.create_MSG(self.SEQ_num, message)

        self.send_packet(msg_P)

        print("Správa úspešne odoslaná.")

        packet_creator.changeInputMode(1)






    def set_enabled_keepAlive(self, value):
        self.enabled_keepAlive = value

    def exceeded_waiting_for_keepAlive(self, ex_SEQ):
        while True:
            time.sleep(5.4)

            if ex_SEQ >= self.arrived_SEQ:
                self.keepAlive_arrived = False
                break

            ex_SEQ += 1

    def waiting_for_keepAlive_packet(self):
        data, addr = packet_creator.waitForPacket()
        #data, addr = self.sock.recvfrom(1500)
        self.arrived_SEQ = self.get_SEQ(data)
        #print(str(self.arrived_SEQ))

    def thread_keepAlive(self):
        self.enabled_keepAlive = True
        self.keepAlive_arrived = True
        threading.Timer(0.5, self.exceeded_waiting_for_keepAlive, args=(0, )).start()
        while self.enabled_keepAlive:
            threading.Thread(target=self.waiting_for_keepAlive_packet).start()
            time.sleep(5)
            self.SEQ_num += 1
            print("KeepAlive packet poslaný")
            self.send_packet(packet_creator.create_KeepAlive(self.SEQ_num))

            if not self.keepAlive_arrived:
                print("\nKomunikácia prerušená!\n")
                break




    def waiting_for_SYN_packet(self):
        data, addr = packet_creator.waitForPacket()
        #data, addr = self.sock.recvfrom(1500)
        print("\n\nKomunikácia nadviazaná!")
        print("IP adresa prijímateľa: " + addr[0])
        print("Port prijímateľa: " + str(addr[1]) + "\n\n")

        print("Ako si prajete pokračovať:\na) Poslať správu\nb) Poslať súbor\nc) Ukončiť komunikáciu\n")

        packet_creator.changeInputMode(1) #poslanie suboru


        threading.Thread(target=self.thread_keepAlive, name="t1").start()




    def establish_com(self):
        syn_P = packet_creator.create_SYN()

        #self.TARGET_IP = "127.0.0.1"
        self.TARGET_IP = "192.168.0.130"
        # UDP_IP = "192.168.0.130"
        self.TARGET_PORT = 5005

        #self.TARGET_IP = input("Zadajte IP adresu prijímateľa: ")
        #self.TARGET_PORT = input("Zadajte port prijímateľa: ")

        self.sock.bind(('', 0))
        addr = self.sock.getsockname()
        print("Mojo infošky")
        print(addr)

        packet_creator.send_socket(self.sock)
        packet_creator.set_TARGET_addr(self.TARGET_IP, self.TARGET_PORT)
        packet_creator.set_TARGET_addr(addr[0], addr[1])


        self.send_packet(syn_P)

        self.waiting_for_SYN_packet()








def thread_waiting_for_input():
    global inputMode
    while True:
        s = input()

        if inputMode == 0: #zacat komunikaciu
            if s == "y":
                #receiver.setActiveClass(False)

                sender.establish_com()
                receiver.restart_listening()


        elif inputMode == 1: #poslat subor
            print("posielanie suboru")

            if s == "a": #sprava
                print("Zadajte správu: ", end="")
                inputMode = 2

            if s == "b": #subor
                print("Zadajte cestu k súboru: ", end="")
                inputMode = 3

            if s == "c": #konec
                print("Koneeeeec")

            #sender.set_enabled_keepAlive(False)  # prestane posielať keepAlive
            #receiver.cancel_waiting()  # prestane očakávať vstup

        elif inputMode == 2: #sprava
            sender.send_message(s)










MY_PORT = int(input("Zadajte port, na ktorom očakávate komunikáciu: "))

packet_creator = Packet_creator()
receiver = Receiver(MY_PORT)#rcv.Receiver(MY_PORT)
sender = Sender()#snd.Sender()

inputMode = 0

t_input = threading.Thread(target=thread_waiting_for_input)
#t2 = threading.Thread(target=receiver.waiting_for_packet)
cancel_t2 = threading.Thread(target=receiver.cancel_waiting)

print("Prajete si začať komunikáciu ? (y/n) ", end="")
#t2.start()
t_input.start()

receiver.waiting_for_packet()





