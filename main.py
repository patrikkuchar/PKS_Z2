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

    def generateCRC(self, fragment):
        return fragment


    def create_SYN(self):
        body = int.to_bytes(0, 1, "big") #type
        body += int.to_bytes(0, 4, "big") #seq
        return body

    def create_INF(self, SEQ, data):
        body = int.to_bytes(1, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        body += bytes(data, "utf-8")
        return self.generateCRC(body)

    def create_PSH(self, SEQ, data):
        body = int.to_bytes(2, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        body += data
        return self.generateCRC(body)

    def create_PSH_F(self, SEQ, data):
        body = int.to_bytes(3, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        body += data
        return self.generateCRC(body)

    def create_MSG(self, SEQ, message):
        body = int.to_bytes(4, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        body += bytes(message, "utf-8")
        return body

    def create_MSG_F(self, SEQ, message):
        body = int.to_bytes(5, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        body += bytes(message, "utf-8")
        return body

    def create_ACK(self, SEQ):
        body = int.to_bytes(6, 1, "big")
        body += int.to_bytes(SEQ, 4, "big")
        return body

    def create_nACK(self, SEQ):
        body = int.to_bytes(7, 1, "big")
        body += int.to_bytes(SEQ, 4, "big")
        return body

    def create_KeepAlive(self, SEQ):
        body = int.to_bytes(8, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        return body

    def create_KeepAliveACK(self, SEQ):
        body = int.to_bytes(9, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        return body

    def create_KeepAliveEND(self, SEQ):
        body = int.to_bytes(10, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
        return body

    def create_FIN(self, SEQ):
        body = int.to_bytes(11, 1, "big") #type
        body += int.to_bytes(SEQ, 4, "big") #seq
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
        self.file = b""

        hostname = socket.gethostname()
        self.MY_IP = socket.gethostbyname(hostname)
        # print(local_ip)

        #self.MY_IP = "127.0.0.1"
        #self.MY_IP = "192.168.0.166"
        self.MY_PORT = port

        self.writeInfo()



        self.enabled_keepAlive = False

        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        self.sock.bind((self.MY_IP, self.MY_PORT))

        self.receiverInput = True

        self.activeClass = True

        self.arrived_SEQ = 0

        self.synchronized = False

    def writeInfo(self):
        print("\n\n\nIP adresa zariadenia: " + self.MY_IP)
        print("Port, na ktorom sa očakáva komunikácia: " + str(self.MY_PORT) + "\n\n")

    def getDataFromPacket(self, body, decode):
        if decode:
            return body[5:].decode("utf-8")
        return body[5:]


    def getReceiverInput(self):
        return self.receiverInput


    def setReceiverInput(self, value):
        self.receiverInput = value

    def setActiveClass(self, value):
        self.activeClass = value

    def saveData(self):
        f = open(self.path, "w+b")
        f.write(self.file)
        f.close()
        print("Súbor bol uspešne uložený na adrese\n" + self.path + "\n")

        self.path = ""
        self.file = b""

    def send_packet(self, body, addr):
        packet_creator.sendPacket(body, addr)
        #self.sock.sendto(body, addr)

    def restart_listening(self):
        self.cancel_waiting()
        self.synchronized = True
        self.waiting_for_packet()

    def cancel_waiting(self):
        self.activeClass = False
        #packet_creator.sendPacket(int.to_bytes(255, 1, "big"), packet_creator.get_MY_addr())
        packet_creator.sendPacket(int.to_bytes(255, 1, "big"), (self.MY_IP, self.MY_PORT))
        #self.sock.sendto(int.to_bytes(255, 1, "big"), (self.MY_IP, self.MY_PORT))

    def cancel_keepAlive_waiting(self):
        #packet_creator.sendPacket(int.to_bytes(254, 1, "big"), packet_creator.get_MY_addr())
        packet_creator.sendPacket(int.to_bytes(254, 1, "big"), (self.MY_IP, self.MY_PORT))
        #self.sock.sendto(int.to_bytes(254, 1, "big"), (self.MY_IP, self.MY_PORT))

    def exceeded_waiting_for_keepAlive(self, ex_SEQ):

        time.sleep(5.1)

        if ex_SEQ >= self.arrived_SEQ and self.enabled_keepAlive:
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

            if type == 1: #INF
                #self.path = self.decodeData(data)
                print("Paket cesty dorazil")
                self.path += self.getDataFromPacket(data, True)


            elif type == 2: #PSH
                print("Paket dorazil")

                self.file += self.getDataFromPacket(data, False)

            elif type == 3: #PSH_F
                print("Posledný paket dorazil")
                self.file += self.getDataFromPacket(data, False)
                self.saveData()

            elif type == 4: #sprava
                print("Paket dorazil")
                #crc kontrola
                self.message += self.getDataFromPacket(data, True)

            elif type == 5: #sprava_F
                print("Posledny paket dorazil")
                #crc kontrola
                self.message += self.getDataFromPacket(data, True)

                print(">> " + self.message)
                self.message = ""



            elif type == 8: #KeepAlive
                self.enabled_keepAlive = True

                if showKeepAlivePackets:
                    print("KeepAlive packet prijatý")

                SEQ = packet_creator.get_SEQ(data)

                self.arrived_SEQ = SEQ

                self.keepAlive_arrived = True

                ack_P = packet_creator.create_KeepAliveACK(SEQ)
                self.send_packet(ack_P, addr)

                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(SEQ, )).start()

            elif type == 9: #keepAlive ACK
                sender.pp_arrived_SEQ()

            elif type == 10: #keepAlive stop
                print("Žiadosť o stopnutie keepAlive prijatá")
                self.enabled_keepAlive = False

            elif type == 11: #FIN
                print("Komunikácia úspešne ukončená")





            elif type == 254: #KeepAlive not arrived
                #print("KeepAlive packet nedorazil")
                print("\nKomunikácia prerušená!\n")
                break











class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        self.SEQ_num = 0


        self.local_path = ""
        self.target_path = ""
        self.file = ""


        self.sock.bind(('', 0))
        addr = self.sock.getsockname()
        MY_PORT = addr[1]
        hostname = socket.gethostname()
        MY_IP = socket.gethostbyname(hostname)
        packet_creator.set_MY_addr(MY_IP, MY_PORT)

        self.arrived_SEQ = 1

        self.packetsToSend = []


    def set_local_path(self, path):
        self.local_path = path

    def set_target_path(self, path):
        self.target_path = path

    def set_TARGET_ADDR(self, addr):
        self.TARGET_IP = addr[0]
        self.TARGET_PORT = addr[1]

    def get_SEQ(self, body):
        return int.from_bytes(body[1:5], "big")

    def send_packet(self, body):
        packet_creator.sendPacket(body, packet_creator.get_TARGET_addr())
        #self.sock.sendto(body, (self.TARGET_IP, self.TARGET_PORT))

    def send_prepared_packets(self):
        for protocol in self.packetsToSend:
            self.send_packet(protocol)
        self.packetsToSend = []

    def ask_for_size(self):
        while True:
            size = int(input("Zadajte počet bajtov pre dáta jedného fragmentu (1-1465)"))
            if size >= 1 and size <= 1465:
                break
        return size

    def split_data(self, data, size):
        array_of_data = []
        j = 0
        l = len(data)
        for i in range(size, l+size, size):
            array_of_data.append(data[j:i])
            j = i

        return array_of_data

    def send_message(self, message):
        size = self.ask_for_size()

        array_of_data = self.split_data(message, size)

        for one_data in array_of_data[:-1]:
            self.packetsToSend.append(packet_creator.create_MSG(self.ppSEQ(), one_data))
            #výpočet CRC
        self.packetsToSend.append(packet_creator.create_MSG_F(self.ppSEQ(), array_of_data[-1]))
        #výpočet CRC

        print("Odošle sa " + str(len(array_of_data)) + " paketov.")

        self.send_prepared_packets()



        #msg_P = packet_creator.create_MSG(self.ppSEQ(), message)

        #self.send_packet(msg_P)

        print("Správa úspešne odoslaná.")


        packet_creator.changeInputMode(1)

    def ppSEQ(self):
        self.SEQ_num += 1
        return self.SEQ_num

    def add_filename(self):
        filename = ""
        for c in self.local_path[::-1]:
            if c == '/':
                break
            filename += c

        if self.target_path[-1] == '/':
            return self.target_path + filename[::-1]
        return self.target_path + "/" + filename[::-1]

    def send_file(self):
        size = self.ask_for_size()




        ## prečítanie súboru
        file = open(self.local_path, "r+b")
        read = file.read()
        file.close()


        ## príprava cesty
        array_of_data = self.split_data(self.add_filename(), size)
        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_INF(self.ppSEQ(), one_data))
            # výpočet CRC


        ## príprava súboru
        array_of_data = self.split_data(read, size)
        for one_data in array_of_data[:-1]:
            self.packetsToSend.append(packet_creator.create_PSH(self.ppSEQ(), one_data))
            # výpočet CRC
        self.packetsToSend.append(packet_creator.create_PSH_F(self.ppSEQ(), array_of_data[-1]))
        # výpočet CRC

        print("Odošle sa " + str(len(self.packetsToSend)) + " paketov.")
        self.send_prepared_packets()
        print("Súbor úspešne odoslaný.")

        packet_creator.changeInputMode(1)

    def end_com(self):
        self.stop_keepAlive()
        fin_p = packet_creator.create_FIN(self.ppSEQ())
        packet_creator.sendPacket(fin_p, packet_creator.get_TARGET_addr())

    def stop_keepAlive(self):
        keepAliveStop_p = packet_creator.create_KeepAliveEND(self.ppSEQ())
        self.enabled_keepAlive = False
        self.send_packet(keepAliveStop_p)

    def start_keepAlive(self):
        self.enabled_keepAlive = True
        threading.Thread(target=self.thread_keepAlive, name="t1").start()

    def set_enabled_keepAlive(self, value):
        self.enabled_keepAlive = value

    def exceeded_waiting_for_keepAlive(self, ex_SEQ):
        while self.enabled_keepAlive:
            time.sleep(5.1)

            if ex_SEQ >= self.arrived_SEQ and self.enabled_keepAlive:
                self.keepAlive_arrived = False
                break

            ex_SEQ += 1

    def pp_arrived_SEQ(self):
        self.arrived_SEQ += 1

    #def waiting_for_keepAlive_packet(self):
        #data, addr = packet_creator.waitForPacket()
        ##data, addr = self.sock.recvfrom(1500)
        #self.arrived_SEQ = self.get_SEQ(data)
        #print(str(self.arrived_SEQ))

    def thread_keepAlive(self):
        self.enabled_keepAlive = True
        self.keepAlive_arrived = True
        threading.Timer(0.5, self.exceeded_waiting_for_keepAlive, args=(0, )).start()
        while self.enabled_keepAlive:
            #threading.Thread(target=self.waiting_for_keepAlive_packet).start()
            time.sleep(5)
            if self.enabled_keepAlive:
                if showKeepAlivePackets:
                    print("KeepAlive packet poslaný")
                self.send_packet(packet_creator.create_KeepAlive(self.ppSEQ()))

            if not self.keepAlive_arrived and self.enabled_keepAlive:
                print("\nKomunikácia prerušená!\n")
                break


    def exceeded_waiting_for_SYN_packet(self):
        if inputMode != 1: #prijaty paket
            nACK_p = packet_creator.create_nACK(0)
            self.sock.sendto(nACK_p, packet_creator.get_MY_addr())


    def waiting_for_SYN_packet(self):
        threading.Timer(0.5, self.exceeded_waiting_for_SYN_packet).start()

        data, addr = packet_creator.waitForPacket()

        type = packet_creator.get_type(data)

        if type == 6: #ACK
            #data, addr = self.sock.recvfrom(1500)
            print("\n\nKomunikácia nadviazaná!")
            print("IP adresa prijímateľa: " + addr[0])
            print("Port prijímateľa: " + str(addr[1]) + "\n\n")

            print("Ako si prajete pokračovať:\na) Poslať správu\nb) Poslať súbor\nc) Ukončiť komunikáciu\n")

            packet_creator.changeInputMode(1) #poslanie suboru

            self.start_keepAlive()
            return True
        elif type == 7: #nACK
            print("\n\nKomunikáciu sa nepodarilo nadviazať!\n\nPrajete si znova začať komunikáciu ? (y/n) ", end="")
            return False
        else:
            print("Neznam co še pohubilo")




    def establish_com(self):
        syn_P = packet_creator.create_SYN()

        #self.TARGET_IP = "127.0.0.1"
        #self.TARGET_IP = "192.168.0.183"
        # UDP_IP = "192.168.0.130"
        #self.TARGET_PORT = 5005

        self.TARGET_IP = input("Zadajte IP adresu prijímateľa: ")
        self.TARGET_PORT = int(input("Zadajte port prijímateľa: "))



        packet_creator.send_socket(self.sock)
        packet_creator.set_TARGET_addr(self.TARGET_IP, self.TARGET_PORT)
        #packet_creator.set_MY_addr(addr[0], addr[1])

        self.sock.sendto(syn_P, (self.TARGET_IP, self.TARGET_PORT))
        #self.send_packet(syn_P)

        return self.waiting_for_SYN_packet()










def thread_waiting_for_input():
    global inputMode
    while True:
        s = input()

        if inputMode == 0: #zacat komunikaciu
            if s == "y":
                #receiver.setActiveClass(False)

                if sender.establish_com():
                    threading.Thread(target=receiver.restart_listening).start()


        elif inputMode == 1: #poslat subor

            if s == "a": #sprava
                print("Zadajte správu: ", end="")
                inputMode = 2

            if s == "b": #subor
                print("Zadajte absolútnu cestu k súboru: ", end="")
                inputMode = 3

            if s == "c": #konec
                print("Koneeeeec")
                sender.end_com()

            if s == "k": #stop KeepAlive
                print("KeepAlive stopnute")
                sender.stop_keepAlive()

            #sender.set_enabled_keepAlive(False)  # prestane posielať keepAlive
            #receiver.cancel_waiting()  # prestane očakávať vstup

        elif inputMode == 2: #sprava
            sender.send_message(s)

        elif inputMode == 3: #subor
            sender.set_local_path(s)

            print("Zadajte absolútnu cestu k priečinku, v ktorom sa má uložiť odoslaný súbor: ", end="")
            inputMode = 4

        elif inputMode == 4: #cesta suboru
            sender.set_target_path(s)
            inputMode = 1
            sender.send_file()









showKeepAlivePackets = True

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





