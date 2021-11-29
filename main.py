import threading
import socket
import time
import crcmod
import random

class Packet_creator:
    def __init__(self):
        #http://crcmod.sourceforge.net/crcmod.html
        self.SEQ_num = 0
        self.prcOfCorrupted = 0.1
        self.crc_func = crcmod.mkCrcFun(0x10211, rev=False, initCrc=0x1d0f, xorOut=0x0000)

    def refresh_configFile(self):
        global showSentPackets, showReceivedPackets, showKeepAlivePackets

        file = open("config.txt", "r")

        print("Aktuálne nastavenie zo súboru 'config.txt':")

        self.timeForPacket = float(file.readline().split(';')[1])
        print(" Maximálny čas čakania na potvrdzujúci paket: " + str(self.timeForPacket) + "s")

        self.timeForKeepAlive = float(file.readline().split(';')[1])
        print(" Interval odosielania KeepAlive: " + str(self.timeForKeepAlive) + "s")

        self.thresholdKA = int(file.readline().split(';')[1])
        print(" Threshold KeepAlive: " + str(self.thresholdKA))

        window = file.readline().split(';')[1]
        sender.set_window(int(window))
        print(" Window: " + window[:-1])

        self.prcOfCorrupted = float(file.readline().split(';')[1])
        print(" Koľko paketov sa má poškodiť pred odoslaním: " + str(round(self.prcOfCorrupted * 100, 2)) + "%")

        value = file.readline().split(';')[1]
        showKeepAlivePackets = value[0] == "1"
        if showKeepAlivePackets:
            print(" Ukázať KeepAlive pakety: Áno")
        else:
            print(" Ukázať KeepAlive pakety: Nie")

        value = file.readline().split(';')[1]
        showReceivedPackets = value[0] == "1"
        if showReceivedPackets:
            print(" Ukázať prichádzajúce pakety: Áno")
        else:
            print(" Ukázať prichádzajúce pakety: Nie")


        value = file.readline().split(';')[1]
        showSentPackets = value[0] == "1"
        if showSentPackets:
            print(" Ukázať odosielajúce pakety: Áno\n")
        else:
            print(" Ukázať odosielajúce pakety: Nie\n")

        file.close()

    def get_timeForPacket(self):
        return self.timeForPacket
    def get_timeForKA(self):
        return self.timeForKeepAlive
    def get_thresholdKA(self):
        return self.thresholdKA


    def get_prcOfCorrupted(self):
        return self.prcOfCorrupted

    def set_prcOfCorrupted(self, value):
        self.prcOfCorrupted = value

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
        crc = self.crc_func(fragment)

        fragment += int.to_bytes((crc >> 8) & 0xff, 1, "big")
        fragment += int.to_bytes(crc & 0xff, 1, "big")

        return fragment

    def checkCRC(self, fragment):
        if self.crc_func(fragment) == 0:
            return True
        return False

    def corruptData(self, fragment):
        index = random.randrange(len(fragment)-3) + 3
        return fragment[:index] + int.to_bytes(random.randrange(256), 1, "big") + fragment[index+1:]

    def create_SYN(self):
        body = int.to_bytes(0, 1, "big") #type
        body += int.to_bytes(0, 2, "big") #seq
        return body

    def create_INF(self, SEQ, data):
        body = int.to_bytes(1, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        body += bytes(data, "utf-8")
        return self.generateCRC(body)

    def create_PSH(self, SEQ, data):
        body = int.to_bytes(2, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        body += data
        return self.generateCRC(body)

    def create_PSH_F(self, SEQ):
        body = int.to_bytes(3, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_MSG(self, SEQ, message):
        body = int.to_bytes(4, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        body += bytes(message, "utf-8")
        return self.generateCRC(body)

    def create_MSG_F(self, SEQ):
        body = int.to_bytes(5, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_ACK(self, SEQ):
        body = int.to_bytes(6, 1, "big")
        body += int.to_bytes(SEQ, 2, "big")
        return body

    def create_nACK(self, SEQ):
        body = int.to_bytes(7, 1, "big")
        body += int.to_bytes(SEQ, 2, "big")
        return body

    def create_KeepAlive(self, SEQ):
        body = int.to_bytes(8, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_KeepAliveACK(self, SEQ):
        body = int.to_bytes(9, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_KeepAliveEND(self, SEQ):
        body = int.to_bytes(10, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_FIN(self, SEQ):
        body = int.to_bytes(11, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def get_nameOf_type(self, type):
        types = ["SYN", "INF", "PSH", "PSH_F", "MSG", "MSG_F", "ACK", "nACK", "KeepAlive", "KeepAlive_ACK", "KeepAlive_END", "FIN"]
        return types[type]

    def set_enabled_KeepAlive(self, value):
        self.enabled_KA = value

    def enabled_KeepAlive(self):
        return self.enabled_KA

    def get_type(self, body):
        return body[0]

    def get_SEQ(self, body):
        return int.from_bytes(body[1:3], "big")

    def ppSEQ(self):
        self.SEQ_num += 1
        return self.SEQ_num

    def setSEQ_num(self, value):
        self.SEQ_num = value

    def getSEQ_num(self):
        return self.SEQ_num

    def send_socket(self, socket):
        self.sck = socket

    def sendPacket(self, body, addr):
        if showSentPackets:
            type = self.get_type(body)
            if type < 13 and (((type == 8 or type == 9) and showKeepAlivePackets) or not (type == 8 or type == 9)):
                print("<- " + self.get_nameOf_type(type) + " - SEQ: " + str(self.get_SEQ(body)))
        self.sck.sendto(body, addr)

    def waitForPacket(self):
        return self.sck.recvfrom(1500)


class Receiver:
    def __init__(self, port):
        self.message = []
        self.path = []
        self.file = []

        hostname = socket.gethostname()
        self.MY_IP = socket.gethostbyname(hostname)

        ##self.MY_IP = "127.0.0.1"
        self.MY_PORT = port

        self.writeInfo()


        packet_creator.set_enabled_KeepAlive(False)
        #self.enabled_keepAlive = False

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
            return body[3:-2].decode("utf-8")
        return body[3:-2]


    def getReceiverInput(self):
        return self.receiverInput


    def setReceiverInput(self, value):
        self.receiverInput = value

    def setActiveClass(self, value):
        self.activeClass = value

    def insertData(self, arr, data):
        for i, one_data in enumerate(arr):
            if packet_creator.get_SEQ(data) < packet_creator.get_SEQ(one_data):
                arr.insert(i, data)
                return arr
        arr.append(data)
        return arr

    def saveData(self):
        path = ""
        file = b""

        for part in self.path:
            path += self.getDataFromPacket(part, True)
        for part in self.file:
            file += self.getDataFromPacket(part, False)

        f = open(path, "w+b")
        f.write(file)
        f.close()
        end_time_recvFile = time.time()
        print("Súbor bol úspešne prijatý.")
        print("Veľkosť súboru: " + str(len(file)) + "B")
        print("Počet fragmentov: " + str(len(self.path) + len(self.file)))
        print("Počet dát v jednom fragmente: " + str(len(self.file[0]) - 7))
        print("Čas prenosu súboru: " + str(round(end_time_recvFile - self.start_time_recvFile, 4)) + "s")
        print("Cesta k súboru: '" + path + "'")


        self.path = []
        self.file = []

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

    def exceeded_waiting_for_keepAlive(self, SEQ):

        #time.sleep(5.1)
        time.sleep((packet_creator.get_timeForKA() + 0.1) * packet_creator.get_thresholdKA())

        if SEQ >= self.arrived_SEQ and packet_creator.enabled_KeepAlive():
            self.cancel_keepAlive_waiting()

    def exceeded_waiting_for_packet(self, SEQ):
        #time.sleep(0.5)
        time.sleep(packet_creator.get_timeForPacket())

        if SEQ >= self.arrived_SEQ:
            print("SEQ: " + str(SEQ))
            print("arrived: " + str(self.arrived_SEQ))
            print("Spojenie prerušené v dôsledku neprijatia paketu do " + str(packet_creator.get_timeForPacket()) + "s")
            #self.cancel_waiting()
            exit()


    def waiting_for_packet(self):
        self.activeClass = True
        while self.activeClass:
            if self.synchronized:
                data, addr = packet_creator.waitForPacket()
            else:
                data, addr = self.sock.recvfrom(1500)  # buffer size is 1024 bytes

            type = packet_creator.get_type(data)

            SEQ = packet_creator.get_SEQ(data)

            packet_creator.setSEQ_num(SEQ)

            if showReceivedPackets and type < 13 and (((type == 8 or type == 9) and showKeepAlivePackets) or not (type == 8 or type == 9)):
                print("-> " + packet_creator.get_nameOf_type(type), " - SEQ: " + str(SEQ))

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

                print("Ako si prajete pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'r' - Znova načítať súbor 'config.txt' - načítať zmenu nastavení\n 'e' - Ukončiť komunikáciu\n")

                packet_creator.changeInputMode(1) #poslanie suboru

                self.keepAlive_arrived = False
                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(0, )).start()


            if type == 1 or type == 2 or type == 4:

                threading.Thread(target=self.exceeded_waiting_for_packet, args=(SEQ,)).start()

                if packet_creator.checkCRC(data):
                    ack_P = packet_creator.create_ACK(SEQ)
                    self.send_packet(ack_P, addr)


                    if type == 1:  # INF
                        if len(self.path) == 0:
                            self.arrived_SEQ = SEQ
                            self.start_time_recvFile = time.time()
                            self.path.append(data)
                        else:
                            self.path = self.insertData(self.path, data)
                            self.arrived_SEQ += 1

                        # self.path = self.decodeData(data)
                        # "Paket cesty dorazil")

                        #self.path += self.getDataFromPacket(data, True)


                    elif type == 2:  # PSH
                        # print("Paket dorazil")
                        if len(self.file) == 0:
                            self.file.append(data)
                        else:
                            self.file = self.insertData(self.file, data)

                        self.arrived_SEQ += 1

                        #self.file += self.getDataFromPacket(data, False)


                    elif type == 4:  # sprava
                        # print("Paket dorazil")
                        # crc kontrola
                        if len(self.message) >= 4:
                            time.sleep(60)


                        if len(self.message) == 0:
                            self.arrived_SEQ = SEQ
                            self.message.append(data)
                        else:
                            self.message = self.insertData(self.message, data)
                            self.arrived_SEQ += 1
                        #self.message += self.getDataFromPacket(data, True)

                else:
                    self.arrived_SEQ += 1
                    nack_p = packet_creator.create_nACK(SEQ)
                    self.send_packet(nack_p, addr)

            elif type == 3: #PSH_F
                self.saveData()

            elif type == 5: #MSG_F
                print(">> ", end="")
                for part in self.message:
                    print(self.getDataFromPacket(part, True), end="")
                print()

                self.message = []


            elif type == 6: #ACK
                if not sender.sentFirtsPackets:
                    time.sleep(0.1)
                sender.pp_arrived_SEQ()
                sender.move_window()

            elif type == 7: #nACK
                if not sender.sentFirtsPackets:
                    time.sleep(0.1)
                sender.pp_arrived_SEQ()
                sender.send_again_packet(SEQ)


            elif type == 8: #KeepAlive
                packet_creator.set_enabled_KeepAlive(True)
                #self.enabled_keepAlive = True


                self.arrived_SEQ = SEQ

                self.keepAlive_arrived = True

                ack_P = packet_creator.create_KeepAliveACK(SEQ)
                self.send_packet(ack_P, addr)

                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(SEQ, )).start()

            elif type == 9: #keepAlive ACK
                sender.pp_arrived_SEQ()

            elif type == 10: #keepAlive stop
                packet_creator.set_enabled_KeepAlive(False)
                #self.enabled_keepAlive = False

            elif type == 11: #FIN
                print("Komunikácia úspešne ukončená")
                break





            elif type == 254: #KeepAlive not arrived
                #print("KeepAlive packet nedorazil")
                print("\nKomunikácia prerušená! - kvôli keeepalive\n")
                break

            elif type == 255:
                print("\nKomunikácia prerušená! - kvôli neaktivite\n")











class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP



        self.local_path = ""
        self.target_path = ""
        self.file = ""


        self.sock.bind(('', 0))
        addr = self.sock.getsockname()
        MY_PORT = addr[1]
        hostname = socket.gethostname()
        MY_IP = socket.gethostbyname(hostname)
        packet_creator.set_MY_addr(MY_IP, MY_PORT)

        self.window = 10


        self.packetsToSend = []

    def set_window(self, value):
        self.window = value

    def set_local_path(self, path):
        self.local_path = path

    def set_target_path(self, path):
        self.target_path = path

    def set_TARGET_ADDR(self, addr):
        self.TARGET_IP = addr[0]
        self.TARGET_PORT = addr[1]

    def send_packet(self, body):
        packet_creator.sendPacket(body, packet_creator.get_TARGET_addr())
        #self.sock.sendto(body, (self.TARGET_IP, self.TARGET_PORT))

    def send_and_corrupt_packet(self, body):
        if len(self.corrupted) != 0 and self.corrupted[0] == packet_creator.get_SEQ(body):
            self.send_packet(packet_creator.corruptData(body))
            self.corrupted.pop(0)
        else:
            self.send_packet(body)

    def exceeded_waiting_for_ACK(self, SEQ):
        time.sleep(packet_creator.get_timeForPacket())

        if SEQ >= self.arrived_SEQ: ##nedošiel packet
            self.send_again_packet(SEQ)

    def send_again_packet(self, SEQ):
        #zistím ktorý paket treba znova poslať podľa SEQ

        for packet in self.packetsToSend:
            if SEQ == packet_creator.get_SEQ(packet):
                self.send_and_corrupt_packet(packet)
                threading.Thread(target=self.exceeded_waiting_for_ACK, args=(SEQ,)).start()
                break


    def move_window(self):
        if self.lastIndexInWindow != len(self.packetsToSend) - 1:
            self.lastIndexInWindow += 1
            self.packetsInWindow.append(self.packetsToSend[self.lastIndexInWindow])

            self.send_and_corrupt_packet(self.packetsInWindow[-1])
            threading.Thread(target=self.exceeded_waiting_for_ACK, args=(packet_creator.get_SEQ(self.packetsToSend[-1]),)).start()

        self.packetsInWindow.pop(0)

        if len(self.packetsInWindow) == 0: ##všetky pakety odoslané
            if packet_creator.get_type(self.packetsToSend[-1]) == 3: #PSH_F
                psh_f = packet_creator.create_PSH_F(packet_creator.ppSEQ())
                self.send_packet(psh_f)

                end_time_sendFile = time.time()
                print("Súbor úspešne odoslaný")
                print("Cesta k súboru na uzle prijímača: '" + self.add_filename() + "'")
                print("Čas odoslania: " + str(round(end_time_sendFile - self.start_time_sendFile, 4)) + "s")

            else:
                msg_f = packet_creator.create_MSG_F(packet_creator.ppSEQ())
                self.send_packet(msg_f)

                print("Správa úspešne odoslaná")



            packet_creator.changeInputMode(-1)
            self.packetsToSend = []
            time.sleep(packet_creator.get_timeForKA())
            #prajete si poslať správu ...
            packet_creator.changeInputMode(1)
            self.start_keepAlive()





    def send_prepared_packets(self):

        ##corrupt data
        numOfPackets = len(self.packetsToSend)
        numForCorrupt = int(packet_creator.get_prcOfCorrupted() * numOfPackets)
        self.corrupted = []
        for i in range(numForCorrupt):
            self.corrupted.append(packet_creator.get_SEQ(self.packetsToSend[random.randrange(numOfPackets)]))
        self.corrupted.sort()

        if len(self.packetsToSend) < self.window:
            win = len(self.packetsToSend)
        else:
            win = self.window

        print(self.corrupted)
        print("VEĽKOSŤ OKNA JE - " + str(win))

        self.arrived_SEQ = packet_creator.get_SEQ(self.packetsToSend[0])

        self.packetsInWindow = []


        for i in range(win):
            self.packetsInWindow.append(self.packetsToSend[i])

        self.lastIndexInWindow = win - 1

        self.sentFirtsPackets = False

        #pošlem všetky pakety z okna
        for i, protocol in enumerate(self.packetsInWindow):
            if i % 32 == 0:
                time.sleep(0.2)
            self.send_and_corrupt_packet(protocol)
            threading.Thread(target=self.exceeded_waiting_for_ACK, args=(packet_creator.get_SEQ(protocol),)).start()


        self.sentFirtsPackets = True



    def ask_for_size(self):
        while True:
            size = int(input("Zadajte počet bajtov pre dáta jedného fragmentu (1-1467): "))
            if size >= 1 and size <= 1467:
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
        self.stop_keepAlive()

        size = self.ask_for_size()

        array_of_data = self.split_data(message, size)

        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_MSG(packet_creator.ppSEQ(), one_data))
            #výpočet CRC

        #corruption of data
        #self.packetsToSend[-1] = packet_creator.corruptData(self.packetsToSend[-1])

        print("Odošle sa " + str(len(array_of_data)) + " paketov.")

        self.send_prepared_packets()



        #msg_P = packet_creator.create_MSG(self.ppSEQ(), message)

        #self.send_packet(msg_P)

        #print("Správa úspešne odoslaná.")


        packet_creator.changeInputMode(-1) #off


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
        self.stop_keepAlive()

        size = self.ask_for_size()

        ## prečítanie súboru
        file = open(self.local_path, "r+b")
        read = file.read()
        file.close()


        ## príprava cesty
        array_of_data = self.split_data(self.add_filename(), size)
        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_INF(packet_creator.ppSEQ(), one_data))
            # výpočet CRC


        ## príprava súboru
        array_of_data = self.split_data(read, size)
        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_PSH(packet_creator.ppSEQ(), one_data))
            # výpočet CRC

        print("Odošle sa " + str(len(self.packetsToSend)) + " paketov o veľkosti " + str(len(read)) + "B. ")
        self.start_time_sendFile = time.time()
        self.send_prepared_packets()
        #print("Súbor úspešne odoslaný.")

        packet_creator.changeInputMode(-1) #off

    def end_com(self):
        self.stop_keepAlive()
        fin_p = packet_creator.create_FIN(packet_creator.ppSEQ())
        packet_creator.sendPacket(fin_p, packet_creator.get_TARGET_addr())
        #vypnuť WHILE ČAKANIA NA PAKET MORE

    def stop_keepAlive(self):
        keepAliveStop_p = packet_creator.create_KeepAliveEND(packet_creator.ppSEQ())
        packet_creator.set_enabled_KeepAlive(False)
        #self.enabled_keepAlive = False
        self.send_packet(keepAliveStop_p)

    def start_keepAlive(self):
        self.arrived_SEQ = packet_creator.getSEQ_num()
        packet_creator.set_enabled_KeepAlive(True)
        #self.enabled_keepAlive = True
        threading.Thread(target=self.thread_keepAlive, name="t1").start()

    def exceeded_waiting_for_keepAlive(self, ex_SEQ):
        while packet_creator.enabled_KeepAlive():
            #time.sleep(5.1)
            time.sleep((packet_creator.get_timeForKA() + 0.1) * packet_creator.get_thresholdKA())

            if ex_SEQ >= self.arrived_SEQ and packet_creator.enabled_KeepAlive():
                self.keepAlive_arrived = False
                break

            ex_SEQ += 1

    def pp_arrived_SEQ(self):
        self.arrived_SEQ += 1


    def thread_keepAlive(self):
        packet_creator.set_enabled_KeepAlive(True)
        #self.enabled_keepAlive = True
        self.keepAlive_arrived = True
        threading.Timer(0.5, self.exceeded_waiting_for_keepAlive, args=(self.arrived_SEQ, )).start()
        while packet_creator.enabled_KeepAlive():
            #threading.Thread(target=self.waiting_for_keepAlive_packet).start()
            time.sleep(packet_creator.get_timeForKA())
            if packet_creator.enabled_KeepAlive():
                self.send_packet(packet_creator.create_KeepAlive(packet_creator.ppSEQ()))

            if not self.keepAlive_arrived and packet_creator.enabled_KeepAlive():
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

            print("Ako si prajete pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'r' - Znova načítať súbor 'config.txt' - načítať zmenu nastavení\n 'e' - Ukončiť komunikáciu\n")

            packet_creator.changeInputMode(1) #poslanie suboru

            self.start_keepAlive()
            return True
        elif type == 7: #nACK
            print("\n\nKomunikáciu sa nepodarilo nadviazať!\n\nPrajete si znova začať komunikáciu ? (y/n) ", end="")
            return False




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

            if s == "m": #sprava
                print("Zadajte správu: ", end="")
                inputMode = 2

            if s == "f": #subor
                print("Zadajte absolútnu cestu k súboru: ", end="")
                inputMode = 3

            if s == "e": #konec
                print("Koneeeeec")
                sender.end_com()
                exit()

            if s == "r": #refresh file
                print("Súbor 'config.txt' sa znova načítal\n")
                sender.stop_keepAlive()
                time.sleep(0.5)
                packet_creator.refresh_configFile()
                sender.start_keepAlive()

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





#C:/PKS_na_poslanie/test.png
#C:/PKS_vystup



showKeepAlivePackets = False
showSentPackets = True
showReceivedPackets = True

MY_PORT = int(input("Zadajte port, na ktorom očakávate komunikáciu: "))

packet_creator = Packet_creator()
receiver = Receiver(MY_PORT)#rcv.Receiver(MY_PORT)
sender = Sender()#snd.Sender()
packet_creator.refresh_configFile()

inputMode = 0

t_input = threading.Thread(target=thread_waiting_for_input)
#t2 = threading.Thread(target=receiver.waiting_for_packet)
cancel_t2 = threading.Thread(target=receiver.cancel_waiting)

print("Prajete si začať komunikáciu ? (y/n) ", end="")
#t2.start()
t_input.start()

receiver.waiting_for_packet()





