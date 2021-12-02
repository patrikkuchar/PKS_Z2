import threading
import socket
import time
import crcmod
import random

class Packet_creator:
    def __init__(self):
        self.SEQ_num = 0
        self.prcOfCorrupted = 0.1
        #http://crcmod.sourceforge.net/crcmod.html
        self.crc_func = crcmod.mkCrcFun(0x10211, rev=False, initCrc=0x1d0f, xorOut=0x0000)

    ## funkcia prehľadá súbor 'config.txt' a podľa neho zmení niektoré parametre
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

    ##swich ako sa bude input spracovávať
    def changeInputMode(self, value):
        global inputMode
        inputMode = value

    ##vytvorí crc a vložím ho ako posledné 2 byty
    def generateCRC(self, fragment):
        crc = self.crc_func(fragment)

        fragment += int.to_bytes((crc >> 8) & 0xff, 1, "big")
        fragment += int.to_bytes(crc & 0xff, 1, "big")

        return fragment

    ##vloží fragment do crc funckie a ak výjde 0 tak dáta nie sú poškodené
    def checkCRC(self, fragment):
        if self.crc_func(fragment) == 0:
            return True
        return False

    ##náhodne si vyberie jeden byte z dátovej časti a zmení ho na iný
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
        body += bytes(data, "utf-8") #data
        return self.generateCRC(body) #vytvorenie CRC kodu

    def create_PSH(self, SEQ, data):
        body = int.to_bytes(2, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        body += data #data
        return self.generateCRC(body) #vytvorenie CRC kodu

    def create_PSH_F(self, SEQ):
        body = int.to_bytes(3, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_MSG(self, SEQ, message):
        body = int.to_bytes(4, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        body += bytes(message, "utf-8") #data
        return self.generateCRC(body) #vytvorenie CRC kodu

    def create_MSG_F(self, SEQ):
        body = int.to_bytes(5, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_ACK(self, SEQ):
        body = int.to_bytes(6, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
        return body

    def create_nACK(self, SEQ):
        body = int.to_bytes(7, 1, "big") #type
        body += int.to_bytes(SEQ, 2, "big") #seq
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

    ##socket, ktorý sa uloží na oboch uzloch po začatí komunikácie
    def send_socket(self, socket):
        self.sck = socket

    ##odosiela pakety pre prijímača aj vysielača
    def sendPacket(self, body, addr):
        if showSentPackets:
            type = self.get_type(body)
            if type < 13 and (((type == 8 or type == 9) and showKeepAlivePackets) or not (type == 8 or type == 9)): ##filter, či sa ma zobrazovať odosielanie paketu
                print("<- " + self.get_nameOf_type(type) + " - SEQ: " + str(self.get_SEQ(body)))
        self.sck.sendto(body, addr)

    ##prijíma pakety pre prijímača aj vysielača
    def waitForPacket(self):
        return self.sck.recvfrom(1500)


class Receiver:
    def __init__(self, port):
        self.message = []
        self.path = []
        self.file = []

        hostname = socket.gethostname()
        self.MY_IP = socket.gethostbyname(hostname)

        ##self.MY_IP = "127.0.0.1" # pre localhost komunikáciu
        self.MY_PORT = port

        self.writeInfo()

        packet_creator.set_enabled_KeepAlive(False)

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

    ##získa dátovu a časť a (ak je to potrebné) dekóduje ju
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
        ## pakety môžu vďaka ARQ prichádzať v rôznom poradí, preto v tejto funkcií vďaka poradiu paketu (SEQ)
        ## sa paket uloží do zoznamu na príslušné miesto
        for i, one_data in enumerate(arr):
            if packet_creator.get_SEQ(data) < packet_creator.get_SEQ(one_data):
                arr.insert(i, data)
                return arr
        arr.append(data)
        return arr

    ## funkcia uloží súbor a vyhodnotí prenos
    def saveData(self, folderPath):
        path = ""
        file = b""

        for part in self.path:
            path += self.getDataFromPacket(part, True)
        for part in self.file:
            file += self.getDataFromPacket(part, False)

        if folderPath[-1] != '/':
            folderPath += "/"

        f = open(folderPath + path, "w+b")
        f.write(file)
        f.close()
        end_time_recvFile = time.time()
        print("Súbor bol úspešne prijatý.")
        print("Veľkosť súboru: " + str(len(file)) + "B")
        print("Počet fragmentov: " + str(len(self.path) + len(self.file)))
        print("Počet dát v jednom fragmente: " + str(len(self.file[0]) - 5))
        print("Čas prenosu súboru: " + str(round(end_time_recvFile - self.start_time_recvFile, 4)) + "s")
        print("Cesta k súboru: '" + folderPath + path + "'")

        self.path = []
        self.file = []

    def send_packet(self, body, addr):
        packet_creator.sendPacket(body, addr)

    ##funkcia sa volá pri tom ako uzol sa stane vysielačom, kde pošle paket sám na seba (aby zrušil while) a znoza ju zavola
    ##to preto aby sa pakety neočakávali na porte, ktorý je určený na začiatku používateľom ale na tom, z ktorého sa poslal paket
    def restart_listening(self):
        self.cancel_waiting(1)
        self.synchronized = True
        self.waiting_for_packet()

    ##fukncia pošle paket sám na seba (aby ukončil while cyklus a program)
    def stop_waiting(self):
        self.activeClass = False
        packet_creator.sendPacket(int.to_bytes(255, 1, "big"), packet_creator.get_MY_addr())

    ## funkcia pošle paket sám na seba (aby ukončil while cyklus)
    def cancel_waiting(self, type):
        self.activeClass = False
        if type == 0:
            packet_creator.sendPacket(int.to_bytes(253, 1, "big"), packet_creator.get_MY_addr())
        if type == 1:
            self.sock.sendto(int.to_bytes(253, 1, "big"), (self.MY_IP, self.MY_PORT))

    def cancel_keepAlive_waiting(self):
        print("\nKomunikácia prerušená! - po " + str(packet_creator.get_thresholdKA()) + " neprijatých KeepAlive paketoch\n")
        self.stop_waiting()

    ## thread čakajúci na keepAlive pakety
    def exceeded_waiting_for_keepAlive(self, SEQ):
        ## po n * m sekundách skontroluje či sa zväčšilo arrived_SEQ číslo (n - čas čakania na keepalive; m - threshold)
        time.sleep((packet_creator.get_timeForKA() + 0.1) * packet_creator.get_thresholdKA())

        if SEQ >= self.arrived_SEQ and packet_creator.enabled_KeepAlive():
            self.cancel_keepAlive_waiting()

    ## thread čakajúci na INF/PSH/MSG pakety
    def exceeded_waiting_for_packet(self, SEQ):
        ## po n * m sekundách skontroluje či sa zväčšilo arrived_SEQ číslo (n - čas čakania na paket; m - threshold)
        SEQ += 1
        time.sleep(packet_creator.get_timeForPacket() * packet_creator.get_thresholdKA())

        if SEQ >= self.arrived_SEQ:
            print("Spojenie prerušené v dôsledku " + str(packet_creator.get_thresholdKA()) + "x neprijatia paketu.")
            self.stop_waiting()
            exit()

    ##v tejto funkcii sa prijíma väčšina paketov (aj vysielača aj prijímača)
    def waiting_for_packet(self):
        self.activeClass = True
        while self.activeClass:
            if self.synchronized:
                ## čakanie na porte uloženom v packet_creator
                ## vysielač - ten z ktorého odosiela
                ## prijímač - ten, ktorý zadal na začiatku používateľ
                data, addr = packet_creator.waitForPacket()
            else:
                data, addr = self.sock.recvfrom(1500)  #čakanie na porte zadanom od používateľa

            type = packet_creator.get_type(data)

            SEQ = packet_creator.get_SEQ(data)

            packet_creator.setSEQ_num(SEQ)

            ##filter či sa má ukazovať prijímanie paketu
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

                print("Ako si prajete pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'e' - Ukončiť komunikáciu\n")

                packet_creator.changeInputMode(1) #poslanie suboru

                self.keepAlive_arrived = False
                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(0, )).start()


            if type == 1 or type == 2 or type == 4: #INF/PSH/MSG

                threading.Thread(target=self.exceeded_waiting_for_packet, args=(self.arrived_SEQ,)).start() #thread čakania na ďalší paket

                if packet_creator.checkCRC(data): #ak je paket nepoškodený
                    ack_P = packet_creator.create_ACK(SEQ)
                    self.send_packet(ack_P, addr) #odošle ack

                    if type == 1:  # INF
                        if len(self.path) == 0: #pridanie prvého údaju do poľa path
                            self.arrived_SEQ = SEQ
                            self.start_time_recvFile = time.time()
                            self.path.append(data)
                        else:
                            self.path = self.insertData(self.path, data)
                            self.arrived_SEQ += 1

                    elif type == 2:  # PSH
                        if len(self.file) == 0:
                            self.file.append(data)  #pridanie prvého údaju do poľa file
                        else:
                            self.file = self.insertData(self.file, data)
                        self.arrived_SEQ += 1

                    elif type == 4:  # sprava
                        if len(self.message) == 0:
                            self.arrived_SEQ = SEQ
                            self.message.append(data) #pridanie prvého údaju do poľa message
                        else:
                            self.message = self.insertData(self.message, data)
                            self.arrived_SEQ += 1

                else: #paket je poškodený - odšlem nACK
                    self.arrived_SEQ += 1
                    nack_p = packet_creator.create_nACK(SEQ)
                    self.send_packet(nack_p, addr)

            elif type == 3: #PSH_F
                self.arrived_SEQ += 10 #fix aby to určite nepadlo
                packet_creator.changeInputMode(4)
                print("Zadajte absolútnu cestu k priečinku, do ktorého sa má súbor uložiť:", end=" ")


            elif type == 5: #MSG_F
                self.arrived_SEQ += 10 #fix aby to určite nepadlo
                print(">> ", end="")
                for part in self.message:
                    print(self.getDataFromPacket(part, True), end="")
                print()
                print("\nAko si prajete pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'e' - Ukončiť komunikáciu\n")

                self.message = []


            elif type == 6: #ACK
                ##freeze aby sa odoslali na začiatku všetky pakety z okna
                if not sender.sentFirtsPackets:
                    time.sleep(0.1)
                sender.pp_arrived_SEQ()
                sender.move_window()

            elif type == 7: #nACK
                ##freeze aby sa odoslali na začiatku všetky pakety z okna
                if not sender.sentFirtsPackets:
                    time.sleep(0.1)
                sender.pp_arrived_SEQ()
                sender.send_again_packet(SEQ)


            elif type == 8: #KeepAlive
                ##odošlem naspať KeepAliveACK a zavolám thread, ktorý kontroluje či dôjde ďalší keepalive
                packet_creator.set_enabled_KeepAlive(True)

                self.arrived_SEQ = SEQ

                self.keepAlive_arrived = True

                ack_P = packet_creator.create_KeepAliveACK(SEQ)
                self.send_packet(ack_P, addr)

                threading.Thread(target=self.exceeded_waiting_for_keepAlive, args=(SEQ, )).start()

            elif type == 9: #keepAlive ACK
                ##v objekte sender zväčším arrived_SEQ, pre potreby zistenia či došiel keepAliveACK
                sender.pp_arrived_SEQ()

            elif type == 10: #keepAlive stop
                packet_creator.set_enabled_KeepAlive(False)

            elif type == 11: #FIN
                print("Komunikácia úspešne ukončená")
                print("Pre ukončenia aplikácie zadajte 'e'")
                break


            elif type == 253: #prerušenie čakania (ukončenie while cyklu)
                break

            elif type == 255: #stopnutie komunikácie
                time.sleep(0.5)
                print("\n\nKomunikácia ukončená!\n")
                print("Prajete si znova začať komunikáciu ? (y/n) ", end="")
                packet_creator.changeInputMode(0)
                break











class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        self.local_path = ""
        self.target_path = ""
        self.file = ""

        ##bindnutie portu a by sa zistilo, z ktorého portu bude vysielač odosielať (pre neskoršie použitie, keď potrebujem poslať paket sám na seba)
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

    ##funkcia zistí či dané SEQ číslo je v poli SEQ čísel, ktoré sa majú poškodiť, ak áno tak sa paket poškodí a odošle
    def send_and_corrupt_packet(self, body):
        if len(self.corrupted) != 0 and self.corrupted[0] == packet_creator.get_SEQ(body):
            self.send_packet(packet_creator.corruptData(body))
            self.corrupted.pop(0)
        else:
            self.send_packet(body)

    ##thread čakajúci na ACK podľa SEQ - arrived_SEQ
    def exceeded_waiting_for_ACK(self, SEQ):
        time.sleep(packet_creator.get_timeForPacket())
        ##po n sekunách kontroluje či došiel ACK (zväčšené arrived_SEQ)

        if SEQ >= self.arrived_SEQ: ##nedošiel packet
            l = len(self.thresholdForPackets)
            m = packet_creator.get_thresholdKA()

            ##funkcia pridáva do poľa SEQ čísla paketov, ktoré nedorazili (veľkosť poľa je maximálne 3 - vtedy sa posledný vypustí)
            if l == m or l == m - 1:
                if l == m:
                    self.thresholdForPackets.pop(0)
                self.thresholdForPackets.append(SEQ)

                equal = True
                for i in range(1, m):
                    if self.thresholdForPackets[i - 1] != self.thresholdForPackets[1]:
                        equal = False
                        break
                ##ak tieto tri SEQ čísla v poli sú rovnaké (3-krát neprišiel jeden paket) - komunikácia sa ukončí
                if equal:
                    self.thresholdForPackets = []
                    print("Spojenie prerušené v dôsledku " + str(packet_creator.get_thresholdKA()) + "x neprijatia paketu do " + str(packet_creator.get_timeForPacket()) + "s")
                    receiver.stop_waiting()

                else:
                    self.send_again_packet(SEQ)

            else:
                self.thresholdForPackets.append(SEQ)
                self.send_again_packet(SEQ)

    def send_again_packet(self, SEQ):
        #zistím ktorý paket treba znova poslať podľa SEQ
        for packet in self.packetsToSend:
            if SEQ == packet_creator.get_SEQ(packet):
                self.send_and_corrupt_packet(packet)
                threading.Thread(target=self.exceeded_waiting_for_ACK, args=(self.arrived_SEQ,)).start()
                break

    ##po príchode ack sa volá táto funkcia, ktorá posunie okno o jeden paket
    def move_window(self):
        ##podmienka zisťuje či je okno na konci poľa paketov na odoslanie (nemá sa kde ďalej posunúť)
        if self.lastIndexInWindow != len(self.packetsToSend) - 1:
            ##nie je na konci - pridáme doň ďalší paket a pošleme ho
            self.lastIndexInWindow += 1
            self.packetsInWindow.append(self.packetsToSend[self.lastIndexInWindow])

            self.send_and_corrupt_packet(self.packetsInWindow[-1])
            threading.Thread(target=self.exceeded_waiting_for_ACK, args=(self.arrived_SEQ,)).start()

        ##odstraníme z okna posledný paket
        self.packetsInWindow.pop(0)

        if len(self.packetsInWindow) == 0: ##všetky pakety odoslané

            if packet_creator.get_type(self.packetsToSend[-1]) == 2: #PSH_F
                ##odošlem final paket, ktorý informuje uzol o ukončení odosielania súboru
                psh_f = packet_creator.create_PSH_F(packet_creator.ppSEQ())
                self.send_packet(psh_f)

                end_time_sendFile = time.time()
                print("Súbor úspešne odoslaný")
                print("Čas odoslania: " + str(round(end_time_sendFile - self.start_time_sendFile, 4)) + "s")

            else:
                ##odošlem final paket, ktorý informuje uzol o ukončení odosielania správy
                msg_f = packet_creator.create_MSG_F(packet_creator.ppSEQ())
                self.send_packet(msg_f)

                print("Správa úspešne odoslaná")


            ##znova spustím keepalive a switchnem do modu na odosielanie
            packet_creator.changeInputMode(-1)
            self.packetsToSend = []
            time.sleep(packet_creator.get_timeForKA()) ##zmrazenie ak sa náhodou správa poslala tak rýchlo, že sa ešte ani nestihol ukončiť keepalive
            print("\nAko si prajete ďalej pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'e' - Ukončiť komunikáciu\n")
            packet_creator.changeInputMode(1)
            self.start_keepAlive()




    ##funkcia odošle pripravené pakety
    def send_prepared_packets(self):

        self.thresholdForPackets = [] ##pole, v ktorom sa ukladajú SEQ čísla paketov, ktorých potvrdzovacie pakety nedorazili

        ##corrupt data
        ##vytvorí za pole SEQ čísel, u ktorých sa pri odosielaní poškodia dáta
        numOfPackets = len(self.packetsToSend)
        numForCorrupt = int(packet_creator.get_prcOfCorrupted() * numOfPackets)
        self.corrupted = []
        for i in range(numForCorrupt):
            self.corrupted.append(packet_creator.get_SEQ(self.packetsToSend[random.randrange(numOfPackets)]))
        self.corrupted.sort()

        ##zmenšenie okna, ak počet paketov na odoslanie je menej ako veľkosť okna
        if len(self.packetsToSend) < self.window:
            win = len(self.packetsToSend)
        else:
            win = self.window

        self.arrived_SEQ = packet_creator.get_SEQ(self.packetsToSend[0]) + (win - 1) #arrived_SEQ začne o posunutie okna (keďže ACK SEQ budú posunuté)

        self.packetsInWindow = []

        #vložia sa pakety do poľa podľa veľskoti okna
        for i in range(win):
            self.packetsInWindow.append(self.packetsToSend[i])

        self.lastIndexInWindow = win - 1

        self.sentFirtsPackets = False #premenná slúži na jemné zmrazenie prichádzajúcich ACK paketov (aby sa stihli poslať všetky pakety)

        #pošlem všetky pakety z okna
        for i, protocol in enumerate(self.packetsInWindow):
            if i % 32 == 0: #pri odosielaní väčšieho počtu paketov to prestane posielať - sleep fix
                time.sleep(0.2)
            self.send_and_corrupt_packet(protocol)
            threading.Thread(target=self.exceeded_waiting_for_ACK, args=(self.arrived_SEQ,)).start()


        self.sentFirtsPackets = True #začiatočné pakety sa odoslali, zmrazenie už nie je potrebné


    ##funkcia žiada input od použivateľa, podľa ktorého sa rozdelia data do skupín podľa veľkosti (inputu)
    def ask_for_size(self):
        while True:
            size = int(input("Zadajte počet bajtov pre dáta jedného fragmentu (1-1467): "))
            if size >= 1 and size <= 1467:
                break
        return size

    ##rozdelenie dát do skupín
    def split_data(self, data, size):
        array_of_data = []
        j = 0
        l = len(data)
        for i in range(size, l+size, size):
            array_of_data.append(data[j:i])
            j = i

        return array_of_data

    ##funkcia odošle správu
    def send_message(self, message):
        self.stop_keepAlive()

        size = self.ask_for_size()

        array_of_data = self.split_data(message, size)

        ##vytvorenie paketov z fragmentov
        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_MSG(packet_creator.ppSEQ(), one_data))

        print("Odošle sa " + str(len(array_of_data)) + " paketov.")

        self.send_prepared_packets()

        packet_creator.changeInputMode(-1) #pri switchnuti -1 input z klávesnice nič nespraví

    ##funkcia pridá k ceste na uloženie súboru názov súboru
    def get_filename(self):
        ##cyklus získa reversnutý názov súboru
        filename = ''
        for c in self.local_path[::-1]:
            if c == '/':
                break
            filename += c

        ##prevráti názov
        return filename[::-1]

    ##odosielanie súboru
    def send_file(self):
        self.stop_keepAlive()

        size = self.ask_for_size()

        ## prečítanie súboru
        file = open(self.local_path, "r+b")
        read = file.read()
        file.close()

        ## príprava cesty
        array_of_data = self.split_data(self.get_filename(), size)
        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_INF(packet_creator.ppSEQ(), one_data))

        ## príprava súboru
        array_of_data = self.split_data(read, size)
        for one_data in array_of_data:
            self.packetsToSend.append(packet_creator.create_PSH(packet_creator.ppSEQ(), one_data))

        print("Odošle sa " + str(len(self.packetsToSend)) + " paketov o veľkosti " + str(len(read)) + "B. ")
        self.start_time_sendFile = time.time() #odmeranie času odosielania
        self.send_prepared_packets()

        packet_creator.changeInputMode(-1) #pri switchnuti -1 input z klávesnice nič nespraví

    ##funkcia stopne keepalive, stopne čakanie na paket a pošle ukončovací paket (oznámenie druhému uzlu)
    def end_com(self):
        self.stop_keepAlive()
        receiver.cancel_waiting(0)
        fin_p = packet_creator.create_FIN(packet_creator.ppSEQ())
        packet_creator.sendPacket(fin_p, packet_creator.get_TARGET_addr())


    ##funkcia oznamí druhému uzlu koniec keepalive a ukončí keepalive
    def stop_keepAlive(self):
        keepAliveStop_p = packet_creator.create_KeepAliveEND(packet_creator.ppSEQ())
        packet_creator.set_enabled_KeepAlive(False)
        #self.enabled_keepAlive = False
        self.send_packet(keepAliveStop_p)

    ##funkcia pripraví premenné na posielanie keepalive a zavolá tento thread
    def start_keepAlive(self):
        self.arrived_SEQ = packet_creator.getSEQ_num()
        packet_creator.set_enabled_KeepAlive(True)
        threading.Thread(target=self.thread_keepAlive, name="t1").start()

    def exceeded_waiting_for_keepAlive(self, ex_SEQ):
        ##funkcia každý n sekúnd inkrementuje lokálnu premennú, ktorú porovnáva s arrived_SEQ (to sa zväčšuje pri prijatí paketu), ak lokálna premenná
        ##"predbehne" arrived_SEQ -> niekoľko potvrdzujúcich paketov neprišlo
        ex_SEQ -= packet_creator.get_thresholdKA() - 1 #aby komunikacia nespadla po prvom neprijatom pakete
        while packet_creator.enabled_KeepAlive():
            time.sleep(packet_creator.get_timeForKA() + 0.1)

            if ex_SEQ >= self.arrived_SEQ and packet_creator.enabled_KeepAlive():
                self.keepAlive_arrived = False
                break

            ex_SEQ += 1

    ##funkcia inkrementuje premennú arrived_SEQ, ktorú používam pri kontrole keepalive_ack alebo ack paketov
    def pp_arrived_SEQ(self):
        self.arrived_SEQ += 1

    ##funkcia každých n sekúnd odosiela keepalive paket, pričom na začiatku po pol sekunde zavolá thread, ktorý kontroluje, či prišli keepalive_ack pakety
    def thread_keepAlive(self):
        packet_creator.set_enabled_KeepAlive(True)
        self.keepAlive_arrived = True
        threading.Timer(0.5, self.exceeded_waiting_for_keepAlive, args=(self.arrived_SEQ, )).start()
        while packet_creator.enabled_KeepAlive():
            time.sleep(packet_creator.get_timeForKA())
            if packet_creator.enabled_KeepAlive():
                self.send_packet(packet_creator.create_KeepAlive(packet_creator.ppSEQ()))

            if not self.keepAlive_arrived and packet_creator.enabled_KeepAlive():
                print("\nKomunikácia prerušená! - po " + str(packet_creator.get_thresholdKA()) + " neprijatých KeepAlive paketoch\n")
                receiver.stop_waiting()
                break


    def exceeded_waiting_for_SYN_packet(self):
        ## ak žiaden paket nebol prijatý, inputMode ostal nezmenený - 0
        if inputMode == 0:
            ## nACK paket na seba
            nACK_p = packet_creator.create_nACK(0)
            self.sock.sendto(nACK_p, packet_creator.get_MY_addr())


    def waiting_for_SYN_packet(self):
        ##po nejakom čase sa zavolá thread, ktorý zistí, že či bol prijatý paket
        threading.Timer(packet_creator.get_timeForPacket(), self.exceeded_waiting_for_SYN_packet).start()


        data, addr = packet_creator.waitForPacket()

        type = packet_creator.get_type(data)

        if type == 6: #ACK - paket prišiel
            print("\n\nKomunikácia nadviazaná!")
            print("IP adresa prijímateľa: " + addr[0])
            print("Port prijímateľa: " + str(addr[1]) + "\n\n")

            print("Ako si prajete pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'e' - Ukončiť komunikáciu\n")

            packet_creator.changeInputMode(1) #switch na mód inputu - "odosielanie"

            self.start_keepAlive() #začne odosielať keepalive
            return True #vráti true - komunikácia nadviazaná
        elif type == 7: #nACK - paket neprišiel, bol odoslaný týmto uzlom, funkciou exceeded_waiting_for_SYN_packet()
            print("\n\nKomunikáciu sa nepodarilo nadviazať!\n\nPrajete si znova začať komunikáciu ? (y/n) ", end="")
            return False #vráti false - komunikáciu sa nepodarilo nadviazať



    ##funkcia začne komunikáciu - vracia True hodnotu ak sa nadviaže komunikácia
    def establish_com(self):
        syn_P = packet_creator.create_SYN()

        self.TARGET_IP = input("Zadajte IP adresu prijímateľa: ")
        self.TARGET_PORT = int(input("Zadajte port prijímateľa: "))

        packet_creator.send_socket(self.sock)
        packet_creator.set_TARGET_addr(self.TARGET_IP, self.TARGET_PORT)

        self.sock.sendto(syn_P, (self.TARGET_IP, self.TARGET_PORT))

        return self.waiting_for_SYN_packet()










def thread_waiting_for_input():
    global inputMode
    while True:
        s = input()

        if inputMode == 0: #zacat komunikaciu
            if s == "y":
                if sender.establish_com():
                    threading.Thread(target=receiver.restart_listening).start()
            elif s == "n":
                ##ukončenie komunikácie - vypnutie očakávania paketu aby sa vypol program
                receiver.cancel_waiting(1)
                exit()


        elif inputMode == 1: #odosielanie

            if s == "m": #sprava
                print("Zadajte správu: ", end="")
                inputMode = 2

            if s == "f": #subor
                print("Zadajte absolútnu cestu k súboru: ", end="")
                inputMode = 3

            if s == "e": #konec
                sender.end_com()
                print("Komunikácia úspešne ukončená")
                break


        elif inputMode == 2: #sprava
            sender.send_message(s)

        elif inputMode == 3: #cesta k suboru
            sender.set_local_path(s)
            sender.send_file()
            inputMode = 1

        elif inputMode == 4: #kde sa ma súbor uložiť
            receiver.saveData(s)
            print("\nAko si prajete pokračovať:\n 'm' - Poslať správu\n 'f' - Poslať súbor\n 'e' - Ukončiť komunikáciu\n")
            #sender.set_target_path(s)
            inputMode = 1
            #sender.send_file()







showKeepAlivePackets = False
showSentPackets = True
showReceivedPackets = True

MY_PORT = int(input("Zadajte port, na ktorom očakávate komunikáciu: "))

packet_creator = Packet_creator() #objekt, v ktorom sú funkcie a premenné o paketoch
receiver = Receiver(MY_PORT) #objekt, ktorý obsahuje funkcionalitu vysielača
sender = Sender() #objekt, ktorý obsahuje funkcionalitu prijímača
packet_creator.refresh_configFile() #načítanie nastavení z 'config.txt'

inputMode = 0 #prepínač na input - začiatok komunikácie

t_input = threading.Thread(target=thread_waiting_for_input)

print("Prajete si začať komunikáciu ? (y/n) ", end="")
t_input.start()

receiver.waiting_for_packet()





