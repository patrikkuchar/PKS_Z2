import receiver as rcv
import sender as snd
import threading
import keyboard

def thread_waiting_for_input_synCom():
    print("Pre začiatok písania stlačte medzerník.\n")
    while receiver.getReceiverInput():
        if keyboard.read_key() == "space":
            s = input("Prajete si začať komunikáciu ? (y/n):")
            if s != "y":
                continue
            receiver.setActiveClass(False)

            sender.establish_com()
            cancel_t2.start()
            break

def thread_waiting_for_input_send():
    print("\nPre začiatok písania stlačte medzerník.\n")

    if keyboard.read_key() == "space":

        receiver.setReceiverInput(True)
        sender.set_enabled_keepAlive(False) #prestane posielať keepAlive
        receiver.cancel_waiting() #prestane očakávať vstup






MY_PORT = int(input("Zadajte port, na ktorom očakávate komunikáciu: "))

receiver = rcv.Receiver(MY_PORT)
sender = snd.Sender()

t1 = threading.Thread(target=thread_waiting_for_input_synCom, name="t1")
t2 = threading.Thread(target=receiver.waiting_for_packet, name="t2")
cancel_t2 = threading.Thread(target=receiver.cancel_waiting, name="cancel_t2")

t1.start()
t2.start()

t2.join()





