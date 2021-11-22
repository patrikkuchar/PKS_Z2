import receiver as rcv
import sender as snd
import threading
import keyboard

def thread_waiting_for_input():

    while receiver.receiverInput():
        if keyboard.read_key() == "space":
            s = input("Prajete si začať komunikáciu ?:")
            sender.establish_com()
            break





MY_PORT = int(input("Zadajte port, na ktorom očakávate komunikáciu: "))

receiver = rcv.Receiver(MY_PORT)
sender = snd.Sender()

t1 = threading.Thread(target=thread_waiting_for_input, name="t1")
t2 = threading.Thread(target=receiver.waiting_for_packet, name="t2")

t1.start()
t2.start()


