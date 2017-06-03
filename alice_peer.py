from pyp2p.net import *
# from pyp2p.unl import UNL
# from pyp2p.dht_msg import DHT
import time

# Start Alice's direct server
alice = Net(passive_bind="137.158.63.124", passive_port=44444)
alice.start()
alice.bootstrap()
alice.advertise()

while 1:
    for con in alice:
        for reply in con:
            print(reply)
    time.sleep(1)
