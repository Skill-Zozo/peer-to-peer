from pyp2p.net import *
import time

#Setup Bob's p2p node.
bob = Net(passive_bind="196.24.187.212", passive_port=44445)
bob.start()
bob.bootstrap()
bob.advertise()

#Event loop.
while 1:
    for con in bob:
        con.send_line("test")

    time.sleep(1)
