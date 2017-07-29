from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from uuid import uuid4
import json
import pdb

class Greeter(Protocol):
    def sendMessage(self, msg):
        self.transport.write("message %s\n" % msg)

def gotProtocol(p):
    print "we ouchea"
    p.sendMessage()

# factory = MyFactory()
#client side
point = TCP4ClientEndpoint(reactor,"localhost" , 5222)
d = connectProtocol(point, Greeter())
d.addCallback(gotProtocol)
reactor.run()
