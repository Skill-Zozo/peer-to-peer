from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
import json

class ChatProtocol(Protocol):
    def sendMessage(self, msg):
        print "sending messagings"
        self.transport.write(msg)

def gotProtocol(p):
    json_msg_1 = json.dumps({'id': 'Bob'})
    json_msg_2 = json.dumps({'id': 'Bob', 'message': 'What it is'})
    p.sendMessage(json_msg_1)
    reactor.callLater(1, p.sendMessage, json_msg_2)
    reactor.callLater(2, p.transport.loseConnection)

chat_prot = ChatProtocol()
point = TCP4ClientEndpoint(reactor, "localhost", 8123)
d = connectProtocol(point, chat_prot)
d.addCallback(gotProtocol)
reactor.run()
