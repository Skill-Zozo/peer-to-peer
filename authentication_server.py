from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
import json

class Chat(Protocol):
    def __init__(self, users):
        self.users = users
        self.name = None
        self.state = "GETNAME"

    def connectionMade(self):
        print("connectionMade")
        self.transport.write("What's your name?")

    def connectionLost(self, reason):
        if self.name in self.users:
            del self.users[self.name]

    def dataReceived(self, data):
        print "recieved message"
        if self.state == "GETNAME":
            self.registerUser(data)
        else:
            self.handleChat(data)
        # for line in data.splitlines():
        #     line = line.strip()
        #     if self.state == "GETNAME":
        #         self.registerUser()

    def registerUser(self, data):
        json_data = json.loads(data)
        self.name = json_data["id"]
        response = json.dumps({
            'authentication': 'success',
            'message': 'Welcome %s' % self.name
        })
        self.transport.write(response)
        self.users[self.name] = self
        self.state = "CHAT"

    def handleChat(self, data):
        import ipdb; ipdb.set_trace()
        msg = json.load(data)
        message = "<%s> %s" % (self.name, msg["message"])
        for name, protocol in self.users.iteritems():
            if protocol != self:
                protocol.transport.write(message)

class ChatFactory(Factory):

    def __init__(self):
        self.users = {} # maps user names to Chat instances

    def buildProtocol(self, addr):
        return Chat(self.users)

endpoint = TCP4ServerEndpoint(reactor, 8123)
endpoint.listen(ChatFactory())
reactor.run()
