from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol
from twisted.internet import reactor, stdio
from twisted.protocols import basic
from twisted.logger import Logger
import json, argparse
from datetime import datetime

parser = argparse.ArgumentParser(description='Should be a p2p service')
parser.add_argument('--sip',
                default='localhost', dest='sip',
                help="the IP Adress you want to connect to, defaults to localhost")
parser.add_argument('--sport',  default='8123',
 help='specifies the port number that the server listens on, defaults to 8123',
 dest='sport')
parser.add_argument('--cport',  default='8124',
    help='specifies the port number that the client connects to, defaults to 8124',
    dest='cport')
parser.add_argument('--ping', action='store_true', dest='ping',
                    help='initiate convo')

args = parser.parse_args()
name = 'Alice'
cmd_connection_made = False
my_client_connected = False

class ChatServerProtocol(Protocol):
    def __init__(self, users):
        self.users = users
        self.name = name
        self.state = "GETNAME"

    def connectionMade(self):
        print("%s %s has connected with %s" % (gettime(), self.name, self.transport.getPeer()))

    def connectionLost(self, reason):
        print("%s Lost Connection" % gettime())
        # if self.name in self.users:
        #     del self.users[self.name]

    def dataReceived(self, data):
        print("%s %s server received data %s" % (gettime(), self.name, data))
        json_data = json.loads(data)
        if self.state == "GETNAME":
            self.registerUser(json_data)
        else:
            self.handleChat(data)

    def registerUser(self, json_data):
        self.state = "CHAT"
        username = json_data['id']
        cport = json_data['port']
        global my_client_connected
        if not my_client_connected:
            startClient()
        response = json.dumps({
            'id': self.name,
            'status': 'pong',
            'port': str(args.sport),
            'message': 'Welcome %s' % username
        })
        self.transport.write(response)
        print("%s Sent data %s" % (gettime(), response))

    def handleChat(self, data):
        json_data = json.loads(data)
        username = json_data['id']
        status = json_data['status']
        if status == 'pong':
            startchat()
        message = json_data['message']
        print("<%s> %s" % (username, message))
        commandLineProtocol.transport.write(">>> ")

class CMDProtocol(basic.LineReceiver):
    from os import linesep as delimiter

    # def connectionMade(self):
    #     self.transport.write('>>> ')

    def lineReceived(self, line):
        client_protocol.send_message_from_cmd(line)
        self.transport.write('>>> ')

class ChatClientProtocol(Protocol):
    def __init__(self):
        self.connectedUser = []

    def ping(self, msg):
        print("%s %s pinging with %s" % (gettime(), name, msg))
        self.transport.write(msg)

    def dataReceived(self, data):
        json_data = json.loads(data)
        username = json_data['id']
        status = json_data['status']
        if status == 'pong':
            reactor.callLater(2, startchat)
        message = json_data['message']
        print("<%s> %s" % (username, message))

    def send_message_from_cmd(self, line):
        response = json.dumps({
            'id': name,
            'status': 'reply',
            'port': str(args.sport),
            'message': line
        })
        self.transport.write(response)


class ChatFactory(Factory):
    def __init__(self, server_protocol):
        self.server_protocol = server_protocol

    def buildProtocol(self, addr):
        return self.server_protocol

def gotProtocol(p):
    json_msg_1 = json.dumps({'id': name, 'status': 'ping', 'port': args.sport})
    print("%s Connected. %s pinging to peer server on: %s" % (gettime(), name, args.cport))
    global my_client_connected
    my_client_connected = True
    p.ping(json_msg_1)

def gettime():
    return datetime.now().strftime("[%H:%M:%S]")

def startchat():
    global cmd_connection_made
    if not cmd_connection_made:
        print("%s -------------Start of Chat------------------" % gettime())
        stdio.StandardIO(commandLineProtocol)
        cmd_connection_made = True

#initialize protocols
server_protocol = ChatServerProtocol({})
client_protocol = ChatClientProtocol()
commandLineProtocol = CMDProtocol()

# start server
print("%s Starting peer server on port: %s" % (gettime(), args.sport))
endpoint = TCP4ServerEndpoint(reactor, int(args.sport))
endpoint.listen(ChatFactory(server_protocol))
print("%s Peer server listening on port: %s" % (gettime(), args.sport))

# start client
def startClient():
    print("%s Connecting to peer server on: %s" % (gettime(), int(args.cport)))
    point = TCP4ClientEndpoint(reactor, args.sip, int(args.cport))
    d = connectProtocol(point, client_protocol)
    d.addCallback(gotProtocol)

if args.ping:
    startClient()

reactor.run()
