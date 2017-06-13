from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint, connectProtocol
from twisted.internet import reactor, stdio
from twisted.protocols import basic
from twisted.logger import Logger
import json, argparse, base64, os
from datetime import datetime
from Crypto.Cipher import AES
from user import User
from io import FileIO, BufferedWriter, BufferedReader

parser = argparse.ArgumentParser(description='Should be a p2p service')
parser.add_argument('--csip', default='localhost', dest='csip',
 help="the peer IP Address you want to connect to, defaults to localhost")
parser.add_argument('--asip', default='localhost', dest='asip',
 help="the IP Address of the authentication server you want to connect to, defaults to localhost")
parser.add_argument('--sport',  default='8123', dest='sport',
 help='specifies the port number that this peer server listens on, defaults to 8123')
parser.add_argument('--cport',  default='8124', dest='cport',
 help='specifies the port number that this peer client connects to, defaults to 8124')
parser.add_argument('--ping', action='store_true', dest='ping', help='initiate convo')
parser.add_argument('--asport',  default='3000', dest='asport',
 help='specifies the port number of the authentication server, defaults to 3000')

args = parser.parse_args()
name = 'Bob'
cmd_connection_made = False
my_client_connected = False
expected_server_response = base64.b64encode(os.urandom(15))

# chat client
class ChatClientProtocol(Protocol):
    def __init__(self, user):
        self.user = user

    def connectionLost(self, reason):
        commandLineProtocol.transport.write("Connection lost. Press n to reconnect \n>>>")

    def ping(self, msg):
        print("\n%s %s pinging with %s" % (gettime(), name, msg))
        self.transport.write(msg)

    def dataReceived(self, data):
        json_data = json.loads(data)
        username = json_data['id']
        status = json_data['status']
        if status == 'pong':
            reactor.callLater(2, startcmdchat)
        message = json_data['message']
        print("\n<%s> %s" % (username, message))

    def send_message_from_cmd(self, line, status, filename=None):
        response = {
            'id': name,
            'status': status,
            'message': line
        }
        if filename:
            response.update({ "filename": filename})
        encrypted_response = self.user.sign(json.dumps(response))
        self.transport.write(encrypted_response)

def gotChatProtocol(p):
    json_ping_msg = {
        'id': name,
        'status': 'ping',
        'port': user.sign(args.sport),
        'csip': user.sign(args.csip)
    }
    if args.ping:
        json_ping_msg.update({'message': user.retrieve_foreign_key()})
        reactor.callLater(auth_protocol.ttl+1, client_protocol.transport.loseConnection)
    ping = json.dumps(json_ping_msg)
    print("\n%s Connected. %s pinging to peer server on: %s" % (gettime(), name, args.cport))
    global my_client_connected
    my_client_connected = True
    p.ping(ping)

def startCommClient():
    print("\n%s Connecting to peer server on: %s" % (gettime(), int(args.cport)))
    point = TCP4ClientEndpoint(reactor, args.csip, int(args.cport))
    d = connectProtocol(point, client_protocol)
    d.addCallback(gotChatProtocol)
    d.addErrback(ebPrintError)

# chat server
class ChatServerProtocol(Protocol):
    def __init__(self, user):
        self.user = user
        self.name = name
        self.state = "GETNAME"

    def connectionMade(self):
        print("\n%s %s has connected with %s" % (gettime(), self.name, self.transport.getPeer()))

    def connectionLost(self, reason):
        print("\n%s Lost Connection" % gettime())
        self.state = "GETNAME"
        # if self.name in self.users:
        #     del self.users[self.name]

    def dataReceived(self, data):
        print("\n%s %s server received data %s" % (gettime(), self.name, data))
        if self.state == "GETNAME":
            self.registerUser(data)
        else:
            self.handleChat(data)

    def registerUser(self, data):
        self.state = "CHAT"
        json_data = json.loads(data)
        username = json_data['id']
        if not args.ping:
            self.retrieve_and_save_key(json_data['message'])
        args.cport = user.read_message(json_data['port'])
        args.csip = user.read_message(json_data['csip'])
        global my_client_connected
        if not my_client_connected:
            startCommClient()
        response = json.dumps({
            'id': self.name,
            'status': 'pong',
            'message': 'Welcome %s' % username
        })
        self.transport.write(response)
        print("\n%s Sent data %s" % (gettime(), response))

    def handleChat(self, data):
        decrypted_data = self.user.read_message(data)
        json_data = json.loads(decrypted_data)
        username = json_data['id']
        status = json_data['status']
        message = json_data['message']
        if status == 'pong':
            startcmdchat()
        elif status == 'reply':
            print("\n<%s> %s" % (username, message))
        elif status == 'ftp-init':
            original_message = base64.b64decode(message)
            filename = json_data['filename']
            self.buffer = BufferedWriter(FileIO(filename, 'wb'))
            with self.buffer as destination:
                destination.write(original_message)
        elif status == 'ftp-wip':
            original_message = base64.b64decode(message)
            filename = json_data['filename']
            self.buffer = BufferedWriter(FileIO(filename, 'ab'))
            with self.buffer as destination:
                destination.write(original_message)
        commandLineProtocol.transport.write(">>> ")

    def retrieve_and_save_key(self, key):
        shared_key = self.user.decrypt(key)
        self.user.save_shared_key(shared_key)

class ChatFactory(Factory):
    def __init__(self, server_protocol):
        self.server_protocol = server_protocol

    def buildProtocol(self, addr):
        return self.server_protocol

# command line
class CMDProtocol(basic.LineReceiver):
    from os import linesep as delimiter

    def lineReceived(self, line):
        if line.strip().startswith('<send>'):
            filename = line.split("<send>")[-1].strip()
            read_and_encrypt(filename)
        elif line.strip()=='n':
            startAuthClient()
        else:
            client_protocol.send_message_from_cmd(line, "reply")
        self.transport.write('>>> ')

def read_and_encrypt(filename):
    binary_file = ""
    ftp_state = "ftp-init"
    with open(filename, 'rb') as source:
        binary_file = source.read(2048)
        count = 0
        while binary_file:
            json_friendly = base64.b64encode(binary_file)
            reactor.callLater(count, client_protocol.send_message_from_cmd, json_friendly, ftp_state, filename+"transferred")
            binary_file = source.read(2048)
            ftp_state = "ftp-wip"
            count = count + 1
    source.closed

def startcmdchat():
    global cmd_connection_made
    if not cmd_connection_made:
        print("\n%s -------------Start of Chat------------------" % gettime())
        stdio.StandardIO(commandLineProtocol)
        cmd_connection_made = True

# authentication
def gotAuthProtocol(p):
    print("\nafter connect")
    raw_request = json.dumps({
        "username": user.name,
        "password": user.encrypt(user.password),
        "service": "bob",
        "nonce":  user.encrypt(expected_server_response)

    })
    p.transport.write(raw_request)

def startAuthClient():
    print("\n%s Connecting to auth server on: %s" % (gettime(), args.asport))
    point = TCP4ClientEndpoint(reactor, args.asip, int(args.asport))
    d = connectProtocol(point, auth_protocol)
    d.addCallback(gotAuthProtocol)
    d.addErrback(ebPrintError)

def ebPrintError(failure):
    import sys
    sys.stderr.write(str(failure))

class AuthClientProtocol(Protocol):
    def __init__(self, user):
        self.user = user

    def retrieve_user(self):
        return self.user

    def disconnect(self, message):
        print "\n\n%s %s" % (gettime(), message)
        self.transport.loseConnection()

    def dataReceived(self, data):
        print("\n%s auth client received data %s" % (gettime(), data))
        json_data = json.loads(data)
        if set(json_data) != set(["status", "server_auth", "user_shared_key", "peer_shared_key", "ttl"]):
            self.disconnect("Malformed response")
            return

        # authenticate the server on the client
        received_server_response = self.user.decrypt(json_data['server_auth'])
        expected_response = expected_server_response + " welcome %s" % user.name
        if received_server_response != expected_response:
            self.disconnect("Unknown authentication server")
            return

        # shared key distribution
        shared_key = user.decrypt(json_data['user_shared_key'])
        self.user.save_shared_key(shared_key)
        self.user.save_foreign_key(json_data['peer_shared_key'])
        self.ttl = json_data['ttl']
        self.disconnect("Shared key received: %s" % shared_key)
        reactor.callLater(1, startCommClient)


def gettime():
    return datetime.now().strftime("[%H:%M:%S]")

# security
BOB_PRIVATE_KEY = '\xb7d\xfe\xf7\xf3\x86\x87e\x87\x10@C?\x82\x1e\x982\xc5\x85\x0c\xe4\x02\xd0\x1d<\xf6\xc1\xe0i\nTe'
IV='\xe7\x97Ao\xeb>-@\\\x89! \xc8\x80\x7f\x83'
user = User(username="bob", password="bob_pwd", private_key=BOB_PRIVATE_KEY, IV=IV)

#initialize protocols
server_protocol = ChatServerProtocol(user)
client_protocol = ChatClientProtocol(user)
auth_protocol = AuthClientProtocol(user)
commandLineProtocol = CMDProtocol()

# start server
print("\n%s Starting peer server on port: %s" % (gettime(), args.sport))
endpoint = TCP4ServerEndpoint(reactor, int(args.sport))
endpoint.listen(ChatFactory(server_protocol))
print("\n%s Peer server listening on port: %s" % (gettime(), args.sport))

if args.ping:
    startAuthClient()

reactor.run()
