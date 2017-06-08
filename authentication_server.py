from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
import json

PRIVATE_KEY = ""
KDF =

class User():
    def __init__(self, username, password, private_key):
        self.password = password
        self.name = username
        self.private_key = private_key
        self.state = "offline"
        generate_shared_key();

    def retrieve_shared_key(self):
        return self.shared_key;

    def generate_shared_key(self):
        self.shared_key = KDF.derive(private_key.encode('utf8'))


class AS(Protocol):
    def __init__(self, users):
        self.users = users
        self.name = None
        self.state = "GETNAME"
        self.bob_keys = {
            "private": "",
            "shared": ""
        }
        self.alice_keys = {
            "private": "",
            "shared": ""
        }
        self.kdf =

    def connectionMade(self):
        print("connectionMade")
        self.transport.write("What's your name?")

    def connectionLost(self, reason):
        # if self.name in self.users:
        #     del self.users[self.name]
        print("Lost Connection")

    def dataReceived(self, data):
        '''
            expects data in this format
            {
                username: "usrname"
                password: "encrypted_password"
                service: "A"
            }
            and returns
            {
                status: "OK"
                server_auth: "encrypted_password",
                shared_key: "shared_key",
                service_shared_key: "service_shared_key"
            }
        '''
        print "recieved message"
        json_data = json.loads(data)
        username = json_data['username']
        requested_username = json_data['service']
        if users[username]:
            user = users[username]
            requested_user = users[requested_username]
            if verify(user, json_data['password']):
                status, server_auth, shared_key, service_shared_key = generate_success(username, requested_user)
            else:
                status, server_auth, shared_key, service_shared_key = generate_error("Service not found")    # return random strings, confuse the enemy
        else:
             status, server_auth, shared_key, service_shared_key = generate_error("Service not found")# confuse the enemy
        response = json.dumps({
            "status": status,
            "server_auth": server_auth,
            "shared_key": shared_key,
            "service_shared_key": service_shared_key
        })

        # if self.state == "REGISTERUSER":
        #     self.registerUser(data)
        # else:
        #     self.handleChat(data)
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

class ASFactory(Factory):
    def __init__(self, users):
        self.users = {
            "bob": users[0],
            "alice": users[1]
        } # maps user names to Chat instances

    def buildProtocol(self, addr):
        return AS(self.users)

# Registering users
alice = User(username="alice", password="alice_pwd", private_key="")
bob = User(username="bob", password="bob_pwd", private_key="")

endpoint = TCP4ServerEndpoint(reactor, 8123)
endpoint.listen(ASFactory([bob, alice]))
reactor.run()
