from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from user import User
import json, os, hashlib, base64

class AS(Protocol):
    def __init__(self, users):
        self.users = users
        self.name = None
        self.state = "GETNAME"

    def connectionMade(self):
        print("\nconnection made to auth")
        # self.transport.write("What's your name?")

    def connectionLost(self, reason):
        # if self.name in self.users:
        #     del self.users[self.name]
        print("\nLost Connection")

    def dataReceived(self, data):
        '''
            expects data in this format
            {
                username: "usrname"
                password: "encrypted_password"
                service: "A"
                nonce: "f6ds51bgfd5"
            }
            and returns
            {
                status: "OK"
                server_auth: "encrypted_password",
                user_shared_key: "shared_key",
                peer_shared_key: "service_shared_key"
            }
        '''

        json_data = json.loads(data)
        print "\nrecieved message: %s" % json_data
        username = json_data['username'].strip()
        requested_username = json_data['service']
        if self.users[username]:
            # import ipdb; ipdb.set_trace()
            user = self.users[username]
            requested_user = self.users[requested_username]
            if self.verify(user, json_data['password']):
                nonce = json_data['nonce']
                status, server_auth, shared_key, service_shared_key = self.generate_success(user, nonce, requested_user)
            else:
                status, server_auth, shared_key, service_shared_key = self.generate_error("Service not found")    # return random strings, confuse the enemy
        else:
            print("\nwe in NOT")
            status, server_auth, shared_key, service_shared_key = self.generate_error("Service not found")# confuse the enemy
        response = json.dumps({
            "status": status,
            "server_auth": server_auth,
            "user_shared_key": shared_key,
            "peer_shared_key": service_shared_key,
            "ttl": 600
        })
        self.transport.write(response)

    def verify(self, user, password):
        plaintext = user.decrypt(password)
        return plaintext == user.password

    def generate_nonce(self, user, nonce):
        plain_response = user.decrypt(nonce) + " welcome %s" % user.name
        return user.encrypt(plain_response)

    def generate_success(self, user, nonce, requested_user):
        shared_key = user.generate_shared_key(requested_user)
        nonce_response = self.generate_nonce(user, nonce)
        print("\nthis is the shared key %s" % shared_key)
        return "OK", nonce_response, user.encrypt(shared_key), requested_user.encrypt(shared_key)

    def generate_error(self, message):
        return message, message, message, message

    # def registerUser(self, data):
    #     json_data = json.loads(data)
    #     self.name = json_data["id"]
    #     response = json.dumps({
    #         'authentication': 'success',
    #         'message': 'Welcome %s' % self.name
    #     })
    #     self.transport.write(response)
    #     self.users[self.name] = self
    #     self.state = "CHAT"

class ASFactory(Factory):
    def __init__(self, users):
        self.users = {
            "bob": users[0],
            "alice": users[1]
        } # maps user names to Chat instances

    def buildProtocol(self, addr):
        return AS(self.users)

# Credentials
ALICE_MASTER_KEY = '\xa4Tyf\x82\xd8=@\xce<\xd2\xa3\x88$`\x81\xceM9t\xa3f\x8a3@\xdc\x8c\x9dnj\xe0\xbd'
BOB_MASTER_KEY = '\xb7d\xfe\xf7\xf3\x86\x87e\x87\x10@C?\x82\x1e\x982\xc5\x85\x0c\xe4\x02\xd0\x1d<\xf6\xc1\xe0i\nTe'


# Initial vector
IV='\xe7\x97Ao\xeb>-@\\\x89! \xc8\x80\x7f\x83'
# Registering users
alice = User(username="alice", password="alice_pwd", master_key=ALICE_MASTER_KEY, IV=IV, public_key=RSA.importKey(open('alice_public_key.der').read().strip().replace('\\n', '\n')))
bob = User(username="bob", password="bob_pwd", master_key=BOB_MASTER_KEY, IV=IV, public_key=RSA.importKey(open('bob_public_key.der').read().strip().replace('\\n', '\n')))

endpoint = TCP4ServerEndpoint(reactor, 3000)
endpoint.listen(ASFactory([bob, alice]))
reactor.run()
