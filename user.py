from Crypto.Cipher import AES
from datetime import datetime, timedelta
import os, hashlib, base64

class User():
    def __init__(self, username, password, master_key, IV, public_key):
        self.password = password
        self.name = username
        self.master_key = master_key
        self.iv = IV
        self.public_key = public_key
        self.state = "offline"

    def retrieve_shared_key(self):
        return self.shared_key;

    def retrieve_foreign_key(self):
        if not self.foreign_key:
            "No foreign_key"
        return self.foreign_key;

    def encrypt(self, message):
        encryption_suite = AES.new(self.master_key, AES.MODE_CFB, self.iv)
        return base64.b64encode(encryption_suite.encrypt(message))

    def decrypt(self, message):
        decryption_suite = AES.new(self.master_key, AES.MODE_CFB, self.iv)
        return decryption_suite.decrypt(base64.b64decode(message))

    def save_shared_key(self, key, ttl):
        self.ttl = datetime.now() + timedelta(seconds=ttl)
        print "\nSession key expires on %s" % self.ttl
        self.shared_key = key

    def sign(self, message):
        if not self.shared_key:
            print "No known shared key"
            return "This should be an error"
        encryption_suite = AES.new(self.shared_key, AES.MODE_CFB, self.iv)
        return base64.b64encode(encryption_suite.encrypt(message))

    def read_message(self, message):
        if not self.shared_key:
            print "No known shared key"
            return "This should be an error"
        elif datetime.now() > self.ttl:
            return
        decryption_suite = AES.new(self.shared_key, AES.MODE_CFB, self.iv)
        return decryption_suite.decrypt(base64.b64decode(message))

    def generate_shared_key(self, other_user):
        initial_vector = self.master_key + os.urandom(12) + other_user.master_key
        shared_key = hashlib.sha256(initial_vector).digest()
        # print "shared key: %s" % shared_key
        return shared_key

    def save_foreign_key(self, foreign_key):
        self.foreign_key = foreign_key

    # def signature(self):
    #     if self.name == 'Bob':
    #         return
    #     elif self.name == 'Alice':
    #         return 'Q\x89\xb9\xc5\x00\xa5\xb9\xf2o\x06\x08\x03\xb5g\x9d'
    #     else:
    #         print("user unknown by authentication server")
