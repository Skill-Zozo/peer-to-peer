from Crypto.Cipher import AES
import os, hashlib, base64

class User():
    def __init__(self, username, password, private_key, IV):
        self.password = password
        self.name = username
        self.private_key = private_key
        self.iv = IV
        self.state = "offline"

    def retrieve_shared_key(self):
        return self.shared_key;

    def retrieve_foreign_key(self):
        if not self.foreign_key:
            "No foreign_key"
        return self.foreign_key;

    def encrypt(self, message):
        encryption_suite = AES.new(self.private_key, AES.MODE_CFB, self.iv)
        return base64.b64encode(encryption_suite.encrypt(message))

    def decrypt(self, message):
        decryption_suite = AES.new(self.private_key, AES.MODE_CFB, self.iv)
        return decryption_suite.decrypt(base64.b64decode(message))

    def save_shared_key(self, key):
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
        decryption_suite = AES.new(self.shared_key, AES.MODE_CFB, self.iv)
        return decryption_suite.decrypt(base64.b64decode(message))

    def generate_shared_key(self, other_user):
        initial_vector = self.private_key + os.urandom(12) + other_user.private_key
        shared_key = hashlib.sha256(initial_vector).digest()
        print "shared key: %s" % shared_key
        return shared_key

    def save_foreign_key(self, foreign_key):
        self.foreign_key = foreign_key
