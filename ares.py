import requests, base64, random, json, time, subprocess
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from enum import Enum

import os

class response_e(Enum):
    VALID = 0
    INVALID = 1
    HWID = 2
    EXPIRED = 3
    BANNED = 4

class secure_module_ctx:
    data = []
    key = 0

    def __init__(self, data, key) -> None:
        self.data = data
        self.key = key

    def decrypt(self):
        temp = []
        for byte in self.data:
            temp.append(byte ^ self.key)

        return temp

class session_ctx:
    client_public_key = None
    client_private_key = None
    server_public_key = None
    server_public_array = [77, 73, 73, 67, 73, 84, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 103, 52, 65, 77, 73, 73, 67, 67, 81, 75, 67, 65, 103, 66, 56, 81, 66, 116, 116, 82, 110, 88, 70, 112, 106, 67, 57, 101, 67, 121, 108, 74, 80, 72, 53, 84, 75, 77, 78, 65, 81, 80, 48, 122, 76, 116, 118, 107, 74, 108, 90, 109, 68, 90, 103, 90, 77, 80, 82, 74, 82, 51, 118, 87, 68, 80, 111, 119, 87, 48, 104, 103, 57, 81, 77, 113, 119, 79, 106, 54, 101, 112, 75, 66, 75, 102, 50, 108, 55, 73, 88, 81, 84, 99, 119, 74, 102, 97, 47, 119, 80, 84, 80, 52, 69, 110, 74, 73, 73, 66, 119, 48, 86, 114, 111, 51, 43, 47, 119, 118, 90, 49, 72, 80, 80, 47, 73, 107, 108, 74, 68, 69, 104, 57, 87, 119, 54, 69, 84, 57, 121, 54, 54, 121, 111, 67, 48, 49, 116, 68, 84, 76, 74, 65, 84, 67, 54, 50, 103, 104, 79, 112, 82, 49, 70, 89, 69, 49, 116, 71, 75, 114, 117, 71, 79, 47, 71, 104, 54, 76, 106, 84, 84, 106, 84, 53, 85, 77, 122, 120, 106, 122, 107, 43, 83, 77, 109, 118, 73, 74, 67, 68, 105, 119, 57, 73, 117, 75, 85, 48, 85, 100, 104, 78, 78, 77, 70, 86, 73, 74, 110, 106, 85, 81, 71, 52, 48, 74, 121, 80, 66, 53, 99, 81, 118, 80, 76, 70, 103, 100, 73, 81, 50, 82, 98, 77, 90, 118, 82, 77, 66, 113, 66, 70, 117, 104, 43, 108, 55, 87, 54, 120, 52, 101, 85, 103, 121, 54, 54, 53, 69, 98, 84, 102, 66, 101, 118, 70, 89, 102, 115, 50, 71, 73, 103, 113, 50, 51, 66, 69, 110, 97, 47, 98, 100, 118, 97, 98, 117, 89, 120, 87, 78, 99, 65, 55, 48, 112, 49, 50, 106, 73, 52, 75, 102, 68, 66, 53, 100, 51, 74, 115, 48, 121, 111, 69, 113, 66, 102, 70, 83, 72, 115, 89, 56, 116, 84, 106, 119, 88, 113, 113, 117, 55, 121, 74, 103, 74, 120, 78, 70, 56, 117, 85, 70, 47, 109, 88, 77, 112, 119, 116, 122, 51, 97, 78, 97, 71, 47, 98, 88, 118, 82, 77, 78, 101, 84, 52, 101, 120, 75, 84, 52, 97, 72, 78, 99, 88, 119, 97, 85, 115, 116, 68, 120, 105, 99, 115, 103, 78, 65, 84, 103, 114, 54, 115, 49, 48, 55, 68, 78, 78, 78, 50, 87, 77, 103, 65, 68, 56, 56, 122, 86, 112, 69, 122, 109, 85, 70, 118, 51, 74, 107, 118, 89, 49, 88, 84, 76, 98, 102, 104, 67, 79, 114, 86, 111, 120, 89, 112, 87, 67, 43, 120, 118, 65, 69, 49, 71, 81, 104, 68, 50, 75, 65, 100, 97, 105, 83, 48, 72, 75, 55, 72, 122, 47, 115, 111, 117, 121, 101, 73, 48, 103, 120, 119, 117, 65, 78, 120, 110, 100, 103, 105, 113, 104, 52, 82, 57, 69, 119, 113, 76, 113, 68, 109, 121, 48, 77, 84, 102, 101, 119, 107, 66, 80, 81, 104, 108, 84, 98, 69, 65, 116, 79, 106, 108, 113, 75, 99, 115, 119, 97, 71, 121, 109, 70, 65, 117, 49, 121, 85, 120, 88, 87, 78, 80, 78, 107, 87, 107, 66, 117, 84, 56, 120, 57, 53, 76, 55, 83, 52, 83, 118, 121, 79, 81, 109, 74, 110, 88, 49, 106, 113, 108, 105, 85, 99, 117, 56, 43, 108, 72, 98, 114, 65, 78, 121, 119, 82, 86, 120, 72, 100, 86, 52, 77, 117, 100, 75, 110, 108, 85, 102, 70, 110, 107, 48, 76, 72, 121, 73, 69, 51, 52, 107, 53, 68, 118, 56, 117, 106, 84, 99, 54, 54, 74, 83, 120, 82, 117, 99, 108, 86, 81, 105, 86, 84, 109, 117, 51, 83, 90, 67, 104, 66, 56, 99, 69, 115, 101, 87, 86, 85, 75, 119, 43, 88, 71, 56, 102, 112, 83, 47, 117, 82, 101, 87, 97, 97, 52, 100, 110, 43, 105, 81, 102, 51, 76, 110, 88, 81, 76, 73, 100, 66, 99, 50, 88, 51, 90, 106, 80, 74, 120, 69, 81, 73, 68, 65, 81, 65, 66]
    server_signature = 62463
    app_id = ""

    authenticated = False
    init = False

    app_data = {}
    license_data = {}
    session_id = ""

    def encrypt_text(self, text, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        unencoded = cipher.encrypt(text.encode('ascii'))
        return base64.b64encode(unencoded).decode()

    def get_app(self):
        if not self.authenticated:
            raise Exception("Not authenticated!")

        return self.app_data

    def get_license(self):
        if not self.authenticated:
            raise Exception("Not authenticated!")

        return self.license_data

    def decrypt_text(self, encoded, private_key):
        decoded = base64.b64decode(encoded)
        cipher = PKCS1_OAEP.new(private_key)
        unencoded = cipher.decrypt(decoded)
        return str(unencoded, encoding='ascii')

    def __init__(self, app_array) -> None:
        for byte in app_array:
            self.app_id += chr(byte ^ self.server_signature)

        server_public_key_temp = ""
        signature = 0
        for byte in self.server_public_array:
            signature += byte
            server_public_key_temp += chr(byte)

        if signature != self.server_signature:
            return

        client_key = random.randint(0, 99999999)
    
        
        server_public_key_temp = f'-----BEGIN PUBLIC KEY-----\n{server_public_key_temp}\n-----END PUBLIC KEY-----'

        self.server_public_key = RSA.import_key(server_public_key_temp)

        key_pair = RSA.generate(4096)

        self.client_public_key = key_pair.public_key()
        self.client_private_key = key_pair

        raw_export = str(self.client_public_key.export_key('PEM')).split('b\'')[1].split('\\n-----')[0].split('KEY-----\\n')[1].replace('\\n', '\n')

        array = []
        for byte in raw_export.encode('ascii'):
            array.append(byte ^ client_key)

        hash = SHA256.new()
        hash.update(str(subprocess.check_output('wmic bios get serialnumber')).split('\\r\\n')[1].strip('\\r').strip().encode('ascii'))

        request_data = {}

        request_data[self.encrypt_text("hwid", self.server_public_key)] = self.encrypt_text(str(hash.hexdigest()), self.server_public_key)
        request_data[self.encrypt_text("system_time", self.server_public_key)] = self.encrypt_text(str(int(time.time())), self.server_public_key)
        request_data[self.encrypt_text("client_key", self.server_public_key)] = self.encrypt_text(str(client_key), self.server_public_key)
        request_data[self.encrypt_text("app", self.server_public_key)] = self.encrypt_text(self.app_id, self.server_public_key)
        request_data[self.encrypt_text("client_public_array", self.server_public_key)] = json.dumps({
            "data": array
        })
        
        connect = requests.post('http://client-api.ares.lol/api/standard/connect', json=request_data).json()

        decrypted_body = {}

        for key in connect.keys():
            decrypted_body[self.decrypt_text(key, self.client_private_key)] = self.decrypt_text(connect[key], self.client_private_key)

        self.session_id = decrypted_body['session']    
        self.app_data = json.loads(decrypted_body['app'])

        self.init = True

    def authenticate(self, license) -> response_e:
        if not self.init:
            raise Exception("Not initialized!")

        request_data = {}

        request_data[self.encrypt_text("session", self.server_public_key)] = self.encrypt_text(self.session_id, self.server_public_key)
        request_data[self.encrypt_text("app", self.server_public_key)] = self.encrypt_text(self.app_data['id'], self.server_public_key)
        request_data[self.encrypt_text("license", self.server_public_key)] = self.encrypt_text(license, self.server_public_key)
        
        connect = requests.post('http://client-api.ares.lol/api/standard/vector', json=request_data).json()

        decrypted_body = {}

        for key in connect.keys():
            decrypted_body[self.decrypt_text(key, self.client_private_key)] = self.decrypt_text(connect[key], self.client_private_key)

        if decrypted_body['authenticated'] == 'false':
            if decrypted_body['reason'] == 'expired':
                return response_e.EXPIRED

            if decrypted_body['reason'] == 'hwid':
                return response_e.HWID

            if decrypted_body['reason'] == 'banned':
                return response_e.BANNED

            return response_e.INVALID


        self.authenticated = True

        self.license_data = {
            'id': license,
            'app': self.get_app(),
            'hwid': decrypted_body['hwid'],
            'expiry': decrypted_body['expiry'],
            'lastLogin': decrypted_body['lastLogin'],
            'created_on': decrypted_body['created_on'],
            'duration': decrypted_body['duration'],
            'status': decrypted_body['status'],
            'ip': decrypted_body['ip'],
        }
        
        return response_e.VALID

    def variable(self, name):
        if not self.authenticated:
            raise Exception("Not authenticated!")

        request_data = {}

        request_data[self.encrypt_text("session", self.server_public_key)] = self.encrypt_text(self.session_id, self.server_public_key)
        request_data[self.encrypt_text("app", self.server_public_key)] = self.encrypt_text(self.app_data['id'], self.server_public_key)
        request_data[self.encrypt_text("name", self.server_public_key)] = self.encrypt_text(name, self.server_public_key)
        
        connect = requests.post('http://client-api.ares.lol/api/standard/variable', json=request_data).json()

        decrypted_body = {}

        for key in connect.keys():
            decrypted_body[self.decrypt_text(key, self.client_private_key)] = self.decrypt_text(connect[key], self.client_private_key)

        return decrypted_body['content']

    def module(self, id) -> secure_module_ctx:
        if not self.authenticated:
            raise Exception("Not authenticated!")

        request_data = {}

        request_data[self.encrypt_text("session", self.server_public_key)] = self.encrypt_text(self.session_id, self.server_public_key)
        request_data[self.encrypt_text("app", self.server_public_key)] = self.encrypt_text(self.app_data['id'], self.server_public_key)
        request_data[self.encrypt_text("module", self.server_public_key)] = self.encrypt_text(id, self.server_public_key)
        
        connect = requests.post('http://client-api.ares.lol/api/standard/module', json=request_data).json()

        decrypted_body = {}

        image = []

        for key in connect.keys():
            header = self.decrypt_text(key, self.client_private_key)

            if 'array' in header:
                if 'fake' not in header:
                    image = connect[key]
            else:
                decrypted_body[self.decrypt_text(key, self.client_private_key)] = self.decrypt_text(connect[key], self.client_private_key)
        
        key = int(decrypted_body['key'])

        image.reverse()

        return secure_module_ctx(image, key)