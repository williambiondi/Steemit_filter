from hashlib import sha256
import base64
from Crypto import Random
from Crypto.Cipher import AES

blocks = 16
def pad(s):
    s = s.encode('utf-8')
    s += bytes( (blocks - len(s) % blocks) * chr(blocks - len(s) % blocks), 'utf-8')
    return s

unpad = lambda s : s[:-ord(s[len(s) - 1:])]

class AESCipher(object):
    def __init__( self, key ):
        self.key = bytes(key, 'utf-8')
 
    def encrypt(self, raw ):
        #raw = raw.encode('utf-8')
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] )).decode('utf-8')
 

