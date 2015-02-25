#    Copyright (C) 2011-2014 University of Southampton
#    Copyright (C) 2011-2014 Daniel Alexander Smith
#    Copyright (C) 2011-2014 Max Van Kleek
#    Copyright (C) 2011-2014 Nigel R. Shadbolt
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License, version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


# some from http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
 
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import logging


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

## Symmetric Key Classes/Functions

class AESCipher:
    def __init__( self, key ):
        # TODO check that a SHA256 hash of the key is a good way to use AES
        h = SHA256.new()
        h.update(key)
        self.key = h.digest()

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


def encrypt(plaintext, password):
    """ Encrypt a plaintext using a password. """
    aes = AESCipher(password)
    return aes.encrypt(plaintext)


def decrypt(cyphertext, password):
    """ Decrypt some cyphertext using a password. """
    aes = AESCipher(password)
    return aes.decrypt(cyphertext)


## PKI Classes/Functions

import Crypto.Random.OSRNG.posix
import Crypto.PublicKey.RSA
import Crypto.Hash.SHA512

def sha512_hash(src):
    h = Crypto.Hash.SHA512.new()
    h.update(src)
    return h.hexdigest()


# Use a key size of 3072, recommended from http://en.wikipedia.org/wiki/Key_size / http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/key-size.htm
def generate_rsa_keypair(size):
    """ Generate a new public and private key pair (strings) of specified size. """
    logging.debug("Generating a new {0}-bit RSA key, this might take a second...".format(size))

    PRNG = Crypto.Random.OSRNG.posix.new().read
    key = Crypto.PublicKey.RSA.generate(size, PRNG)

    public_key = key.publickey().exportKey()
    private_key = key.exportKey()

    # generate a SHA512 hash of the public key to identify it
    public_hash = sha512_hash(public_key)

    return {"public": public_key, "private": private_key, "public-hash": public_hash}

def load_key(key):
    """ Load a key from a string into a RSA key object. """
    if type(key) == type("") or type(key) == type(u""):
        return Crypto.PublicKey.RSA.importKey(key)
    else:
        return key

def rsa_encrypt(key, message):
    """ Use a public key (RSA object loaded using the load_key function above) to encrypt a message into a string. """
    return base64.encodestring(key.encrypt(message, None)[0])

def rsa_decrypt(key, ciphertext):
    """ Use a private key (RSA object loaded using the load_key function above) to decrypt a message into the original string. """
    return key.decrypt(base64.decodestring(ciphertext))

