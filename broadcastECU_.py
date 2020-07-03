from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256
from merkletools import MerkleTools
import time
import sys
from itertools import cycle
import can
import os
import threading
import random

bustype = 'socketcan'
channel = 'vcan0'
mt_sending = MerkleTools()
mt_receiving = MerkleTools()

def xor(var, key):
    """
        - ** var ** *bit_string* : First input of the xor operation
        - ** key ** *bit_string* : Second input of the xor operation
    """
    key = key[:len(var)]
    int_var = int.from_bytes(var, sys.byteorder)
    int_key = int.from_bytes(key, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), sys.byteorder)

def encryption(current_anchor_random_number, message, can_id_key, can_id_counter, nonce=0):
    """
        - ** current_anchor_random_number ** *bytes* : Anchor random number being broadcasted through the bus
        - ** message ** *bytes* : data being encrypted in the form of bytes.
        - ** can_id_key ** *bit_string* : bit string key, length of 32, 64, 128 bits.
        - ** can_id_counter ** *bytes* : Counter
        - ** nonce ** *number* : Cryptographically (NO USE)

        Returns the encrypted message in form of bytes.
    """

    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256() ,
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    #rint("Encryption derivation key:", kdf_output)
    hash_digest = sha256(kdf_output).hexdigest().encode()

    length = len(message)#+len(can_id_counter)
    hash_digest = hash_digest[:length]

    data_frame = message #+ can_id_counter

    ciphertext = xor(data_frame,hash_digest)

    return ciphertext

def decryption(current_anchor_random_number, ciphertext, can_id_key, can_id_counter, nonce=0):
    """
        - ** current_anchor_random_number ** *bytes* : Anchor random number being broadcasted through the bus
        - ** ciphertext ** *bytes* : data being decrypted in the form of bytes.
        - ** can_id_key ** *bit_string* : bit string key, length of 32, 64, 128 bits.
        - ** can_id_counter ** *bytes* : Counter
        - ** nonce ** *number* : Cryptographically (NO USE)

        Returns the decrypted ciphertext in form of bytes.
    """
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output).hexdigest().encode()
    length = len(ciphertext)
    hash_digest = hash_digest[:length]

    data_frame = xor(ciphertext, hash_digest)
    message = data_frame

    return message

def generateHanchor(current_anchor_random_number, can_id_key, can_id_counter, nonce=0):
    """
        Generates the anchor frame mentioned by Lin et. al
        - ** current_anchor_random_number ** *bytes* : Anchor random number being broadcasted through the bus
        - ** can_id_key ** *bit_string* : bit string key, length of 32, 64, 128 bits.
        - ** can_id_counter ** *bytes* : Counter
        - ** nonce ** *number* : Cryptographically (NO USE)

        Returns the decrypted ciphertext in form of bytes.
    """
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256() ,
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output).hexdigest().encode()

    length = len(current_anchor_random_number)#+len(can_id_counter)
    hash_digest = hash_digest[:length]

    data_frame = current_anchor_random_number #+ can_id_counter

    ciphertext = xor(data_frame,hash_digest)

    return ciphertext

def verifyHanchor(current_anchor_random_number, can_id_key, can_id_counter, nonce=0):
    """
        Verifies the anchor frame mentioned by Lin et. al
        - ** current_anchor_random_number ** *bytes* : Anchor random number being broadcasted through the bus
        - ** can_id_key ** *bit_string* : bit string key, length of 32, 64, 128 bits.
        - ** can_id_counter ** *bytes* : Counter
        - ** nonce ** *number* : Cryptographically (NO USE)

        Returns the decrypted ciphertext in form of bytes.
    """
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output).hexdigest().encode()
    length = len(current_anchor_random_number)
    hash_digest = hash_digest[:length]

    data_frame = xor(current_anchor_random_number, hash_digest)
    message = data_frame

    return message

def sendData(id, ciphertext, singleFrame):
    """
        Sends single data frames through the CAN bus.
        - ** id ** *bytes* : ID key identifying the message in the bus.
        - ** ciphertext ** *bit_string* : ciphertext being send through the CAN bus
    """
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    message = can.Message(arbitration_id=id, data=ciphertext, is_extended_id=False)
    if (singleFrame):
        bus.send(message)
    else:
        if (hex(message.arbitration_id) == "0x2ab" and mt_sending.get_leaf_count != 0):
            mt_sending.make_tree()
            mt_s = mt_sending.get_merkle_root()
            mt_sending.reset_tree()
            msg = can.Message(arbitration_id=0x2ac, data = bytes(str(mt_s).encode())[:16])
            bus.send(msg)
            print("Merkle tree root hash, sending: %s",mt_s)
        else:
            mt_sending.add_leaf(message.data.hex())
        bus.send(message)

def periodicData(id, current_anchor_random_number):
    """
        Sends periodic data frames through the CAN bus.
        - ** id ** *bytes* : ID key identifying the message in the bus.
        - ** ciphertext ** *bit_string* : ciphertext being send through the CAN bus
    """
    bus = can.interface.Bus(channel=channel, bustype=bustype)

    msg = can.Message(arbitration_id=id, data=current_anchor_random_number, is_extended_id=False)
    task = bus.send_periodic(msg, 0.20)
    assert isinstance(task, can.CyclicSendTaskABC)
    task.stop()
    time.sleep(2)

def randomData(id, current_anchor_random_number):
    """
        Generate periodic random data frames through the CAN bus, calls the sending function to send data frames created through the bus.
        - ** id ** *bytes* : ID key identifying the message in the bus.
        - ** current_anchor_random_number ** *bit_string* : current anchor random number that was being broadcasted through the bus
    """
    while(True):
        #Not the best idea to implement the separation between data. 
        #Should be used with the periodic broadcast
        initial_data = "00000000"
        sendData(0x2ab,bytes(initial_data.encode()),False)

        for i in range(0,10):
            can_id_counter = get_random_bytes(1)
            can_id_key = b'thisisjustakeythisisjustakeeyID1'

            length_data = random.randint(0,8)
            random_data = get_random_bytes(length_data)
            #print("Unencrypted message from broadcast ECU: %s", random_data.hex())
            ciphertext = encryption(current_anchor_random_number, random_data, can_id_key, can_id_counter)
            #print("Encrypted message from broadcast ECU: %s", ciphertext.hex())
            sendData(id, ciphertext,False)
            time.sleep(1)

def periodicBroadcast(id, current_anchor_random_number):
    while(True):
        periodicData(id, current_anchor_random_number)
    
def merkleMonitor(id):
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    mt = MerkleTools()
    for message in bus:
        #If the broadcast number is detected, calculate all the root hashes.
        if(hex(message.arbitration_id) == "0x3ab"):
            mt.make_tree()
            mt_r = mt.get_merkle_root()
            mt.reset_tree()
            print("Merkle tree root hash, receiving from %s: %s" %(hex(id), mt_r))
        elif(hex(message.arbitration_id) == hex(id)):
            mt.add_leaf(message.data.hex())
        
        
            

try:
        current_anchor_random_number = get_random_bytes(8)
        current_anchor_random_number = b'\xfd\xf2\xcdQO\x1b\xa6\x06'
        IDa = 0x2aa
        IDb = 0x2ab

        IDc = 0x3aa

        thread_1 = threading.Thread(target=randomData, args=(IDa, current_anchor_random_number,))
        #thread_2 = threading.Thread(target=periodicBroadcast, args=(IDb, current_anchor_random_number,))
        #thread_3 = threading.Thread(target=receiveData, args=(IDa, current_anchor_random_number,))
        thread_4 = threading.Thread(target=merkleMonitor, args=(IDc,))

        thread_1.start()
        #thread_2.start()
        #thread_3.start()
        thread_4.start()

except:  
    print("Error: Unable to start thread.")
while 1: 
    pass  