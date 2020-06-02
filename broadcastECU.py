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
import threadin
import random

bustype = 'socketcan'
channel = 'vcan0'

def periodicData(id, current_anchor_random_number):
    message = ' '.join(current_anchor_random_number[i:i+2] for i in range(0,len(current_anchor_random_number),2))
    message_bytes = bytes.fromhex(message)

    #print("Starting to send a message every 200ms for 2s")
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    #IDb for broadcast
    msg = can.Message(arbitration_id = id, data=message_bytes, is_extended_id=False)
    task = bus.send_periodic(msg, 0.20)
    assert isinstance(task, can.CyclicSendTaskABC)
    task.stop()
    time.sleep(2)

def sendData(id, ciphertext):
    bus = can.interface.Bus(channel=channel, bustype=bustype)

    message = ' '.join(ciphertext[i:i+2] for i in range(0,len(ciphertext),2))
    ciphertext_bytes = bytes.fromhex(message)

    msg = can.Message(arbitration_id=id, data=ciphertext_bytes,is_extended_id=False)
    bus.send(msg)
    #time.sleep(1)

def generateRandomHanchorCanData(id, current_anchor_random_number):
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    can_id_counter = get_random_bytes(1)
    can_id_key = b'thisisjustakeythisisjustakeeyID1'

    length_data = random.randint(0,8)
    random_data = get_random_bytes(length_data)

    ciphertext = generateHanchorCanData(current_anchor_random_number, random_data, can_id_key, can_id_counter)
    ciphertext = sendData()
    msg = can.Message(arbitration_id=id, data=ciphertext,is_extended_id=False)
    task = bus.send_periodic(msg, 0.0)
    assert isinstance(task, can.CyclicSendTaskABC)
    time.sleep(0.1)

def receiveData(id):
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    #Receiving data through the CAN bus
    message = bus.recv()

    #Arbitration IDs that this ECU will filter.
    #Broadcast IDb 0x2aa
    IDs = [0x2aa]
    if(message.arbitration_id in IDs):
        print("Hello daddy")

    #print("This is the message being read:%s", hex(message.arbitration_id)  ) 
    return message


mt = MerkleTools()

def xor(var, key) :
    key = key[:len(var)]
    int_var = int.from_bytes(var, sys.byteorder)
    int_key = int.from_bytes(key, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), sys.byteorder)


def generateHanchorCan(current_anchor_random_number, message, can_id_key, can_id_counter, nonce=0):
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256() ,
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output+can_id_counter).hexdigest().encode()

    length = len(message)#+len(can_id_counter)
    hash_digest = hash_digest[:length]

    data_frame = current_anchor_random_number #+ can_id_counter

    ciphertext = xor(data_frame,hash_digest)
    #mt.add_leaf(message,True)
    #mt.make_tree()
    return ciphertext


def verifyHanchorCan(current_anchor_random_number, ciphertext, can_id_key, can_id_counter, nonce=0):
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output+can_id_counter).hexdigest().encode()
    length = len(ciphertext)
    hash_digest = hash_digest[:length]

    data_frame = xor(ciphertext, hash_digest)
    message = data_frame
    #counter = data_frame[7:8]

    mt.get_merkle_root()
    #Validate the authentication of the message

    return message

    
def generateHanchorCanData(current_anchor_random_number, message, can_id_key, can_id_counter, nonce=0):
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256() ,
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output+can_id_counter).hexdigest().encode()
    #Authentication

    #Encryption
    length = len(message)#+len(can_id_counter)
    hash_digest = hash_digest[:length]

    data_frame = message #+ can_id_counter

    ciphertext = xor(data_frame,hash_digest)
    #mt.add_leaf(message,True)
    #mt.make_tree()
    return ciphertext


def verifyHanchorCanData(current_anchor_random_number, ciphertext, can_id_key, can_id_counter, nonce=0):
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output+can_id_counter).hexdigest().encode()
    length = len(ciphertext)
    hash_digest = hash_digest[:length]

    data_frame = xor(ciphertext, hash_digest)
    message = data_frame[:7]
    #counter = data_frame[7:8]

    mt.get_merkle_root()
    return message


def main1(id, current_anchor_random_number):
    #Generating periodic broadcast of random number using IDb
    print("Im here about to send data.")
    while(True):
        #Define the start of the frame
        print("Sending periodic messages for ")
        sendData(id,"0000000000000000")
        periodicData(id, current_anchor_random_number)
        sendData(id, "1111111111111111")
def main(id, current_anchor_random_number):
    #Generating random hanchor CAN data
    while(True):
        generateRandomHanchorCanData(IDb, current_anchor_random_number)

#message_1 = verifyHanchorCanData(current_anchor_random_number, ciphertext, can_id_key, can_id_counter)
        #print("message: " + str("".join("\\x%02x" % i for i in message))) # display bytes


try:
    current_anchor_random_number = get_random_bytes(8)
    #Define IDb for broadcasting Data:
        #IDB = 0xaaaaaa
        #IDa = 0xaaaaab
    IDb = 0xaaaaaa
    IDa = 0xaaaaab

    thread_1 = threading.Thread(target=main, args=(IDa,current_anchor_random_number,))
    thread_2 = threading.Thread(target=main1, args=(IDb, current_anchor_random_number.hex(),))

    thread_1.start()
    thread_2.start()

        #So it's watchable on the screen.

except:
    print("Error: unable to start thread")

while 1:
    pass

