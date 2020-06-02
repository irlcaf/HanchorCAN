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

def sendData(id, ciphertext):
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    #ID specific for this ECU
    msg = can.Message(arbitration_id=0xc0ffee, data=ciphertext,is_extended_id=False)

    bus.send(msg)
    #time.sleep(1)

def generateRandomCanData(id, current_anchor_random_number):
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    can_id_counter = get_random_bytes(1)
    can_id_key = b'thisisjustakeythisisjustakeeyID1'

    length_data = random.randint(0,8)
    random_data = get_random_bytes(length_data)

    #m#essage = ' '.join(random_data[i:i+2] for i in range(0,len(current_anchor_random_number),2))
    #message_bytes = bytes.fromhex(random_data)

    #IDa for normal data.
    ciphertext = generateHanchorCanData(current_anchor_random_number, random_data, can_id_key, can_id_counter)
    msg = can.Message(arbitration_id=0xa0aabb, data=ciphertext,is_extended_id=False)
    task = bus.send_periodic(msg, 0.0)
    assert isinstance(task, can.CyclicSendTaskABC)
    time.sleep(0.1)


def receiveData(id):
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    #Receiving data through the CAN bus
    message = bus.recv() 
    return message

mt = MerkleTools()

def xor(var, key) :
    key = key[:len(var)]
    int_var = int.from_bytes(var, sys.byteorder)
    int_key = int.from_bytes(key, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), sys.byteorder)
    
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
    counter = data_frame[7:8]

    mt.get_merkle_root()
    return message

def main(id, current_anchor_random_number):
    can_id_counter = get_random_bytes(1)
    can_id_key = b'thisisjustakeythisisjustakeeyID1'

    #message = ' '.join(sys.argv[1][i:i+2] for i in range(0,len(sys.argv[1]),2))
    #message = "69081F67FE5C6B36"
    #message_bytes = bytes.fromhex(message)

    #Generating random hanchor CAN data
    while(True):
        generateRandomCanData(1, current_anchor_random_number)
""" 
    current_anchor_random_number = get_random_bytes(64)
    can_id_counter = get_random_bytes(1)
    can_id_key = b'thisisjustakeythisisjustakeeyID1'

    #Random hex message
    message = ' '.join(sys.argv[1][i:i+2] for i in range(0,len(sys.argv[1]),2))
    #message = "69081F67FE5C6B36"
    message_bytes = bytes.fromhex(message)
    ciphertext = generateHanchorCanData(current_anchor_random_number, message_bytes, can_id_key, can_id_counter)


    #To-do:
        #Define ID for the purpose of each ECU.
    sendData(10, ciphertext)

    #Writing the encrypted bytes on an external file.
    with open("temp.txt", "wb") as f:
        f.write(ciphertext)
 """
try:
    current_anchor_random_number = get_random_bytes(8)
    thread_1 = threading.Thread(target=main, args=(0xc0ffee,current_anchor_random_number,))
    #thread_2 = threading.Thread(target=main1, args=(69, current_anchor_random_number.hex(),))
    print("Thread started")
    thread_1.start()
    #thread_2.start()

        #So it's watchable on the screen.

except:
    print("Error: unable to start thread")

while 1:
    pass

#message_1 = verifyHanchorCanData(current_anchor_random_number, ciphertext, can_id_key, can_id_counter)
        #print("message: " + str("".join("\\x%02x" % i for i in message))) # display bytes



