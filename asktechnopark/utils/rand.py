import random
import sys
import traceback
import uuid




def getrandbytes(n_bytes):
    bs = []
    for i in range(n_bytes):
        bs.append(random.getrandbits(8))
    return bytes(source=bs)

def genranduuid():
    return uuid.UUID(bytes=getrandbytes(16))




        
