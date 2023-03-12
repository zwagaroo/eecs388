#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "eecs388+uniqname+100.00"
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import sys

import base64

def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    #To forge a signature we need to find a value s, such that s^3 = y where y is a malformed signature
    #This value s that we need to find is our forged signature. To do so, first find a malformed signature y, then since s^3 = y,
    #then s = y^(1/3) and we are done. Must make sure s^3 = y < the modulous, call it n.
    #step 1 compute sha256 of the message
    hasher = hashlib.sha256()
    hasher.update(message.encode("utf-8"))
    y = "0001ff003031300d060960864801650304020105000420"
    y += hasher.hexdigest()
    y += "00" * 201
    forged_signature, x = integer_nthroot(int(y, 16), 3) #compute the 3rd root which will act as our signature
    k = bytes_to_base64(integer_to_bytes(forged_signature+1, 256))
    print(k)


if __name__ == '__main__':
    main()
