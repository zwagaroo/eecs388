#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "https://project1.eecs388.org/uniqname/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Union, Dict, List
from testoracle import *
from Crypto.Hash import HMAC, SHA256

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            print({"message": [m.hex() for m in messages]})
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue


def main():
    """     if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr) """

    decryptedBytes = bytearray()

    message = bytes.fromhex("c1e4cd25201cfe41a96dc4009f31f00621344ef6a044ae7112f27faaa1a8fd1ae742da04c3e3d74a059fd259e2edf22d944c4770efa00c71d103da79a39e2ed9");
    numBlocks = int(len(message)/16) #first block is the iv
    for i in range(numBlocks-1, 0, -1):
        blockToDecode = bytearray(message[i*16:(i+1)*16])
        blockToChange = bytearray(message[(i-1)*16: (i)*16])
        originalBlockToChange = blockToChange #this doesn't change
        originalBlockToDecode = blockToDecode

        paddingnum = 0 # this tells us how much padding we need
        for j in range(15, -1, -1):
            paddingnum += 1
            for k in range(j+1, 16):
                blockToChange[k] = originalBlockToChange[k] ^ blockToDecode[k] ^ paddingnum  
            for g in range(0,256):
                blockToChange[j] = originalBlockToChange[j] ^ g ^ paddingnum
 #block to decode holds the correct plaintext value at that location
                key = bytes.fromhex("12345443344334344334433223456787")
                mackey = bytes.fromhex("1234543223456787")
                try:
                    decryptThenVerify(blockToChange+originalBlockToDecode,key, mackey)
                except Exception as e:
                    if(str(e) == "invalid_mac"):
                        print(e);
                        break;

                """ result = oracle(oracle_url, [bytes(blockToChange + originalBlockToDecode)])
                if(result[0]["status"] == "invalid_mac"):
                    blockToDecode[j] = g
                    break """
        decryptedBytes = blockToDecode + decryptedBytes

    

    decrypted = decryptedBytes.decode("ascii")
    print(decrypted)


if __name__ == '__main__':
    main()
