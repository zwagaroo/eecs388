#!/usr/bin/python3

# Run me like this:
# $ python3 padding_oracle.py "https://project1.eecs388.org/uniqname/paddingoracle/verify" "5a7793d3..."
# or select "Padding Oracle" from the VS Code debugger

import json
import sys
import time
from typing import Union, Dict, List
from Crypto.Hash import HMAC, SHA256

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()

def unpad(message):
    n = message[-1]
    if n < 1 or n > 16 or message[-n:] != bytes([n]*n):
        raise Exception('invalid_padding')
    return message[:-n]


def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
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
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])

    

    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)


    decryptedBytes = bytearray()

    numBlocks = int(len(message)/16)

    for i in range(numBlocks-1, 0 ,-1): # for all i in the range from numblocks-1 to 1
        correctValues = bytearray(message[i*16:(i+1)*16])
        blockToChange = bytearray(message[(i-1)*16: (i)*16])
        originalBlockToDecode = bytearray(message[i*16:(i+1)*16])
        originalBlockToChange = bytearray(message[(i-1)*16: (i)*16])

        #for the last byte, we go through the process of guess all possible things, but if we succeed
        #we change the second to last byte and see if it still works, if so then our guess is right!
        #i.e. it's 0x01 so the orcale only looks at 0x01, but if it does change that means the last byte could not be 0x01 so we keep searching

        for g in range(0, 256):
            blockToChange[-1] = originalBlockToChange[-1] ^ g ^ 1
            result = oracle(oracle_url, [bytes(blockToChange + originalBlockToDecode)])
            if(result[0]["status"] == "invalid_mac"):
                blockToChange[-2] = blockToChange[-2] +1 #change the second to last block's values
                #try again now
                result = oracle(oracle_url, [bytes(blockToChange + originalBlockToDecode)])
                if(result[0]["status"] == "invalid_mac"): 
                    correctValues[-1] = g
                    break
        
        paddingNum = 1
        for j in range(14,-1,-1): #do the rest of the blocks
            paddingNum += 1
            for k in range(j+1, 16):
                blockToChange[k] = originalBlockToChange[k] ^ correctValues[k] ^ paddingNum
            for g in range(0,256):
                blockToChange[j] = originalBlockToChange[j] ^ g ^ paddingNum
                result = oracle(oracle_url, [bytes(blockToChange + originalBlockToDecode)])
                if(result[0]["status"] == "invalid_mac"):
                    correctValues[j] = g
                    break
        
        decryptedBytes = correctValues + decryptedBytes

    plaintext = unpad(decryptedBytes)
    message, mac = plaintext[:-SHA256.digest_size], plaintext[-SHA256.digest_size:]
    decrypted = message.decode("utf-8")
    
    print(decrypted)


if __name__ == '__main__':
    main()