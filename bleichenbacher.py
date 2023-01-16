#!/usr/bin/python3

# Run me like this:
# $ python3 bleichenbacher.py "eecs388+uniqname+100.00"
# or select "Bleichenbacher" from the VS Code debugger

from roots import *

import hashlib
import sys


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} MESSAGE", file=sys.stderr)
        sys.exit(-1)
    message = sys.argv[1]

    #
    # TODO: Forge a signature
    #

    forged_signature = 0
    print(bytes_to_base64(integer_to_bytes(forged_signature, 256)))


if __name__ == '__main__':
    main()
