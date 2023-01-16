#!/usr/bin/python3

# Run me like this:
# $ python3 len_ext_attack.py "https://project1.eecs388.org/uniqname/lengthextension/api?token=...."
# or select "Length Extension" from the VS Code debugger

import sys
from urllib.parse import quote
from urllib.parse import quote_from_bytes
from pysha256 import sha256, padding


class URL:
    def __init__(self, url: str):
        # prefix is the slice of the URL from "https://" to "token=", inclusive.
        self.prefix = url[:url.find('=') + 1]
        self.token = url[url.find('=') + 1:url.find('&')]
        # suffix starts at the first "command=" and goes to the end of the URL
        self.suffix = url[url.find('&') + 1:]

    def __str__(self) -> str:
        return f'{self.prefix}{self.token}&{self.suffix}'

    def __repr__(self) -> str:
        return f'{type(self).__name__}({str(self).__repr__()})'


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} URL_TO_EXTEND", file=sys.stderr)
        sys.exit(-1)

    url = URL(sys.argv[1])
    
    padded_message_len = 8+len(url.suffix) + len(padding(8+len(url.suffix)))
    
    h = sha256(
        state=bytes.fromhex(url.token),
        count=padded_message_len,
    )
    h.update('&command=UnlockSafes'.encode())

    url.token = h.hexdigest()
    url.suffix += quote(padding(8+len(url.suffix))) + '&command=UnlockSafes'
    print(url)


"""     print(url) """


if __name__ == '__main__':
    main()

#!/usr/bin/python3

# Run me like this:
# $ python3 len_ext_attack.py "https://project1.eecs388.org/uniqname/lengthextension/api?token=...."
# or select "Length Extension" from the VS Code debugger
""" 
import sys
from urllib.parse import quote
from urllib.parse import quote_from_bytes
from pysha256 import sha256, padding


class URL:
    def __init__(self, url: str):
        # prefix is the slice of the URL from "https://" to "token=", inclusive.
        self.prefix = url[:url.find('=') + 1]
        self.token = url[url.find('=') + 1:url.find('&')]
        # suffix starts at the first "command=" and goes to the end of the URL
        self.suffix = url[url.find('&') + 1:]

    def __str__(self) -> str:
        return f'{self.prefix}{self.token}&{self.suffix}'

    def __repr__(self) -> str:
        return f'{type(self).__name__}({str(self).__repr__()})'


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} URL_TO_EXTEND", file=sys.stderr)
        sys.exit(-1)

    url = URL(sys.argv[1])

    padded_message_len = len(url.__str__()) + len(padding(len(url.__str__())))

    print(url.token)
    print(url.suffix)

    h = sha256(
        state=bytes.fromhex(url.token),
        count=padded_message_len,
    )



    h.update('&command=UnlockSafes'.encode())

    url.token = quote(h.hexdigest())
    url.suffix += quote_from_bytes(padding(len(url.__str__()))) + quote('&command=UnlockSafes')

    print(url)


if __name__ == '__main__':
    main()
 """
