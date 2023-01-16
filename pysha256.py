class sha256:
    def __init__(self, data: bytes = None, state: bytes = None, count: int = None):
        """
        Construct a new sha256 object.

        To construct a blank sha256 object:
            h = sha256()

        To construct a sha256 object that is the hash of a bytes object:
            h = sha256(b)

        To construct a sha256 object with a predetermined state:
            h = sha256(state=token, count=n)
        """

        self.__state = (
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        )
        self.__buffer = b''
        self.__count = 0

        if data is not None:
            if state is not None:
                raise TypeError(
                    '__init__() requires arguments \'data\' and \'state\' to not be used together'
                )
            if count is not None:
                raise TypeError(
                    '__init__() requires arguments \'data\' and \'count\' to not be used together'
                )

            self.update(data)

        elif state is not None or count is not None:
            if state is None or count is None:
                raise TypeError(
                    '__init__() requires arguments \'state\' and \'count\' to be used together'
                )
            if len(state) != 32:
                raise ValueError(
                    '__init__() requires argument \'state\' to be 32 bytes'
                )

            self.__state = (
                int.from_bytes(state[0:4], 'big'),
                int.from_bytes(state[4:8], 'big'),
                int.from_bytes(state[8:12], 'big'),
                int.from_bytes(state[12:16], 'big'),
                int.from_bytes(state[16:20], 'big'),
                int.from_bytes(state[20:24], 'big'),
                int.from_bytes(state[24:28], 'big'),
                int.from_bytes(state[28:32], 'big')
            )
            self.__count = count

    def update(self, data: bytes):
        """Append `data` to what has been hashed so far."""

        self.__buffer += data
        self.__count += len(data)

        while len(self.__buffer) >= 64:
            block = self.__buffer[:64]
            self.__buffer = self.__buffer[64:]
            self.__state = _compress(block, self.__state)

    def digest(self) -> bytes:
        """Get the digest of what has been hashed so far as a bytes object."""

        buffer = self.__buffer + padding(self.__count)

        state = self.__state
        while len(buffer) >= 64:
            block = buffer[:64]
            buffer = buffer[64:]
            state = _compress(block, state)

        return state[0].to_bytes(4, 'big') + \
            state[1].to_bytes(4, 'big') + \
            state[2].to_bytes(4, 'big') + \
            state[3].to_bytes(4, 'big') + \
            state[4].to_bytes(4, 'big') + \
            state[5].to_bytes(4, 'big') + \
            state[6].to_bytes(4, 'big') + \
            state[7].to_bytes(4, 'big')

    def hexdigest(self) -> str:
        """Get the digest of what has been hashed so far as a hex string."""

        return self.digest().hex()


def _compress(block: bytes, state: tuple[int]) -> bytes:
    extended_block = block + b'\x00' * 192
    w = [
        int.from_bytes(extended_block[i:i+4], 'big')
        for i
        in range(0, len(extended_block), 4)
    ]

    for i in range(16, 64):
        s0 = _rightrotate(w[i-15], 7) ^ \
            _rightrotate(w[i-15], 18) ^ \
            (w[i-15] >> 3)

        s1 = _rightrotate(w[i-2], 17) ^ \
            _rightrotate(w[i-2], 19) ^ \
            (w[i-2] >> 10)

        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff

    a, b, c, d, e, f, g, h = state

    k = (
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    )

    for ki, wi in zip(k, w):
        s1 = _rightrotate(e, 6) ^ \
            _rightrotate(e, 11) ^ \
            _rightrotate(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + s1 + ch + ki + wi) & 0xffffffff
        s0 = _rightrotate(a, 2) ^ \
            _rightrotate(a, 13) ^ \
            _rightrotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xffffffff
        h = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return (
        (a + state[0]) & 0xffffffff,
        (b + state[1]) & 0xffffffff,
        (c + state[2]) & 0xffffffff,
        (d + state[3]) & 0xffffffff,
        (e + state[4]) & 0xffffffff,
        (f + state[5]) & 0xffffffff,
        (g + state[6]) & 0xffffffff,
        (h + state[7]) & 0xffffffff,
    )


def _rightrotate(n: bytes, rotation: int) -> int:
    return (n >> rotation) | (n << (32 - rotation)) & 0xffffffff


def padding(message_bytes: int) -> bytes:
    """Generate the padding that SHA-256 would append to a message with this many bytes."""

    return b'\x80' + \
        b'\x00' * ((55 - message_bytes) % 64) + \
        (message_bytes * 8).to_bytes(8, 'big')
