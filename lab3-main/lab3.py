import sys
import socket


try:
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
except (IndexError, ValueError):
    print(f'Usage: {sys.argv[0]} HOST PORT', file=sys.stderr)
    exit(1)

def lab3send(socket, msg):
    totalsent = 0
    while totalsent < 9:
        sent = socket.send(msg[totalsent:])
        if sent == 0:
            return 0
        totalsent = totalsent + sent

def lab3receive(socket):
    chunks = []
    bytes_recd = 0
    while bytes_recd < 9:
        chunk = socket.recv(min(9 - bytes_recd, 4096))
        if chunk == b'':
            return b''
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        #initiate message receiving
        data = lab3receive(sock)
        while data != b'':
            if data[0] == b'Q'[0]:
                int1 = int.from_bytes(data[1:5], 'big')
                int2 = int.from_bytes(data[5:9], 'big')
                answer = int1+int2
                answer = int.to_bytes(answer, 4, 'big')
                sock.sendall(answer)
                data = lab3receive(sock)
            if data[0] == b'S'[0]:
                print(data[1:9])
                data = lab3receive(sock)





if __name__ == '__main__':
    main()
