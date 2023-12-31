#!/usr/bin/python
# FROM: https://voorloopnul.com/blog/a-python-proxy-in-less-than-100-lines-of-code/
#
# This is a simple port-forward / proxy, written using only the default python
# library. If you want to make a suggestion or fix something you can contact-me
# at voorloop_at_gmail.com
# Distributed over IDC(I Don't Care) license
import socket
import select
import time
import sys
from decode_asn1 import decode
import argparse

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001
CAPTURE_FILE = 'capture.bin'
#forward_to = ('158.117.27.97', 1389)
#forward_to = ('165.89.206.184', 389)
# metaview uat
forward_to = ('165.89.207.119', 389)

#CLIENT_PORT = 392
CLIENT_PORT = 392

def save_data(data):
    f = open(CAPTURE_FILE, 'ab')
    binary_format = bytearray(data)
    f.write(binary_format)
    f.close()

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print (e)
            return False

class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen()

    def main_loop(self, args):
        self.input_list.append(self.server)
        self.args = args
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print (f'{clientaddr}  has connected')
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print ("Can't establish connection with remote server.")
            print (f"Closing connection with client side {clientaddr}")
            clientsock.close()

    def on_close(self):
        print (f"{self.s.getpeername()} has disconnected")
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        #print data
        print(f'on_recv len data {len(data)}')
        decode(data, self.args)
        save_data(data)
        self.channel[self.s].send(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()
    print(f'quiet_output is {args.quiet}')
    print(f'Listening on port: {CLIENT_PORT}')
    print(f'Fowarding to {forward_to[0]}:{forward_to[1]}')
    
    server = TheServer('', CLIENT_PORT)
    try:
        server.main_loop(args)
    except KeyboardInterrupt:
        print ("Ctrl C - Stopping server")
        sys.exit(1)
