#!/usr/bin/env python

from mrc_hdrs import *
import argparse
import re
import pprint
import pickle
import os
import time


count = 0
def packet_callback(packet):
    data = str(packet.show)
    pattern = "(.*)tos=0x(.*)"
    d = re.search(pattern, data)
    if "tos" in data:
        dd = d.group(2).split(' ')
        dd[0] = int(dd[0], 16)
        global count
        print("Packet Count: {0}".format(count))
        print("###[ IPv4 hdr Info ]###")
        print("ToS    =  {0}".format(int(dd[0])& 0b11111111))
        count = count + 1

    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver", help="Receiver Host Number")
    args = parser.parse_args()
    host_n = args.receiver
    ipv4dstAddr = '10.0.'+str(host_n)+'.'+str(host_n)
    iface = 'eth0'
    print("sniffing on {}".format(iface))
    sniff(filter="ip host "+ipv4dstAddr, iface=iface,
          prn= lambda x:packet_callback(x))

if __name__ == '__main__':
    main()
