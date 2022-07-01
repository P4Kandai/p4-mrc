#!/usr/bin/env python
from mrc_hdrs import *
import socket

from scapy.all import sendp
from scapy.all import Packet
from scapy.all import Ether
from scapy.fields import *
from scapy.all import *

def main():
    detectpkt = Ether(dst='ff:ff:ff:ff:ff:ff',\
                      src=get_if_hwaddr('eth0'))/\
                      Detect(in_time=0,\
                             type=0)
    sendp(detectpkt, iface='eth0')

if __name__ == '__main__':
    main()
