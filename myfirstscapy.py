#!/usr/bin/env python3

import sys
from scapy.all import *

# Read pcap from stdin

data = sys.argv[1]
packets = rdpcap(data)

# Count and print the number of packets in the pcap
# count = 0 
# for packet in packets:
#       count +=1
# print (count)

# print session streams 
# sessions = packets.sessions()
# for session in sessions:
#        print (session)

# returns command that wld generate the packet 
#  for packet in packets:
#        print (packet.command())

# fills a format string with fields values of the packet
# for packet in packets:
#       print (packet.sprintf)

# print (packets.summary)
