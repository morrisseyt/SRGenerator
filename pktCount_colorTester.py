#! /usr/bin/env python3

import sys
from scapy.all import *

### below packages used for steps
# from prettytable import PrettyTable
# from collections import Counter

### Read pcap from stdin

data = sys.argv[1]
packets = rdpcap(data)

### Packet counter
count = 0
for packet in packets:
        count +=1

# Printing colored text by creating function using Python's format() method  

def prRed(txt): print("\033[1;31m {}\033[00m".format(txt))  # bold red

prRed(f'This pcap has {count} packets')

# Printing colored text by setting variable to desired ANSI code(s)

YH = '\033[30;43m' # black text, yellow background
R = '\033[1;31m' # bold red text
WB = '\033[1;37;46m' # bold white text on cyan backgroun

print(YH + f'This pcap has {count} packets')

print(R + 'Same count, different color')

print(WB + 'This time in blue')
