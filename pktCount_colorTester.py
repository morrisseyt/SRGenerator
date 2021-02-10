#! /usr/bin/env python3

# import sys
# from scapy.all import *

### below packages used for steps
# from prettytable import PrettyTable
# from collections import Counter

### Read pcap from stdin

# data = sys.argv[1]
# packets = rdpcap(data)

### Packet counter
# count = 0
# for packet in packets:
#        count +=1

# Printing colored text by setting variable to desired ANSI code(s)

BR = '\033[1;31m' # bold red text
BW = '\033[1;37m' # bold white text
BB = '\033[1;34m' # bold blue text
BG = '\033[1;32m' # bold green
BY = '\033[1;33m' # bold yellow

# YH = '\033[30;43m' # black text, yellow background
# WB = '\033[1;37;46m' # bold white text on cyan backgroun

print(BR + 'Sample bold red text')
print(BW + 'Same bold white text')
print(BB + 'Sample bold blue')
print(BG + 'Sample bold green')
print(BY + 'Sample bold yellow')

