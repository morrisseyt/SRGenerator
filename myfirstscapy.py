! /usr/bin/env python3

import sys
from scapy.all import *

### below packages used for steps 2 - 3
#from prettytable import PrettyTable
#from collections import Counter

### Read pcap from stdin

data = sys.argv[1]
packets = rdpcap(data)

### Check for TCP/IP layer

# for packet in packets:
#	if (packet.haslayer(ICMP)):
#         print(f"ICMP code: {packet.getlayer(ICMP).code}")

### Count packets in pcap

# count = 0
# for packet in packets:
#	count +=1
# print (count)

### Print session streams 

# sessions = packets.sessions()
# for session in sessions:
#	 print (session)

### Returns command that wld generate the packet in question

#  for packet in packets:
#        print (packet.command())

### Fills a format string with fields values of the packet

# for packet in packets:
#	print (packet.sprintf)
# print (packets.summary)


### Step 1: Loop to print IPs in packet

#for packet in packets:
#	if IP in packet:
#		try:
#			print(packet[IP].src)
#		except:
#			pass

### Step 2: Read and append

#srcIP = []
#for packet in packets:
#	if IP in packet:
#		try:
#			srcIP.append(packet[IP].src)
#		except:
#			pass

### Step 3: Count

#count=Counter()
#for ip in srcIP:
#	count[ip] += 1

### Step 4: Table and Print 

#table = PrettyTable(["IP", "Count"])
#for ip, count in count.most_common():
#	table.add_row([ip, count])
#print(table)
