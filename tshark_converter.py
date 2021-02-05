#!/usr/bin/python3

import sys
import subprocess
# take a pcap file input from the command line 

# open that file with tshark

# write the output to .txt file

# print or return that .txt file

pcap = sys.argv[1]

def pcapconverter(pcap):
    with open("output", "w") as output:
        subprocess.run(["tshark", "-r", pcap],
        stdout=output, check=True)
   
    print(output)

pcapconverter(pcap)
