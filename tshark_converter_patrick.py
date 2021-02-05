#!/usr/bin/env python3

import sys
import subprocess

# take a pcap file input from the command line

# open that file with tshark

# write the output to a txt file

# print or return that txt file

pcap = sys.argv[1]

pcapASlist= []
def pcapconverter(pcap):
    #output = subprocess.run(["tshark", "-r", pcap], capture_output=True, text=True)
    with subprocess.Popen(["tshark", "-r", pcap], stdout=subprocess.PIPE) as proc:
        output = proc.stdout.readlines() 
        for i in output:
            j = i.decode().strip()
            pcapASlist.append(j)
    #print(txt_file)
    return 



# take pcap logfile (output), and turn it into an iterable format for python (each packet is made into a list, once that list
# has been analyzed and parsed, we move to the next list) 

def pcap_formatting(txt_file):
    #for line in pcap:
    #    print(line)
    for packet in txt_file:
        #print(line)
        fields = packet.split(' ')
        ip_src = fields[2]
        port_src = fields[6]

        print(f'Source IP: {ip_src} and Source Port: {port_src}')

def main():
#   print(pcap)
    txt_file = pcapconverter(pcap)
    #print(pcapASlist)
    pcap_formatting(pcapASlist)

main()
# loop through the list (output) and look for incoming ssh SYN packets from source to DST.PORT 22 ***(for POC, we are
# searching for incoming SSH SYN from any source)***

# Create our if, elif, else logic to analyze results and print out SNORT rule suggestion

# Close out our function

