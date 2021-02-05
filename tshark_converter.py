def pcap_formatting(txt_file):#!/usr/bin/python3 with open (txt_file, 'r') as pcap: for line 
        in pcap:import sys
            print(line)import subprocess
# take a pcap file input from the command line 

# open that file with tshark

# write the output to a txt file

# print or return that txt file

pcap = sys.argv[1]

txt_file = '' 

def pcapconverter(pcap):
    with open("output", "w") as txt_file:
        subprocess.run(["tshark", "-r", pcap],
        stdout=txt_file, check=True)
   
    #print(txt_file)
    return txt_file



# take pcap logfile (output), and turn it into an iterable format for python (each packet is made into a list, once that list
# has been analyzed and parsed, we move to the next list) 

def pcap_formatting(txt_file):
    with open (txt_file, 'r') as pcap:
        for line in pcap:
            print(line)
            


txt_file = pcapconverter(pcap)
print(type(txt_file))
#pcap_formatting(txt_file)
# loop through the list (output) and look for incoming ssh SYN packets from source to DST.PORT 22 ***(for POC, we are
# searching for incoming SSH SYN from any source)***

# Create our if, elif, else logic to analyze results and print out SNORT rule suggestion

# Close out our function

