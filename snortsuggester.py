#!/usr/bin/env python3

import sys
import subprocess

pcap = sys.argv[1]

pcapASlist = []

def pcapconverter(pcap):
	with subprocess.Popen(["tshark", "-r", pcap], stdout=subprocess.PIPE) as proc:
		output = proc.stdout.readlines()
		for line in output:
			stripped_line = line.decode().strip()
			pcapASlist.append(stripped_line)


def main():
	pcapconverter(pcap)
	#print(pcapASlist)
	findSSHtraffic(pcapASlist)

def findSSHtraffic(pcapASlist):
	SSHcounter = 0
	#loop through list
	for line in pcapASlist:
	#split lines on space to ge the fields 
		split_lines = line.split(' ')
		src_ip = split_lines[2]
	#logic destination port 22
		if split_lines[9] == '22' and split_lines[10] == '[SYN]':
			SSHcounter += 1
			if SSHcounter >= 5:
				#print ssh rule suggestion
				print(f"Incoming SSH Handshake from {src_ip}. Suggested SNORT Rule: alert TCP {src_ip} any -> any 22 (msg:'Incoming SSH Handshake')")
				return
	#if true trigger rule suggestion

	#if false continue


# take pcap logfile (output), and turn it into an iterable format for python (each packet is made into a list, once that list
# has been analyzed and parsed, we move to the next list) 


# loop through the list (output) and look for incoming ssh SYN packets from source to DST.PORT 22 ***(for POC, we are
# searching for incoming SSH SYN from any source)***

# Create our if, elif, else logic to analyze results and print out SNORT rule suggestion

# Close out our function








main()
