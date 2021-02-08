#!/usr/bin/env python3

import sys
import subprocess

pcap = sys.argv[1]

stored_rules = []
pcapASlist = []

def pcapconverter(pcap):
	with subprocess.Popen(["tshark", "-r", pcap], stdout=subprocess.PIPE) as proc:
		output = proc.stdout.readlines()
		for line in output:
			stripped_line = line.decode().strip()
			pcapASlist.append(stripped_line)


def main():
	pcapconverter(pcap)
	#findSSHtraffic(pcapASlist)
	findSSHbruteforce(pcapASlist)
	print_summary()
	

def store_rule(str):
#	print(str)
	if str in stored_rules:
		return
	else:
		stored_rules.append(str)
		return


def print_summary():
	for i in stored_rules:
		print(i)


def findSSHtraffic(pcapASlist):
	SSHcounter = 0

	#loop through list

	for line in pcapASlist:

	#split lines on space to ge the fields 

		split_lines = line.split()
		src_ip = split_lines[2]

	#logic destination port 22

		if split_lines[9] == '22' and split_lines[10] == '[SYN]':
			SSHcounter += 1

	#if true trigger rule suggestion

			if SSHcounter >= 5:

				#print ssh rule suggestion

				print(f"Incoming SSH Handshake from {src_ip}. Suggested SNORT Rule: alert TCP {src_ip} any -> any 22 (msg:'Incoming SSH Handshake')")
				return


def findSSHbruteforce(pcapASlist):
	ip_tracker = {}

	#loop through list

	for line in pcapASlist:

	#split lines on space to ge the fields 

		split_lines = line.split()
		src_ip = split_lines[2]
		dst_ip = split_lines[4]
		timestamp = split_lines[1]

		#logic destination port 22

		if len(split_lines) <= 9:
			continue
		elif split_lines[9] == '22' and split_lines[10] == '[SYN]':
			if src_ip in ip_tracker:
				if dst_ip in ip_tracker[src_ip]:

					#logic to compare current timestamp to [timestamp is last position ]
					#current logic checks for 10 syn packets in a 25 second time frame

					interval = float(timestamp) - float(ip_tracker[src_ip][dst_ip][-1])
					if interval < 25:
						ip_tracker[src_ip][dst_ip].append(timestamp)

					#if time between is greater than 60 seconds, overwrite the list of timestamps with new timestamp 

						if len(ip_tracker[src_ip][dst_ip]) > 10:
							#print(f"[+] Potential SSH Brute Force Dectected. Suggested snort rule: alert TCP {src_ip} any -> {dst_ip} 22 (msg:'Potential SSH Brute Force')")
							rule = f"[+] Potential SSH Brute Force Dectected. Suggested snort rule: alert TCP {src_ip} any -> {dst_ip} 22 (msg:'Potential SSH Brute Force')"
							store_rule(rule)
					else:
						ip_tracker[src_ip][dst_ip] = [timestamp]
					
				#elif time between is less than 25 seconds, add timestamp to list of timestamps

				else:
					ip_tracker[src_ip][dst_ip] = [timestamp]

			else:
				ip_tracker[src_ip] = {dst_ip : [timestamp]}

		#elif split_lines[9] == '21' and split_lines[10] == '[SYN]'









#	print(emptydictionary)
	#dictionary logic- if src ip is in dictionary increase count, else add to dicationary with value of 1 
	#if true trigger rule suggestion
                                #print ssh rule suggestion
		#print(f"Incoming SSH Handshake from {src_ip}. Suggested SNORT Rule: alert TCP {src_ip} any -> any 22 (msg:'Incoming SSH Handshake')")


# take pcap logfile (output), and turn it into an iterable format for python (each packet is made into a list, once that list
# has been analyzed and parsed, we move to the next list) 


# loop through the list (output) and look for incoming ssh SYN packets from source to DST.PORT 22 ***(for POC, we are
# searching for incoming SSH SYN from any source)***

# Create our if, elif, else logic to analyze results and print out SNORT rule suggestion

# Close out our function








main()
