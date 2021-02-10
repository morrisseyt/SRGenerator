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
	findbruteforce(pcapASlist)
	findscan(pcapASlist)
	print_summary()

def findscan(pcapASlist):
	IPtracker = {}
	synsweep_ips = []
	portscan_ips = []
	for line in pcapASlist:
		split_lines = line.split()

		#below logic filters out packets with less than 10 fields,
		#packets where destPORT is greater than 10000,
		#packets where index 10 is not a [SYN] flag.

		if len(split_lines) <= 10:
			continue
		if split_lines[8] != '\N{RIGHTWARDS ARROW}':
			continue
		if int(split_lines[9]) > 10000:  #review with team
			continue
		if split_lines[10] != '[SYN]':
			continue
		src_ip = split_lines[2]
		dst_ip = split_lines[4]
		dst_port = split_lines[9]
		packet = split_lines[0]

		try:
			dst_port = int(split_lines[9])
		except:
			continue

		if dst_port > 1000: #review with team
			continue
		if src_ip in IPtracker:
			if dst_ip in IPtracker[src_ip]:
				if dst_port in IPtracker[src_ip][dst_ip]:
					continue
				else:
					IPtracker[src_ip][dst_ip].append(dst_port)

					if len(IPtracker[src_ip][dst_ip]) > 5:
						portscan_ip = [src_ip, dst_ip]

						#below logic checks to see if current sourceIP and destIP have been logged as triggering a rule.
						#similar logic is seen for each code that has the potential to trigger a rule.

						if portscan_ip not in portscan_ips:
							rule = ['MultiplePortScan', packet, src_ip, dst_ip, 'any']
							portscan_ips.append(portscan_ip) #adds srcIP and dstIP to a 'dupe checking' list
							stored_rules.append(rule) #adds rule to list to be used when printing the summary
			else:
				IPtracker[src_ip][dst_ip] = [dst_port]
				if len(IPtracker[src_ip]) >= 3:
					synsweep_ip = [src_ip, dst_ip]
					if synsweep_ip not in synsweep_ips:
						rule = ['SynSweep', packet, src_ip, dst_ip, 'any']
						synsweep_ips.append(synsweep_ip)
						stored_rules.append(rule)
		else:
			IPtracker[src_ip] = {dst_ip:[dst_port]}

def print_summary():
	#for i in stored_rules:
	#	print(i)
	print(stored_rules)

# function currently not in proudction---------
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
#------------------------------------------------

def findbruteforce(pcapASlist):
	ssh_tracker = {}
	ftp_tracker = {}
	ssh_ips = []
	ftp_ips = []

	#loop through list

	for line in pcapASlist:

	#split lines on space to ge the fields 

		split_lines = line.split()
		src_ip = split_lines[2]
		dst_ip = split_lines[4]
		timestamp = split_lines[1]
		packet = split_lines[0]

		#logic destination port 22

		if len(split_lines) <= 9:
			continue
		elif split_lines[9] == '22' and split_lines[10] == '[SYN]':
			if src_ip in ssh_tracker:
				if dst_ip in ssh_tracker[src_ip]:

					#logic to compare current timestamp to [timestamp is last position ]
					#current logic checks for 10 syn packets in a 25 second time frame

					interval = float(timestamp) - float(ssh_tracker[src_ip][dst_ip][-1])
					if interval < 25:
						ssh_tracker[src_ip][dst_ip].append(timestamp)
						#elif time between is less than 25 seconds, add timestamp to list of timestamps


						if len(ssh_tracker[src_ip][dst_ip]) > 10:
							ssh_ip = [src_ip, dst_ip]
							if ssh_ip not in ssh_ips:
								rule = ["sshBruteForce", packet, src_ip, dst_ip, 22]
								ssh_ips.append(ssh_ip)
								store_rule(rule)
					else:
						ssh_tracker[src_ip][dst_ip] = [timestamp]
						#above line overwrites timestamps for src_ip and dst_ip combo if the interval is more than 25 seconds
				else:
					ssh_tracker[src_ip][dst_ip] = [timestamp]
			else:
				ssh_tracker[src_ip] = {dst_ip : [timestamp]}

		#logic is idential to ssh on port 22
		elif split_lines[9] == '21' and split_lines[10] == '[SYN]':
			if src_ip in ftp_tracker:
				if dst_ip in ftp_tracker[src_ip]:

					ftp_interval = float(timestamp) - float(ftp_tracker[src_ip][dst_ip][-1])
					if ftp_interval < 25:
						ftp_tracker[src_ip][dst_ip].append(timestamp)

						if len(ftp_tracker[src_ip][dst_ip]) > 10:
							ftp_ip = [src_ip, dst_ip]
							if ftp_ip not in ftp_ips:
								rule = ["ftpBruteForce", packet, src_ip, dst_ip, 21]
								ftp_ips.append(ftp_ip)
								store_rule(rule)

					else:
						ftp_tracker[src_ip][dst_ip] = [timestamp]
				else:
					ftp_tracker[src_ip][dst_ip] = [timestamp]
			else:
				ftp_tracker[src_ip] = {dst_ip : [timestamp]}

#----START OF GENERAL NOTES AND PSEUDO CODE -----------
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







#CALLS MAIN FUNCTION
main()
