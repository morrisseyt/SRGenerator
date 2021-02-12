#!/usr/bin/env python3

import sys
import subprocess
from prettytable import PrettyTable
from collections import Counter

stored_rules = []
pcapASlist = []
counter = 0
conversations_table = []

list_table = PrettyTable(["IP Addresses", "Packets Sent"])

#defining colors for print summary
BR = '\033[1;31m' # bold red text
BW = '\033[1;37m' # bold white text
BB = '\033[1;34m' # bold blue text
BG = '\033[1;32m' # bold green
BY = '\033[1;33m' # bold yellow
DC = '\033[0m' #default color
BM = '\033[1;35m' #bold magenta

def error_check():
	if len(sys.argv) != 2:
		print(f'[-]{BR} Error:{DC} Expecting exactly 1 arguement.  Usage: ./snortsuggester.py file.pcap')
		exit()
	file = sys.argv[1]
		# below conditional checks if the last 5 characters of the file variable that is now sys.argv[1] is .pcap
	if file[-5:] != '.pcap':
		print(f'[-]{BR} Error:{DC} Expecting .pcap file. Usage: ./snortsuggester.py file.pcap')
		exit()
	return sys.argv[1] # sys.argv[1] is returned to the main function here

def pcapconverter(pcap):

	with subprocess.Popen(["tshark", "-r", pcap], stdout=subprocess.PIPE) as proc:
		output = proc.stdout.readlines()
		for line in output:
			stripped_line = line.decode().strip()
			pcapASlist.append(stripped_line)

def main():
	pcap = error_check()
	pcapconverter(pcap)
	#findSSHtraffic(pcapASlist) #function exists in code but is not in use
	findbruteforce(pcapASlist)
	findscan(pcapASlist)
	packetcounter(pcapASlist)
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
		if int(split_lines[9]) > 10000:
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

def packetcounter(pcapASlist):
	global counter
	for line in pcapASlist:
		counter += 1
		split_lines = line.split()
		proto = split_lines[5]
		src_ip = split_lines[2]
		dst_ip = split_lines[4]
		if proto == 'ARP' or proto == 'LLDP': # omitting traffic that does not travel along layer 3
			continue
		conversations_table.append([src_ip, dst_ip])

	return


def print_summary():

	if counter == 0: # error check: if no lines processed, print the error not blank outputs
		print(f'[-]{BR} Error:{DC} Check file format. pcap format is required.')
		exit()
	count = Counter()
	SID_counter = 1000000
	file_name = f'{sys.argv[1]}.rules'
	line = f'{DC}-'* 100

	# next two for loops build out the IP Conversation table that is printed with the summary
	for i in conversations_table:
		src = i[0]
		dst = i[1]
		count[f'{DC}Source IP:{BM} {src}{DC}, Destination IP:{BM} {dst}{BW}'] += 1

	for ips, count in count.most_common():
		list_table.add_row([ips, count])

	with open(file_name, "w") as f:
		print("\n")
		print(BW + '--------------------------------- Snort Rule Suggester Summary ------------------------------------')
		print(f'\nThe below table summarizes layer 3 recorded traffic by Source IP and Destination IP\n')
		print(list_table)
		print('##------------------- Snort Rule Suggester Summary -----------------------', file=f) 
		print(f'{DC}\n[+] A file containing the below information can be found at:{BG} {file_name}{DC}')
		print(f'[+] The file can be moved/copied into {BG}/etc/snort/rules{DC} for immediate implementation')
		print(f'\n[+]{BW} Total Packets Analyzed:{BB} {counter}\n{DC}')
		print(f'## Total Packets Analyzed: {counter}', file=f)
		print(f'## The below rules were suggested from a pcap file:{sys.argv[1]}', file=f)
		print("", file=f)

		for rule in stored_rules:
			SID_counter += 1
			if rule[0] == 'sshBruteForce':
				print(line)
				print(f'[+]{BR} Potential Attempted SSH Brute Force:')
				print(f'{DC}[++] This rule was triggered by 10 or more SYN packets from a single source IP within a 25 second timeframe.')
				print(f'[++]{DC} The packet that triggered this alert is {BB}{rule[1]}{DC}.')
				print(f'[++] We suggest using the following rule to alert on any future traffic:')
				print(f"[++]{BY} alert TCP {rule[2]} any -> {rule[3]} {rule[4]} (msg:'Potential SSH Brute Force';sid:{SID_counter};)")
				print("")
				#begin print to file
				print(line, file=f)
				print('## Potential Attempted SSH Brute Force:', file=f)
				print('## This rule was triggered by 10 or more SYN packets from a single source IP within a 25 second timeframe.', file=f)
				print(f'## The packet that triggered this alert is {rule[1]}.', file=f)
				print('## We suggest using the following rule to alert on any future traffic:', file=f)
				print(f"alert TCP {rule[2]} any -> {rule[3]} {rule[4]} (msg:'Potential SSH Brute Force';sid:{SID_counter};)", file=f)
				print("", file=f)

			elif rule[0] == 'SynSweep':
				print(line)
				print(f'[+]{BR} Potential Attempted SYN Sweep')
				print(f'{DC}[++] This rule was triggered by a single source IP sending SYN packets to 3 or more different destination IPs')
				print(f'[++] The packet that triggered this alert is {BB}{rule[1]}{DC}.')
				print(f'[++] We suggest using the following rule to alert on any future traffic:')
				print(f"[++]{BY} alert TCP {rule[2]} any -> {rule[3]} {rule[4]} (msg:'Potential SYN Sweep';sid:{SID_counter};)")
				print("")
				#begin print to file
				print(line, file=f)
				print('## Potential Attempted SYN Sweep', file=f)
				print('## This rule was triggered by a single source IP sending SYN packets to 3 or more different destination IPs', file=f)
				print(f'## The packet that triggered this alert is {rule[1]}.', file=f)
				print('## We suggest using the following rule to alert on any future traffic:', file=f)
				print(f"alert TCP {rule[2]} any -> {rule[3]} {rule[4]} (msg:'Potential SYN Sweep';sid:{SID_counter};", file=f)
				print("", file=f)

			elif rule[0] == 'ftpBruteForce':
				print(line)
				print(f'[+]{BR} Potential Attempted FTP Brute Force:')
				print(f'{DC}[++] This rule was triggered by 10 or more SYN packets from a single source IP within a 25 second timeframe.')
				print(f'[++]{DC} The packet that triggered this alert is {BB}{rule[1]}{DC}.')
				print(f'[++] We suggest using the following rule to alert on any future traffic:')
				print(f"[++]{BY} alert TCP {rule[2]} any -> {rule[3]} {rule[4]} (msg:'Potential FTP Brute Force';sid:{SID_counter};)")
				print("")
				#begin print to file
				print(line, file=f)
				print('## Potential Attempted FTP Brute Force:', file=f)
				print('## This rule was triggered by 10 or more SYN packets from a single source IP within a 25 second timeframe.', file=f)
				print(f'## The packet that triggered this alert is {rule[1]}.', file=f)
				print('## We suggest using the following rule to alert on any future traffic:', file=f)
				print(f"alert TCP {rule[2]} any -> {rule[3]} {rule[4]} (msg:'Potential FTP Brute Force';sid:{SID_counter};)", file=f)
				print("", file=f)



			elif rule[0] =='MultiplePortScan':
				print(line)
				print(f'[+]{BR} Potential Attempted Port Scan:')
				print(f'{DC}[++] This rule was triggered by a single source IP sending SYN requests to more than 5 ports on the same destination IP')
				print(f'[++]{DC} The packet that triggered this alert is {BB}{rule[1]}{DC}.')
				print(f'[++] We suggest using the following rule to alert on any future traffic:')
				print(f"[++]{BY} alert TCP {rule[2]} any -> {rule[3]} any (msg: 'Potential Port Scan against {rule[3]}';sid:{SID_counter};)")
				print("")
				#begin print to file
				print(line, file=f)
				print('## Potential Attempted Port Scan:', file=f)
				print('## This rule was triggered by a single source IP sending SYN requests to more than 5 ports on the same destination IP', file=f)
				print(f'## The packet that triggered this alert is {rule[1]}.', file=f)
				print(f'## We suggest using the following rule to alert on any future traffic:', file=f)
				print(f"alert TCP {rule[2]} any -> {rule[3]} any (msg: 'Potential Port Scan against {rule[3]}';sid:{SID_counter};)", file=f)
				print("", file=f)






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
								stored_rules.append(rule)
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
								stored_rules.append(rule)

					else:
						ftp_tracker[src_ip][dst_ip] = [timestamp]
				else:
					ftp_tracker[src_ip][dst_ip] = [timestamp]
			else:
				ftp_tracker[src_ip] = {dst_ip : [timestamp]}


#CALLS MAIN FUNCTION
main()
