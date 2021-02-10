#!/usr/bin/python3

			elif rule[0] =='MultiplePortScan':
				print(f"{DC}-------------------------------------------------------')
				print(f'[+]{BR}Potential Attempted Port Scan:')
				print(f'{DC}[++] This rule was triggered by a single source IP sending SYN requests to more than 5 ports on the same destination IP')
				print(f'[++]{DC} The packet that triggered this alert is {BB}{{rule[1]}{DC}.')
				print(f'[++] We suggest using the following rule to alert on any future traffic:')
				print(f"[++]{BY} alert TCP {rule[2]} any -> {rule[3]} any (msg: 'Potential Port Scan against {rule[3]}';sid:{SID_counter};)")
				print("")
				#begin print to file
				print("##----------------------------------------------------------------------", file=f)
				print('## Potential Attempted Port Scan:', file=f)
				print('## This rule was triggered by a single source IP sending SYN requests to more than 5 ports on the same destination IP', file=f)
				print(f'## The packet that triggered this alert is {rule[1]}.', file=f)
				print(f'## We suggest using the following rule to alert on any future traffic:', file=f)
				print(f'## alert TCP {rule[2]} any -> {rule[3]} any (msg: 'Potential Port Scan against {rule[3]}';sid:{SID_counter};)", file=f)
				print("", file=f)
