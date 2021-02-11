# SRG

SRG, short for the Snort Rule Suggester, is a command-line tool that can be use to detect potentially malicious network traffic. 

# About

SRG was created to detect four types of potentially malicious network behavior by analyzing a network capture file, or pcap: SSH brute-forcing, FTP brute-forcing, network host-scanning, and port-scanning activity. Upon detection of one or more of these behaviors, SRG alerts the user by printing a summary of the triggering behavior. SRG also suggests an appropriate SNORT rule for users to implement, allowing them to detect, alert, and log similar activity in the future.
Snort is a popular, easy-to-use network intrusion detection system (NIDS) can be used as a straight packet sniffer like tcpdump, a packet logger (useful for network traffic debugging, etc), or as a full blown network intrusion prevention system. The rules provided assume use of Snort as an NIDS.

# Features

* Reads pcap files from the command line
* Provides a count of packets in file
* Provides a summary table of layer 3 traffic recorded in the file including: source IP, destination IP, and number of packets sent in each conversation
* Detects and alerts to potential SSH brute-force traffic (source port 22)
* Detects and alerts to potential FTP brute-force traffic (source port 21)
* Detects and alerts to multiport ...
* Detects and alerts to multihost ...
* Generates and prints a Snort rule for each instance described above
* Outputs a .rules file of the recommended rules for easy implementation 

# Tech

SRG was built using Python 3 and requires the modules detailed in the next section. 
SRG reads provided packet captures (pcaps) using [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), which is the command line tool for [WireShark](https://www.wireshark.org/docs/man-pages/wireshark.html).

# Installation & Usage

```
import sys
import subprocess
from prettytable import PrettyTable
from collections import Counter
```

# Contributors

@morrisseyt
@pwalt08
@jcrio

# References & Further Reading

* [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
* [Snort - man pages](https://www.snort.org/documents)

# License





