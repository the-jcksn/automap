# automap
Script to automate all of the essential nmap scans against a target
Must be run with root privileges (sudo).
Written for Unix based systems, and Nmap must already be installed!

usage: 

sudo python automap.py -ip 10.10.10.10

Fire and forget, you can skip some of the scans with Ctrl-C if required.
Outputs various scan results to individual text files.

Scans this automates:

1)Runs top 100 TCP scan

2)Runs top 100 UDP scan

3)Runs top 1000 TCP aggressive scan

4)Runs top 1000 UDP scan

5)Runs TCP vuln scan

6)Runs UDP vuln scan

7)Checks for port 21 open - runs all FTP scripts

8)Checks for port 22 - runs ssh-brute

9)Checks for port 3306 - runs mysql-hash-dump

10)Checks for port 69 - runs tftp-enum

11)Checks for port 636 - runs all LDAP scripts (not brute)
