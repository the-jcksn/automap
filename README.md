# automap
Script to automate all of the essential nmap scans against a target
Must be run with root privileges (sudo).
Written for Unix based systems, and Nmap must already be installed!

usage: sudo python automap.py -ip 10.10.10.10

Fire and forget, you can skip some of the scans with Ctrl-C if required.
Outputs various scan results to individual text files.

Scans this automates:

Runs top 100 TCP scan
Runs top 100 UDP scan
Runs top 1000 TCP aggressive scan
Runs top 1000 UDP scan
Runs TCP vuln scan
Runs UDP vuln scan
Checks for port 21 open - runs all FTP scripts
Checks for port 22 - runs ssh-brute
Checks for port 3306 - runs mysql-hash-dump
Checks for port 69 - runs tftp-enum
Checks for port 636 - runs all LDAP scripts (not brute)
