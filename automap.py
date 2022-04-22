#automap
#python 'fire and forget' script for automating essential nmap scans
#github.com/the-jcksn
#yeah I know the code is spaghetti, I'll sort it out and refine more as definitions when I get a chance
#open source = no moaning if something doesn't work, either fix it yourself in a pull request or ask nicely!

#usage: sudo python automap.py 10.10.10.10

import argparse
import os
from termcolor import colored

parser = argparse.ArgumentParser()
parser.add_argument('-ip', default='none', dest='ip', help='Provide an IP address or CIDR range to scan', type=str)
args = parser.parse_args()

def printstrip():
	print(colored('==================================================','yellow'))

def delempty(filename):
	lines = []
	with open(filename, 'r') as check:
		for line in check:
			lines.append(line)
		if len(lines) < 2:
			os.system('rm -f ' + filename)

def longscript():
	print(colored('    [!]','red'),'This may take some time...(Ctrl-C to skip)')

top100tcp = 'nmap -sT -F ' + args.ip + ' -oN top100tcpscan.txt -v0'
top100udp = 'nmap -sU -F ' + args.ip + ' -oN top100udpscan.txt -v0'
top1000tcpaggressive = 'nmap -sT -A ' + args.ip + ' -oN top1000TCPAggressive.txt -v0'
top1000udp = 'nmap -sU ' + args.ip + ' -oN top1000udp.txt -v0'
tcpvulnscan = 'nmap -sT --script vuln ' + args.ip + ' -oN TCPvulnscan.txt -v0'
udpvulnscan = 'nmap -sU --script vuln ' + args.ip + ' -oN UDPvulnscan.txt -v0'
ftpscriptscan = 'nmap --script ftp-* -p 21 ' + args.ip + ' -oN FTPscriptscan.txt -v0'
sshbrute = 'nmap --script ssh-brute -p 22 ' + args.ip + ' -oN SSHBrute.txt -v0'
sqldump = 'nmap -p 3306 ' + args.ip + ' --script mysql-dump-hashes --script-args=\'username=root,password=secret\' -oN mysql-hash-dump.txt -v0'
snmpbrute = 'nmap -sU --script snmp-brute ' + args.ip + ' -oN snmpbrute.txt -v0'
tftpenum = 'nmap -sU --script tftp-enum ' + args.ip + ' -oN tftp-enum.txt -v0'
ldapscripts = 'nmap -n -sV --script \"ldap* and not brute\" ' + args.ip + ' -oN ldap-scripts.txt -v0'

if not os.environ.get('SUDO_UID') and os.getuid() != 0:
	raise PermissionError('You need to run this script with sudo or as root.')

if args.ip == 'none':
	print(colored('[!]','red'),'No IP address or CIDR range specified, please use \'-ip IPADDRESS\'')
	quit()
printstrip()
print(colored('[!] Starting automap','green'))
printstrip()
print(colored('[+]','blue'), 'Running starting scripts...')
print(colored('[+]','green'), 'Running Top 100 TCP scan - saving output to top100tcpscan.txt', colored(' -Do not skip this scan','red'))
os.system(top100tcp)
print(colored('[+]','green'), 'Running Top 100 UDP scan - saving output to top100udpscan.txt', colored(' -Do not skip this scan','red'))
os.system(top100udp)
print(colored('[+]','green'), 'Running Top 1000 TCP Aggressive scan - saving output to top1000TCPAggressive.txt')
longscript()
os.system(top1000tcpaggressive)
delempty('top1000TCPAggressive.txt')
print(colored('[+]','green'), 'Running Top 1000 UDP scan - saving output to top1000udp.txt')
longscript()
os.system(top1000udp)
delempty('top1000udp.txt')
printstrip()
print(colored('[+]','blue'),'All starting scripts complete!')
printstrip()

print(colored('[+]','blue'), 'Running TCP / UDP vuln scans...')
print(colored('[+]','green'), 'Running TCP vuln scan - saving output to TCPvulnscan.txt')
longscript()
os.system(tcpvulnscan)
delempty('TCPvulnscan.txt')
print(colored('[+]','green'), 'Running UDP vuln scan - saving output to UDPvulnscan.txt')
longscript()
os.system(udpvulnscan)
delempty('UDPvulnscan.txt')
printstrip()
print(colored('[+]','blue'),'All vuln scans complete!')
printstrip()

string = '21/tcp open'
ftpdone = 'n'
with open('top100tcpscan.txt', 'r') as ftpcheck:
	for line in ftpcheck:
		if string in line and ftpdone == 'n':
			print(colored('[+]','blue'),'Looks like TCP port 21 is open!')
			print(colored('[+]','green'), 'Running all FTP scripts - saving output to FTPscriptscan.txt')
			longscript()
			os.system(ftpscriptscan)
			ftpdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'All FTP scripts complete!')
			printstrip()
			delempty('FTPscriptscan.txt')
string = '21/udp open'
with open('top100udpscan.txt', 'r') as ftpucheck:
	for line in ftpucheck:
		if string in line and ftpdone == 'n':
			print(colored('[+]','blue'),'Looks like UDP port 21 is open!')
			print(colored('[+]','green'), 'Running all FTP scripts - saving output to FTPscriptscan.txt')
			longscript()
			os.system(ftpscriptscan)
			ftpdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'All FTP scripts complete!')
			printstrip()
			delempty('FTPscriptscan.txt')
ftpcheck.close()
ftpucheck.close()

string = '22/tcp open'
sshdone = 'n'
with open('top100tcpscan.txt', 'r') as sshcheck:
	for line in sshcheck:
		if string in line and sshdone == 'n':
			print(colored('[!]','blue'),'Looks like TCP port 22 is open!')
			print(colored('[+]','green'), 'Running SSH Brute - saving output to SSHBrute.txt')
			longscript()
			os.system(sshbrute)
			sshdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'SSH Brute complete!')
			printstrip()
			delempty('SSHBrute.txt')
string = '22/udp open'
with open('top100udpscan.txt', 'r') as sshucheck:
	for line in sshucheck:
		if string in line and sshdone == 'n':
			print(colored('[!]','blue'),'Looks like UDP port 22 is open!')
			print(colored('[+]','green'), 'Running SSH Brute - saving output to SSHBrute.txt')
			longscript()
			os.system(sshbrute)
			sshdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'SSH Brute complete!')
			printstrip()
			delempty('SSHBrute.txt')
sshcheck.close()
sshucheck.close()

string = '3306/tcp open'
dumpdone = 'n'
with open('top100tcpscan.txt', 'r') as hashdump:
	for line in hashdump:
		if string in line and dumpdone == 'n':
			print(colored('[!]','blue'),'Looks like TCP port 3306 is open!')
			print(colored('[+]','green'), 'Running Mysql hash dump - saving output to mysql-hash-dump.txt')
			longscript()
			os.system(sqldump)
			dumpdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'Mysql hash dump complete!')
			printstrip()
			delempty('mysql-hash-dump.txt')
string = '3306/udp open'
with open('top100udpscan.txt', 'r') as hashudump:
	for line in hashudump:
		if string in line and dumpdone == 'n':
			print(colored('[!]','blue'),'Looks like UDP port 3306 is open!')
			print(colored('[+]','green'), 'Running Mysql hash dump - saving output to mysql-hash-dump.txt')
			longscript()
			os.system(sqldump)
			dunpdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'Mysql hash dump complete!')
			printstrip()
			delempty('mysql-hash-dump.txt')
hashdump.close()
hashudump.close()

string = '161/udp open'
string2 = '162/udp open'
snmpdone = 'n'
with open('top100udpscan.txt', 'r') as snmpubrute:
	for line in snmpubrute:
		if string in line or string2 in line and snmpdone == 'n':
			print(colored('[!]','blue'),'Looks like UDP port 161 / 162 is open!')
			print(colored('[+]','green'), 'Running SNMP Brute - saving output to snmpbrute.txt')
			longscript()
			os.system(snmpbrute)
			snmpdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'SNMP Brute complete!')
			printstrip()
			delempty('snmpbrute.txt')
snmpubrute.close()

string = '69/udp open'
tftpdone = 'n'
with open('top100udpscan.txt', 'r') as tftpuenum:
	for line in tftpuenum:
		if string in line and tftpdone == 'n':
			print(colored('[!]','blue'),'Looks like UDP port 69 is open!')
			print(colored('[+]','green'), 'Running tftp-enum - saving output to tftp-enum.txt')
			longscript()
			os.system(tftpenum)
			tftpdone = 'y'
			printstrip()
			print(colored('[+]','blue'), 'Tftp-enum complete!')
			printstrip()
			delempty('tftp-enum.txt')
tftpuenum.close()

string = '636/tcp open'
ldapdone = 'n'
with open('top100tcpscan.txt', 'r') as ldap:
	for line in ldap:
		if string in line and ldapdone == 'n':
			print(colored('[!]','blue'),'Looks like TCP port 636 is open!')
			print(colored('[+]','green'), 'Running all LDAP scripts (not brute) - saving output to ldap-scripts.txt')
			longscript()
			os.system(ldapscripts)
			ldapdone = 'y'
			print(colored('[+]','blue'), 'All LDAP scripts complete!')
			printstrip()
			delempty('ldap-scripts.txt')
ldap.close()

print(colored('[!] All scans completed!','green'))
printstrip()
