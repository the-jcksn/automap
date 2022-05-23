import argparse
import re
import os
import requests
from termcolor import colored

#searching for interesting terms in the lines and printing the results
def longscript():
        print(colored('This may take some time, please be patient...\n','blue'))

def findinteresting(line):
        donelines = []
        count = 0
        for word in interesting:
                count += 1
                if line not in donelines:
                        if word in line:
                                print(line, colored('   - THIS COULD BE INTERESTING','red'))
                                donelines.append(line)
                        elif count == len(interesting):
                                print(line)
                                donelines.append(line)

def printline():
        print(colored('==============================================','yellow'))

#setup the arguments and check valid options selected
parser = argparse.ArgumentParser()
parser.add_argument('-d', default='none', dest='domain', help='provide the domain to enumerate', type=str)
parser.add_argument('-o', default='none', dest='output', help='provide a name for the output files', type=str)
parser.add_argument('-w', default='none', dest='wordlist', help='provide a wordlist for direcoty enumeration', type=str)
parser.add_argument('-smap', default='none', dest='sitemap_url', help='provide URL of sitemap if known', type=str)
parser.add_argument('-u', default='none', dest='userlist', help='provide a username wordlist for user enumeration', type=str)
args = parser.parse_args()

interesting = ['admin', 'secret', 'cpanel', 'controlpanel', 'forgot', 'database', 'api', 'portal', 'administrator', 'logon', 'login', 'guests', 'guest', 'account', 'user', 'security', 'dev', 'backup', 'test', 'cms', 'password', 'sql', 'scripts', 'secure']

if args.domain == 'none':
        print('No domain specified! Please use \'-d\'\n')
        print('Use \'-h\' for further help')
        print(colored('\nExiting...','red'))
        quit()
printline()
print('[+]   Starting WebPeas...\n')
domain_url = 'https://www.' + args.domain
directories = []
directories.append(domain_url)
if args.wordlist == 'none':
        print('[+]   Wordlist not provided -',colored('Directory enumeration will be skipped','red'))
else:
        print('[+]   Wordlist provided - Directory enumeration will use',args.wordlist)
if args.sitemap_url == 'none':
        print('[+]   Sitemap URL not provided -',colored('Default \'/sitemap.xml\' will be used','red'))
else:
        print('[+]   Sitemap URL provided -', args.sitemap_url)
if args.userlist == 'none':
        print('[+]   Userlist not provided -',colored('Username enumeration will be skipped', 'red'))
else:
        print('[+]   Userlist privided - Username enumeration will use',args.userlist)
if args.output == 'none':
        print('[+]   Output name not provided -',colored('Output will not be saved','red'))
else:
        print('[+]   Output name provided - Outputs will be saved as',args.output + '.(stage)')

#checking we can reach the target
printline()
print('Verifying connection to target...\n')
connected = requests.get(domain_url, 'r')
if connected.status_code == 200:
        print(colored('200 - we have a connection!','green'))
else:
        print(connected.status_code, '- no connection to target. Exiting...')
        quit()

#looking for a robots.txt file
printline()
print('Searching for robots.txt file...\n')
domain_robots = domain_url + '/robots.txt'
robots = requests.get(domain_robots, 'r')
robot_sitemap = 'notfound'
if robots.status_code == 200:
        print(colored(robots.status_code,'green'),colored('- Robots.txt found! Dumping contents:','green'),'\n')
        robotslines = str(robots.content)
        robotslines = robotslines[2:-1]
        robotslist = robotslines.split('\\n')
        for line in robotslist:
                if len(line) > 0:
                        if line[0] == '/':
                                url = domain_url + line
                                if url not in directories:
                                        directories.append(url)
                        elif line[0:5] == 'Allow':
                                slash = line[7:]
                                if slash[len(slash)-2:] == '\\r':
                                        slash = slash[:-2]
                                url = domain_url + slash
                                if url not in directories:
                                        directories.append(url)
                        elif line[0:5] == 'Disal':
                                slash = line[10:]
                                if slash[len(slash)-2:] == '\\r':
                                        slash = slash[:-2]
                                url = domain_url + slash
                                if url not in directories:
                                        directories.append(url)
                        if line[0:7] == 'Sitemap':
                                robot_sitemap = line[9:]
                l = len(line)
                if line[l-2:] == '\\r':
                        line = line[:-2]
                if args.output != 'none':
                        output_name = args.output + '.robots'
                        with open(output_name, 'a') as output:
                                output.write(line + '\n')
                findinteresting(line)
else:
        print(robots.status_code,'- Could not find robots.txt on target')

#looking for a sitemap.xml file
printline()
if args.sitemap_url != 'none':
        domain_sitemap = args.sitemap_url
        print('Using user provided sitemap at', args.sitemap_url,'\n')
elif robot_sitemap != 'notfound':
        domain_sitemap = robot_sitemap
        print('Using sitemap found from robots.txt at',robot_sitemap,'\n')
else:
        domain_sitemap = domain_url + '/sitemap.xml'
        print('Searching for a sitemap...\n')
sitemap = requests.get(domain_sitemap, 'r', allow_redirects=False)
insidelist = []
finallist = []
furthermaps = []
furtherfinallist = []
output_name = args.output + '.sitemap'
if sitemap.status_code == 200:
        print(colored(sitemap.status_code, 'green'),colored('- Sitemap found! Dumping contents (recursively):','green'),'\n')
        sitemaplines = str(sitemap.content)
        sitemaplist = sitemaplines.split('<loc>')
        for line in sitemaplist:
                stringline = str(line)
                insidelist = stringline.split('</loc>')
                if line[0:4] == 'http':
                        finallist.append(insidelist[0])
        for line in finallist:
                if line not in directories:
                        directories.append(line)
                if line[-4:] == '.xml':
                        furthermaps.append(line)
                if args.output != 'none':
                        with open(output_name, 'a') as output:
                                output.write(line + '\n')
                findinteresting(line)
        for furthermap in furthermaps:
                map_request = requests.get(furthermap,'r')
                map_content = str(map_request.content)
                maplist = map_content.split('<loc>')
                for line in maplist:
                        stringline = str(line)
                        insidelist = stringline.split('</loc>')
                        if line[0:4] == 'http':
                                furtherfinallist.append(insidelist[0])
        for line in furtherfinallist:
                if line not in directories:
                        directories.append(line)
                if args.output != 'none':
                        with open(output_name,'a') as output:
                                output.write(line + '\n')
                findinteresting(line)
else:
        print('Could not find sitemap on target - if you know the precise location of the sitemap please suuply this with -smap <URL>')

#running directory enumeration scan if wordlist provided
if args.wordlist == 'none':
        printline()
        print('No wordlist provided with \'-w\', skipping directory enumeration...')
if args.wordlist != 'none':
        printline()
        print('Conducting directory enumeration of the target...\n')
        with open(args.wordlist, 'r') as dir_wordlist:
                for counting, line in enumerate(dir_wordlist):
                        pass
        print('Using',args.wordlist, '-', counting + 1, 'words loaded\n')
        if counting > 100:
                longscript()
        with open(args.wordlist, 'r') as dir_wordlist:
                progress = 0
                for word in dir_wordlist:
                        progress += 1
                        word = '/' + word
                        word = word[:-1]
                        attempt_url = domain_url + word
                        attempt = requests.get(attempt_url, 'r', allow_redirects=False)
                        attempt_status = attempt.status_code
                        if attempt_status == 200:
                                line = word + '         - ' + str(attempt_status) + ' - Page found!'
                                findinteresting(line)
                                url = domain_url + word
                                if url not in directories:
                                        directories.append(url)
                        if attempt_status == 301 or attempt_status == 302:
                                redirect_attempt = requests.get(attempt_url, 'r')
                                if redirect_attempt.url[-2:] == '?r':
                                        redirect_attempt_url = redirect_attempt.url[:-2]
                                else:
                                        redirect_attempt_url = redirect_attempt.url
                                line = word + '         - ' + str(attempt_status) + ' Redirected to ' + redirect_attempt_url
                                findinteresting(line)
                                url = redirect_attempt_url[:2]
                                if url not in directories:
                                        directories.append(url)
                        if progress % 20 == 0:
                                print(colored('Progress:','blue'),colored(progress,'blue'), colored('out of','blue'), colored(counting + 1,'blue'))

#removing the crap that somehow ended up in the directories list - easier to delete it than find the code that put it there
#del directories[-2:]

#looking for email addresses
output_name = args.output + '.emails'
if len(directories) != 0:
        printline()
        count = 0
        print('Searching all pages found for email addresses...')
        email_found = []
        if len(directories) > 50:
                longscript()
        for page in directories:
                count += 1
                if count % 10 == 0 and count != len(directories):
                        print(colored('Progress:','blue'),colored(count,'blue'), colored('out of','blue'),colored(len(directories),'blue'),colored('pages searched','blue'))
                regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                codeline = []
                nospaces = []
                poss_email = []
                contains_email = []
                deffo_email = []
                get_page = requests.get(page, 'r')
                for line in get_page:
                        codeline.append(str(line))
                for i in codeline:
                        if '@' in i:
                                poss_email.append(i)
                for i in poss_email:
                        new_string = i.replace(">", " ")
                        new_string = new_string.replace("<", " ")
                        new_string = new_string.replace("\"", " ")
                        new_string = new_string.replace("\'", " ")
                        new_string = new_string.replace(":", " ")
                        new_string = new_string.replace("(", " ")
                        new_string = new_string.replace(")", " ")
                        new_string = new_string.replace("[", " ")
                        new_string = new_string.replace("]", " ")
                        contains_email.append(new_string)
                for line in contains_email:
                        for string in line.split():
                                if(re.fullmatch(regex, string)):
                                        deffo_email.append(string)
                                elif(re.fullmatch(regex+'.', string)):
                                        nodot = string[:-1]
                                        deffo_email.append(nodot)
                for line in deffo_email:
                        if line not in email_found:
                                if args.output != 'none':
                                        with open(output_name, 'a') as output:
                                                output.write(line + '\n')
                                print(colored('Possible email found: ','blue'), line)
                                email_found.append(line)
                if count == len(directories):
                        print('Email search complete')

#looking for cms and enumerating users
printline()
print('Looking for admin login page on target\n')
logins = ['wp-login.php']
success = 'n'
for page in logins:
        if success == 'n':
                adminlogin = domain_url + '/' + page
                attempt = requests.get(adminlogin, 'r')
                attempt_status = attempt.status_code
                if attempt_status == 200:
                        print(adminlogin,colored('- Login page found!','green'))
                        success = 'y'
                        loginpage = adminlogin


if success == 'n':
        print('Could not find a login page')

#running nmap vuln scan against target
printline()
scan_results = []
output_name = args.output + '.nmap_vuln_scan'
vulnscan = 'nmap -p 80,443 --script vuln ' + args.domain + ' -oN ' + args.output +'.nmap_vuln_scan'
print('Running nmap vuln scan against target\n')
longscript()
os.system(vulnscan)
scan_file = args.output + '.nmap_vuln_scan'
with open(scan_file,'r') as scanresults:
        for line in scanresults:
                scan_results.append(line)
os.system('rm ' + scan_file)
if args.output != 'none':
        for line in scan_results:
                if args.output != 'none':
                        with open(output_name,'a') as output:
                                output.write(line)

#finished and tidy up
printline()
print(colored('All done!','green'))
print(colored('Exiting...','red'))
