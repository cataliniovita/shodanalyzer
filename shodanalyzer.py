import requests
import struct
import argparse
import json
import re
from colorama import Fore, Back, Style
from bs4 import BeautifulSoup, NavigableString

def error(element):
    if element is None:
        print("[-] You are temporarily banned from accessing account.shodan.io website")
        return False

def banner():
    print(Fore.WHITE + 
    """
          _               _                   _
         | |             | |                 | |
      ___| |__   ___   __| |_____ ____  _____| |_   _ _____ _____  ____
     /___|  _ \ / _ \ / _  (____ |  _ \(____ | | | | (___  | ___ |/ ___)
    |___ | | | | |_| ( (_| / ___ | | | / ___ | | |_| |/ __/| ____| |
    (___/|_| |_|\___/ \____\_____|_| |_\_____|\_\__  (_____|_____|_|
                                               (____/
                                                v0.1
    """)
    print(Style.RESET_ALL, end='')

# Login with csrf token and create a session
def login_session(args):
    # Create a session
    session_requests = requests.session()

    # Get the csrf token
    csrf_req = requests.get('https://account.shodan.io/login')
    soup = BeautifulSoup(csrf_req.content, 'html.parser')

    if error(soup) == False:
        return False

    token = soup.find('input', {'name':'csrf_token'})
    if error(token) == False:
        return False

    # Check if csrf token is available
    access_token = token['value']

    # Grab the cookie session
    session_cookies = csrf_req.cookies
    cookies_dict = session_cookies.get_dict()
    session_key = cookies_dict["session"]

    cookies = cookies_dict

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://account.shodan.io',
        'Alt-Used': 'account.shodan.io',
        'Connection': 'keep-alive',
        'Referer': 'https://account.shodan.io/login?continue=https%3A%2F%2Fwww.shodan.io%2Fdashboard',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'TE': 'trailers',
    }

    data = {
      'username': args.user,
      'password': args.password,
      'grant_type': 'password',
      'continue': 'https://www.shodan.io/dashboard',
      'csrf_token': access_token
    }

    response = session_requests.post('https://account.shodan.io/login', headers=headers, data=data, cookies=cookies)

    params = (
        ('query', args.ip),
    )

    # Create the search request
    response = session_requests.get('https://www.shodan.io/search', headers=headers, params=params)
    soup = BeautifulSoup(response.content, 'html.parser')
    # Create the login session
    response = session_requests.get('https://account.shodan.io/', headers=headers, params=params)
    account = BeautifulSoup(response.content, 'html.parser')

    display_name = account.find_all('td')
    logged_flag = 0

    for name in display_name:
        if name.text == "Display Name":
            logged_flag = 1

    # No valid credentials found. The search will still be made
    if logged_flag == 0:
        print(Fore.RED + "[-] You are not logged in. Try to use valid credentials\n")
        print(Style.RESET_ALL, end='')

    return soup

def get_open_ports(soup, args):
    # Find open ports list
    find_ports = soup.find(id="ports")
    ports_list = []

    if find_ports is None:
        print("[-] No Open Ports found")
        return

    for i in find_ports:
        if isinstance(i, NavigableString):
            break
        else:
            ports_list.append(i.contents[0])

    return ports_list

# Find ports with protocols
def get_open_ports_protocols(soup, args):
    ports_list = []

    print(Fore.RED + Back.YELLOW + "[*] Open Ports for " + args.ip, end='')
    print(Style.RESET_ALL)

    # Services on port
    grid_title = soup.find_all("span")

    if grid_title is None:
        print("[-] No Open Ports found")
        return

    grid_heading = soup.find_all("h6", {"class": "grid-heading"})
    count = 0

    for grid in grid_heading:
        try:
            print_grid = grid.find("span")

            # Print port number
            strong = print_grid.find("strong").text.replace("  ", '')

            # Print protocol type
            if count >= 1:
                rep_n = print_grid.contents[1].replace("\n", " ")
                port_info = strong + rep_n.replace("/", " ")
                print(port_info)
                ports_list.append(port_info)

        except:
            pass

        count += 1 

    if ports_list == []:
        print("[-] No Open Ports found\n")
    else:
        print("")

    return ports_list

# Alert found for possible banned session
def alert_found(soup):
    alert = soup.findAll("div", {"class": "alert alert-notice"}) 

    if alert != []:
        return True

    return False

def get_info(soup):
    print(Fore.RED + Back.YELLOW + "[*] General Information", end='')
    print(Style.RESET_ALL)
    general_info = soup.find(id="general")

    table = soup.find('table')

    if table is None:
        print("[-] No general information found\n")
        return

    trs = table.find_all('tr')

    for tr in trs:
        count = 0
        print_string = ""
        for td in tr:
            if isinstance(td, NavigableString):
                pass 
            else:
                if count == 1:
                    print_string += ": "
                
                print_string += td.text.strip()
                count += 1

        print(print_string)

    print("")

def get_services(soup, ports_list):
    print(Fore.RED + Back.YELLOW + "[*] Services", end='')
    print(Style.RESET_ALL)

    # Services on port
    grid_title = soup.find_all("span")

    if grid_title == []:
        print("[-] No services found\n")

    # Services detailed
    padding_banner = soup.find_all("div", {"class": "card card-padding banner"})

    if padding_banner == []:
        print("[-] No services found\n")
        return

    no = 0
    for i in padding_banner:
        print(Fore.GREEN + ports_list[no])
        print(Style.RESET_ALL, end='')
        print(i.contents[1].text)
        no += 1

    print("")

def get_technologies(soup):
    print(Fore.RED + Back.YELLOW + "[*] Web Technologies", end ='')
    print(Style.RESET_ALL)

    web_techs = soup.findAll("ul", {"id": "http-components"})
    tech_list = []
    web_str = ''

    if web_techs is None:
        print("[-] No technologies found...")
        return
    else:
        for tech in web_techs:
            web_str = tech.text

        if web_str == '':
            print("[-] No technologies found")
            print("")
            return

        web_str = web_str.split("\n")
        
        for web in web_str:
            print(web, end='')
            if web != '':
                print("")

    print("")
        
def get_cves(soup):
    print(Fore.RED + Back.YELLOW + "[*] Vulnerabilities", end='')
    print(Style.RESET_ALL)

    vulns_str = ""
    # Extract possible CVEs from shodan result
    vulnerabilities = soup.findAll("table", {"class":"table", "id":"vulnerabilities"})

    if vulnerabilities is None:
        print("[-] No vulnerabilities found\n")
        return

    for vulns in vulnerabilities:
        vulns_str = vulns.text

    if vulns_str == "":
        print("[-] No vulnerabilities found\n")
        return

    vulns_str = vulns_str.split("\n")

    for v in vulns_str:
        if v.startswith("CVE"):
            print(Fore.RED +  v, end='')
            print(Style.RESET_ALL, end='')
        else:
            print(v, end='')

        if v != '':
            print("\n")

    print("")

def detect_honeypot(args):
    print(Fore.RED + Back.YELLOW + "[*] Honeypot", end ='')
    print(Style.RESET_ALL)

    # Take default header
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en-US,en;q=0.5',
        'Origin': 'https://honeyscore.shodan.io',
        'Connection': 'keep-alive',
        'Referer': 'https://honeyscore.shodan.io/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
        'TE': 'trailers',
    }

    params = (
        ('key', 'Hgqwf9dHMIE157PNCeqVJc6TVvlyGKiP'),
    )

    # Create url with command line IP address
    ip_url = "https://api.shodan.io/labs/honeyscore/"
    ip_url += args.ip

    response = requests.get(ip_url, headers=headers, params=params)

    # Honeyscore has a value lesser than 0.5 -> no honeypot present
    if float(response.text) <= 0.5:
        print("[+] ", end='')
        print(Fore.GREEN + args.ip, end='')
        print(Style.RESET_ALL, end='')
        print(" is not a honeypot. It has a ", end='')
        print(Fore.GREEN + response.text, end='')
        print(Style.RESET_ALL, end='')
        print("/1 honeyscore")
    else:
        print("[+] ", end='')
        print(Fore.RED + args.ip, end='')
        print(Style.RESET_ALL, end='')
        print(" is a honeypot. It has a ", end='')
        print(Fore.RED + response.text, end='')
        print(Style.RESET_ALL, end='')
        print("/1 honeyscore")


# Main gather function
def gather_info(soup, args):
    get_info(soup)
    ports_list = get_open_ports_protocols(soup, args)
    check_common_ports(ports_list)
    get_technologies(soup)
    get_services(soup, ports_list)
    get_cves(soup)
    detect_honeypot(args)

def check_common_ports(ports_list):
    print(Fore.RED + Back.YELLOW + "[*] Uncommon open ports", end ='')
    print(Style.RESET_ALL)

    flag = 0
    tcp_ports_file = open("tcp_ports", "r")
    udp_ports_file = open("udp_ports", "r")
    
    tcp_ports_str = tcp_ports_file.read()
    udp_ports_str = udp_ports_file.read()

    # Parse tcp and udp ports files
    for port in ports_list:
        port = port.split("   ")

        if port[1] == "tcp":
            # Generate alert, we have an uncommon port
            if port[0] not in tcp_ports_str.split(","):
                print("Uncommon port found on ", end='') 
                print(Fore.RED + port[0] + "/tcp", end='')
                print(Style.RESET_ALL)
                # Flag just increment, then we have available ports
                flag += 1

        elif port[1] == "udp":
            # Generate alert, we have an uncommon port
            if port[0] not in udp_ports_str.split(","):
                print("Uncommon port found on ", end='') 
                print(Fore.RED + port[0] + "/udp", end='')
                print(Style.RESET_ALL)
                # Flag just increment, then we have available ports
                flag += 1

    if flag == 0:
        print("[-] No uncommon opened ports found")

    print("")

def get_domain_vuln(args):
    data = {
          'tested_url': args.domain, 
          'choosen_ip': 'any',
          'dnsr': 'off',
          'recheck': 'false'
    }

    response = requests.post('https://www.immuniweb.com/websec/api/v1/chsec/1451425590.html', data=data)
    json_obj = json.loads(response.content)

    # Cache flag
    cached = 0

    try:  
        # Test cached
        if json_obj["status"] == "test_cached":
            data_url = {
                  'id': json_obj["test_id"]
            }

            response = requests.post('https://www.immuniweb.com/websec/api/v1/get_result/1451425590.html', data=data_url)
            resp_to_json = json.loads(response.content)
            vulnerabilities = resp_to_json["http_additional_info"]["app_scan"]["result"]["RESULT"]["VULNS"]

            first_key = list(vulnerabilities.keys())[0]
            vulnerabilities = vulnerabilities[str(first_key)]["BULETINS"]

        # New test
        elif json_obj["status"] ==  "test_started":
            data_url = {
                  'id': json_obj["job_id"]
            }

            response = requests.post('https://www.immuniweb.com/websec/api/v1/get_result/1451425590.html', data=data_url)
            resp_to_json = json.loads(response.content)
            vulnerabilities = resp_to_json["http_additional_info"]["app_scan"]["result"]["RESULT"]["VULNS"]

            first_key = list(vulnerabilities.keys())[0]
            vulnerabilities = vulnerabilities[str(first_key)]["BULETINS"]
        # Extract every element
        for vuln in vulnerabilities.items():
            # Tuple unpack
            name, data_unpack = vuln
            data_field = data_unpack["DATA"]
            # Extract dictionaries
            for elem in data_field:
                print("Vulnerability type: " + elem["TITLE"])
                for cve in elem["CVE"]:
                    print("CVE-ID: " + cve)
                print("CVSSv3.1_SCORE: " + elem["CVSSv3.1_SCORE"])
                print("Risk: " + elem["RISK"])
                print("Published data: " + elem["PUBLISHED"])
                print("Remediation: " + elem["REMEDIATION"])
                print(elem["DETAIL_TEXT"])
                print("Info links: " + elem["LINKS"])
                print(" ")
    except:
        print("[!] Error. Domain name resolved in an invalid IP address")

# Basic parameters
def add_params(parser):
    parser.add_argument(
            '-i',
            dest="ip",
            action="store",
            required=False,
            help="choose an ip address to scan")
    parser.add_argument(
            '-u',
            dest="user",
            action="store",
            required=False,
            help="insert your shodan account username")
    parser.add_argument(
            '-p',
            dest="password",
            action="store",
            required=False,
            help="insert your shodan account password")
    parser.add_argument(
            '-d',
            dest="domain",
            action="store",
            required=False,
            help="drop a domain for immuniweb scan")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description='Shodan-Analyzer - scanner based on shodan.io',
            epilog="Shodan-Analyzer is a web-site scanner based on shodan")

    # Add params
    add_params(parser)
    args = parser.parse_args()

    banner()

    if args.domain is None:
        if args.ip is None:
            print("[!] Choose and ip address or a domain!")
        else:
            print("[*] Starting scan for ip address " + args.ip + "..." + "\n")
            # Create a login session
            soup = login_session(args)
            # Check for banned shodan page
            if soup == False:
                print("[-] Error occured. Aborting")
            elif alert_found(soup) == True:
                print("[-] Can't find any information for " + args.ip)
            else:
                gather_info(soup, args)
    else:
        get_domain_vuln(args)
