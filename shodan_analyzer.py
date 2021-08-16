import requests
import argparse
from colorama import Fore, Back, Style
from bs4 import BeautifulSoup, NavigableString

# Login with csrf token and create a session
def login_session(args):
    # Create a session
    session_requests = requests.session()

    # Get the csrf token
    csrf_req = requests.get('https://account.shodan.io/login')
    soup = BeautifulSoup(csrf_req.content, 'html.parser')
    token = soup.find('input', {'name':'csrf_token'})['value']

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
      'csrf_token': token
    }

    response = session_requests.post('https://account.shodan.io/login', headers=headers, data=data, cookies=cookies)

    params = (
        ('query', args.ip),
    )

    response = session_requests.get('https://www.shodan.io/search', headers=headers, params=params)
    soup = BeautifulSoup(response.content, 'html.parser')

    return soup

def get_open_ports(soup, args):
    # Find open ports list
    ports_list = soup.find(id="ports")
    print(Fore.RED + "[*] Open Ports for " + args.ip + " are:")
    print(Style.RESET_ALL, end='')

    for i in ports_list:
        if isinstance(i, NavigableString):
            break
        else:
            print(Fore.WHITE + ("*   " + i.contents[0]))

    print(Style.RESET_ALL, end='')

def get_open_ports_protocols(soup, args):
    ports_list = []

    print(Fore.RED + "[*] Open Ports for " + args.ip + " are:")
    print(Style.RESET_ALL, end='')

    # Services on port
    grid_title = soup.find_all("span")
    grid_heading = soup.find_all("h6", {"class": "grid-heading"})
    count = 0

    for grid in grid_heading:
        try:
            print_grid = grid.find("span")
            
            # Print port number
            strong = print_grid.find("strong").text.replace("  ", '')

            # Print protocol type
            if count >= 2:
                rep_n = print_grid.contents[1].replace("\n", " ")
                port_info = strong + rep_n.replace("/", " ")
                print(port_info)
                ports_list.append(port_info)

        except:
            pass

        count += 1 

    return ports_list

def get_info(soup):
    print(Fore.RED + "[*] General Information")
    print(Style.RESET_ALL, end='')
    #print(soup.prettify())
    general_info = soup.find(id="general")

    table = soup.find('table')
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
    print(Fore.RED + "[*] Services")
    print(Style.RESET_ALL, end='')
    # Services on port
    grid_title = soup.find_all("span")

    # Services detailed
    padding_banner = soup.find_all("div", {"class": "card card-padding banner"})

    no = 0
    for i in padding_banner:
        print(Fore.RED + ports_list[no], end='')
        print(Style.RESET_ALL, end='')
        print(i.text, end='')
        no += 1

def add_params(parser):
    parser.add_argument(
            '-i',
            dest="ip",
            action="store",
            required=True,
            help="choose an ip address to scan")
    parser.add_argument(
            '-u',
            dest="user",
            action="store",
            required=True,
            help="insert your shodan account username")
    parser.add_argument(
            '-p',
            dest="password",
            action="store",
            required=True,
            help="insert your shodan account password")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description='Shodan-Analyzer - scanner based on shodan.io',
            epilog="Shodan-Analyzer is a web-site scanner based on shodan")

    # Add params
    add_params(parser)
    args = parser.parse_args()

    # Grab open ports
    soup = login_session(args)
    get_info(soup)
    ports_list = get_open_ports_protocols(soup, args)
    get_services(soup, ports_list)
