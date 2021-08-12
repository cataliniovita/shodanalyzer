import requests
import argparse
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
    print("[*] Open Ports for " + args.ip + " are:")

    for i in ports_list:
        if isinstance(i, NavigableString):
            break
        else:
            print("*   " + i.contents[0])

def get_info(soup):
    #print(soup.prettify())
    general_info = soup.find(id="general")

    table = soup.find('table')
    trs = table.find_all('tr')
    
    for tr in trs:
        print("-----------")
        for td in tr:
            if isinstance(td, NavigableString):
                pass 
            else:
                print(":")
                print(td.text.strip())


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
    #get_open_ports(soup, args)
    get_info(soup)
