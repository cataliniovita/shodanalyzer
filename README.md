# Shodanalyzer
Shodanalyzer is a tool which uses shodan.io platform to perform a passive scan for an IP address.

## Introduction
Shodanalyzer was born with the intention of creating a simple passive scanner. You don't have to manually scan with nmap a desired IP address, because it could be interpreted as violated legislation. Using shodan.io, this tool simply brings to you the open ports, open services, web technologies of a possible web-page, general information such as ISP provider, location, country and domains and also checks for CVEs.

## Installation

For instalation we just need Python3, clone this repository and install requirements.

```bash
git clone https://github.com/cataiovita/shodanalyzer/
cd shodanalyzer
pip install -r requirements.txt
```

## Usage

To use shodanalyzer, you will need an account to shodan.io platform. Jump into ```https://account.shodan.io/register``` web-page and create an account.
To scan an IP address, the basic usage is:

```bash
python3 shodanalyzer.py -i IP_ADDRESS -u USERNAME -p PASSWORD
```

Shodanalyzer will take the data out of shodan results. 

   ![runshodanalyzer](run_shodanz.gif)

There are five possible field extracted:
 + **Open Ports**   
 + **Possible Vulnerabilities**
 + **General Information**
 + **Services**
 + **Technologies**
   
