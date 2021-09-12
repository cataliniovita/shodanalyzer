import requests
import json
import re

class RegexDict(dict):
    def get_matching(self, event):
        return (self[key] for key in self if re.match(key, event))

def get_immuni_info():
    data = {
          'tested_url': 'https://www.spitalulmonza.ro/',
          'choosen_ip': 'any',
          'dnsr': 'off',
          'recheck': 'false'
    }

    response = requests.post('https://www.immuniweb.com/websec/api/v1/chsec/1451425590.html', data=data)
    json_obj = json.loads(response.content)

# Cache flag
    cached = 0

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

get_immuni_info()
