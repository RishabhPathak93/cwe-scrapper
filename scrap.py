import requests
from bs4 import BeautifulSoup
import csv
import time
 
BASE_URL = "https://cwe.mitre.org/data/definitions/{}.html"
CSV_FILE = "cwe_vulnerabilities.csv"
 
FIELDNAMES = [
    "CWE-ID",
    "Vulnerability Mapping",
    "Description",
    "Extended Description",
    "Alternate Terms",
    "Common Consequences",
    "Potential Mitigations",
    "Notes"
]
 
def extract_section_by_id(soup, section_id):
    section = soup.find("div", id=section_id)
    if not section:
        return ""
 
    expand = section.find("div", class_="expandblock")
    if not expand:
        return ""
 
    return expand.get_text(" ", strip=True)
 
def extract_vulnerability_mapping(soup):
    mapping = soup.find("a", href=lambda x: x and "Vulnerability_Mapping" in x)
    if not mapping:
        return ""
    parent = mapping.find_parent("span")
    return parent.get_text(" ", strip=True)
 
with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    writer.writeheader()
 
    for cwe_id in range(1, 50000):
        print(f"Fetching CWE-{cwe_id}")
        url = BASE_URL.format(cwe_id)
 
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            print(f"❌ Failed CWE-{cwe_id}")
            continue
 
        soup = BeautifulSoup(response.text, "html.parser")
 
        row = {
            "CWE-ID": f"CWE-{cwe_id}",
            "Vulnerability Mapping": extract_vulnerability_mapping(soup),
            "Description": extract_section_by_id(soup, "Description"),
            "Extended Description": extract_section_by_id(soup, "Extended_Description"),
            "Alternate Terms": extract_section_by_id(soup, "Alternate_Terms"),
            "Common Consequences": extract_section_by_id(soup, "Common_Consequences"),
            "Potential Mitigations": extract_section_by_id(soup, "Potential_Mitigations"),
            "Notes": extract_section_by_id(soup, "Notes"),
        }
 
        writer.writerow(row)
        print(f"✅ Saved CWE-{cwe_id}")
        time.sleep(1)
 
 #nothing as such for now
 
#  @aise he check marna hai