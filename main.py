from dotenv import load_dotenv
import requests
import os


url = "https://services.nvd.nist.gov/rest/json/cves/2.0" # URL to the NVD API
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

headers = {
    "apiKey": NVD_API_KEY
}

response = requests.get(
    url,
    headers=headers,
    params={ # Requqest to the API with parameters
        "cveId": "CVE-2021-44228"
        ""
    },
    timeout=30)

response.raise_for_status()
data = response.json() # Data response variable

for item in data["vulnerabilities"]:
    cve = item["cve"]

    print("ID:", cve["id"])
    print("Published:", cve["published"])

    for desc in cve["descriptions"]:
        if desc["lang"] == "en":
            print("Description:", desc["value"])