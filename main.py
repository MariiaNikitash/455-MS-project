'''
Task: Build a CVE retrieval tool

Implement a tool that can retrieve CVE entries and their details (e.g., CVE ID, description, severity/score if available, references, published/modified dates).
The tool should query an upstream source via an API (please research and choose an appropriate CVE API/provider).
It should be able to iterate through CVE results (e.g., pagination, date ranges, or other supported query parameters) , so you can programmatically go through the CVE list.

Query an upstream CVE source via an API (your choice).
Iterate through CVEs (pagination/date range/search supported by the API).
Extract and present key CVE fields (e.g., CVE ID, description, severity/score if available, references, published/modified dates).

A runnable tool that fetches CVE data from your machine.
Clear output (console + optional JSON/CSV export) demonstrating successful retrieval.

Requirements:
1. Query CVE source via an API - We are using NVD
2. When querying a CVE Record, retrieved information can include:
    CVE ID
    Description
    Severity/Score
    References
    Published/Modified Dates
3. Should be able to interate through batches of CVEs
4. Outputs the result to the console, with the potential for a JSON/CSV export
'''
import requests
import os

from dotenv import load_dotenv


url = "https://services.nvd.nist.gov/rest/json/cves/2.0" # URL to the NVD API
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")
headers = { "apiKey": NVD_API_KEY }

params = {}

response = requests.get(
    url,
    headers=headers,
    params=params,
    timeout=30)

response.raise_for_status()
data = response.json() # Data response variable

# Print out the results, index we are starting at, and how many results per page there are
print("Total Results: ", data["totalResults"])
print("startIndex: ", data["startIndex"])
print("resultsPerPage: ", data["resultsPerPage"])

print()

# print out the different aspects of response
for items in data["vulnerabilities"]:
    print("CVE ID: ", items["cve"]["id"])                   # print CVE ID
    print("Published: ", items["cve"]["published"])         # print publish date
    print("Last Modified: ", items["cve"]["lastModified"])  # print last modified date
    print()

    for desc in items["cve"]["descriptions"]:               # print english description
        if desc["lang"] == "en":
            print("Description:", desc["value"])
    
    print()

    print("References:")                                    # print out references in the form: source ; url
    for reference in items["cve"]["references"]:
        print("   ", reference["source"], "   ;   ", reference["url"])

    print('\n\n')