"""
title: AbuseIPDB Tool
description: A tool to interact with the AbuseIPDB API for reporting and checking IP addresses.
current-functions:

author: q-johnson
version: 0.0.1
license: MIT License
"""
from pydantic import BaseModel, Field
import requests

def abuseipdb_api(api_method: str, endpoint: str, api_key: str, params: dict = None):
    url = f"https://api.abuseipdb.com/api/v2/{endpoint}"
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    response = requests.request(method=api_method.upper(), url=url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"API_KEY = {api_key} | API Error: [{response.status_code}] {response.text}")

class Tools:

    class Valves(BaseModel):
        api_key: str = Field(
            "",
            description="Your AbuseIPDB API key. You can get one from https://www.abuseipdb.com/account/api"
        )

    def __init__(self):
        self.citation = True
        self.valves = self.Valves()
        pass

    def check_ip(self, ip_address: str):
        """Check an IP address against the AbuseIPDB database.
        Args:
            ip_address (str): The IP address to check.
        """

        check_ip_data = abuseipdb_api(
            api_method="GET",
            endpoint="check",
            api_key=self.valves.api_key,
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": 90
                }
        )

        processed_data = {
            "ip_address": check_ip_data.get("data", {}).get("ipAddress"),
            "abuse_confidence_score": check_ip_data.get("data", {}).get("abuseConfidenceScore"),
            "country_code": check_ip_data.get("data", {}).get("countryCode"),
            "domain": check_ip_data.get("data", {}).get("domain"),
            "isp": check_ip_data.get("data", {}).get("isp"),
            "is_whitelisted": check_ip_data.get("data", {}).get("isWhitelisted"),
            "is_public": check_ip_data.get("data", {}).get("isPublic"),
            "ip_version": check_ip_data.get("data", {}).get("ipVersion"),
            "total_reports": check_ip_data.get("data", {}).get("totalReports"),
            "last_reported_at": check_ip_data.get("data", {}).get("lastReportedAt")
        }

        return f"""
### IP Address Check Result
**IP Address:** {processed_data['ip_address']} *This is the IP address you checked.*
**Abuse Confidence Score:** {processed_data['abuse_confidence_score']} *Abuse  confidence score is a value between 0 and 100, where higher values indicate a higher likelihood of abuse.*
**Country Code:** {processed_data['country_code']} *The country code of the IP address.*
**Domain:** {processed_data['domain']} *The domain associated with the IP address, if available.*
**ISP:** {processed_data['isp']} *The Internet Service Provider associated with the IP address.*
**Is Whitelisted:** {processed_data['is_whitelisted']} *Indicates if the IP address is whitelisted.*
**Is Public:** {processed_data['is_public']} *Indicates if the IP address is a public IP address.*
**IP Version:** {processed_data['ip_version']} *The version of the IP address (IPv4 or IPv6).*
**Total Reports:** {processed_data['total_reports']} *Total number of reports made against this IP address.*
**Last Reported At:** {processed_data['last_reported_at']} *The date and time when this IP address was last reported.*
"""
    
    async def report_ip(self, ip_address: str, categories: str, comment: str, __event_call__=None, __event_emitter__=None):
        """Report an IP address to the AbuseIPDB database.
        Args:
            ip_address (str): The IP address to report.
            categories (str): A list of categories for the report. Use the ID(s) for each category when calling this function. In the case of using more than one value, ensure you are using comma separated values. See the below for the list of categories::
| ID  | Title             | Description                                                                                                                                                           |
|-----|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1   | DNS Compromise    | Altering DNS records resulting in improper redirection.                                                                                                               |
| 2   | DNS Poisoning     | Falsifying domain server cache (cache poisoning).                                                                                                                     |
| 3   | Fraud Orders      | Fraudulent orders.                                                                                                                                                     |
| 4   | DDoS Attack       | Participating in distributed denial-of-service (usually part of botnet).                                                                                              |
| 5   | FTP Brute-Force   |                                                                                                                                                                       |
| 6   | Ping of Death     | Oversized IP packet.                                                                                                                                                   |
| 7   | Phishing          | Phishing websites and/or email.                                                                                                                                       |
| 8   | Fraud VoIP        |                                                                                                                                                                       |
| 9   | Open Proxy        | Open proxy, open relay, or Tor exit node.                                                                                                                             |
| 10  | Web Spam          | Comment/forum spam, HTTP referer spam, or other CMS spam.                                                                                                             |
| 11  | Email Spam        | Spam email content, infected attachments, and phishing emails. Note: Limit comments to only relevant information (instead of log dumps) and remove PII if anonymous. |
| 12  | Blog Spam         | CMS blog comment spam.                                                                                                                                                |
| 13  | VPN IP            | Conjunctive category.                                                                                                                                                  |
| 14  | Port Scan         | Scanning for open ports and vulnerable services.                                                                                                                      |
| 15  | Hacking           |                                                                                                                                                                       |
| 16  | SQL Injection     | Attempts at SQL injection.                                                                                                                                             |
| 17  | Spoofing          | Email sender spoofing.                                                                                                                                                |
| 18  | Brute-Force       | Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc. Separate from DDoS attacks.                                        |
| 19  | Bad Web Bot       | Webpage scraping and crawlers ignoring robots.txt. Excessive requests and user agent spoofing can also be reported here.                                             |
| 20  | Exploited Host    | Host likely infected with malware and used for attacks or to host malicious content. Often used with other attack categories.                                         |
| 21  | Web App Attack    | Attempts to exploit web apps like WordPress/Drupal, e-commerce platforms, phpMyAdmin, forums, and plugins.                                                            |
| 22  | SSH               | Secure Shell (SSH) abuse. Use with more specific categories.                                                                                                          |
| 23  | IoT Targeted      | Abuse targeting "Internet of Things" devices. Include device type in comments.                                                                                        |

            comment (str): A descriptive comment for why the IP address is getting reported
        """


        user_confirmation = await __event_call__(
            {
                "type": "confirmation",
                "data": {
                    "title": "Confirm IP Address Report",
                    "message": f"[{categories}] Are you sure you want to report the IP address **{ip_address}** with the following comment: {comment}? This action cannot be undone."
                }
            }
        )

        if user_confirmation:
            await __event_emitter__({
                "type": "notification",
                "data": {
                    "type": "success",
                    "content": f"[{categories}] User confirmed reporting IP address **{ip_address}** with the following comment: {comment}. Please wait..."
                }
            })

            report_data = abuseipdb_api(
                api_method="POST",
                endpoint="report",
                api_key=self.valves.api_key,
                params={
                    "ip": ip_address,
                    "categories": ",".join(categories),
                    "comment": comment
                }
            )

            return f"""
        ### IP Address Report Result
        **IP Address:** {report_data.get("data", {}).get("ipAddress")} *This is the IP address you reported.*
        **Abuse Confidence Score:** {report_data.get("data", {}).get("abuseConfidenceScore")} *Abuse confidence score is a value between 0 and 100, where higher values indicate a higher likelihood of abuse.*
        """
        else:
            await __event_emitter__({
                "type": "notification",
                "data": {
                    "type": "warning",
                    "content": f"User cancelled the report for IP address **{ip_address}**."
                }
            })
            return f"""
### IP Address Report Cancelled By User
**IP Address:** {ip_address} *The report for this IP address has been cancelled.*
"""