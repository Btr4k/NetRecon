#!/usr/bin/env python3

import os
import sys
import requests
from datetime import datetime
from colorama import Fore, Style, init
import socket
from requests.exceptions import RequestException
import secure_handler import APIKeyProtector


# Initialize colorama
init(autoreset=True)

try:
    # Get API keys securely
    api_handler = APIKeyProtector()
    API_KEY1, API_KEY2 = api_handler.get_api_keys()

    if not API_KEY1 or not API_KEY2:
        print(f"{Fore.RED}Error: Failed to retrieve API keys{Style.RESET_ALL}")
        sys.exit(1)

except Exception as e:
    print(f"{Fore.RED}Error initializing security: {str(e)}{Style.RESET_ALL}")
    sys.exit(1)


class SecurityScanner:
    def __init__(self):
        if not API_KEY1:
            print(f"{Fore.RED}Error: API_KEY1 not found in .env file{Style.RESET_ALL}")
            sys.exit(1)
        if not API_KEY2:
            print(f"{Fore.RED}Error: API_KEY2 not found in .env file{Style.RESET_ALL}")
            sys.exit(1)

    def check_internet_connection(self):
        """Check if there's an active internet connection"""
        try:
            # Try to connect to a reliable host (Google's DNS)
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False

    def make_request(self, url, headers=None):
        """Make HTTP request with proper error handling"""
        if not self.check_internet_connection():
            print(f"{Fore.RED}[!] Error: No internet connection. Please check your network connection and try again.{Style.RESET_ALL}")
            return None

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response
        except requests.exceptions.ConnectTimeout:
            print(f"{Fore.RED}[!] Error: Connection timed out. The server took too long to respond.{Style.RESET_ALL}")
        except requests.exceptions.ReadTimeout:
            print(f"{Fore.RED}[!] Error: Read timeout. The server took too long to send the data.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check your internet connection and try again.{Style.RESET_ALL}")
        except requests.exceptions.HTTPError as e:
            print(f"{Fore.RED}[!] Error: HTTP error occurred. Status code: {e.response.status_code}{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error: An error occurred while making the request: {str(e)}{Style.RESET_ALL}")
        return None

    def print_banner(self):
        banner = f"""
        {Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED}  ___  {Fore.YELLOW}___  {Fore.GREEN}___  {Fore.BLUE}_  _ {Fore.MAGENTA}___  {Fore.RED}_  _{Fore.WHITE}_____  {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED} / __>{Fore.YELLOW}/ __>{Fore.GREEN}/ __>{Fore.BLUE}| || {Fore.MAGENTA}| __>{Fore.RED}| || {Fore.WHITE}|  ___| {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED} \__ \\{Fore.YELLOW}| __>{Fore.GREEN}| | {Fore.BLUE}| >< {Fore.MAGENTA}| __>{Fore.RED}| >< {Fore.WHITE}|___  | {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED} <___/{Fore.YELLOW}`___/{Fore.GREEN}|_| {Fore.BLUE}|_||_{Fore.MAGENTA}|___>{Fore.RED}|_||_{Fore.WHITE}|_____| {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}║                                                              ║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.WHITE}SECURITY SCANNER{Fore.CYAN} ║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.WHITE}SECURITY SCANNER{Fore.CYAN} ║{Style.RESET_ALL}
        {Fore.CYAN}║                                                              ║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED}[+] {Fore.WHITE}Created By: {Fore.GREEN}Abdullah @A_cyb3r              {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED}[+] {Fore.WHITE}Version: {Fore.YELLOW}1.0.0                               {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}║     {Fore.RED}[+] {Fore.WHITE}For Educational Purposes Only                  {Fore.CYAN}║{Style.RESET_ALL}
        {Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

        {Fore.RED}[!] {Fore.YELLOW}Legal Disclaimer: Usage of this tool for attacking targets without prior mutual consent is illegal. 
            It's the end user's responsibility to obey all applicable laws. The developer assumes no liability.{Style.RESET_ALL}
        """
        print(banner)

    def print_menu(self):
        menu = f"""
        {Fore.YELLOW}┌───────────── Information Gathering ─────────────┐{Style.RESET_ALL}
        {Fore.CYAN}[1]{Style.RESET_ALL} Subdomain Finder     {Fore.CYAN}[2]{Style.RESET_ALL} DNS Lookup
        {Fore.CYAN}[3]{Style.RESET_ALL} Phone Info           {Fore.CYAN}[4]{Style.RESET_ALL} Port Scanner

        {Fore.YELLOW}┌───────────── Website Security ──────────────────┐{Style.RESET_ALL}
        {Fore.CYAN}[5]{Style.RESET_ALL} WAF Detector         {Fore.CYAN}[6]{Style.RESET_ALL} Website Up/Down
        {Fore.CYAN}[7]{Style.RESET_ALL} Cloudflare Resolver  {Fore.CYAN}[8]{Style.RESET_ALL} IP Logger

        {Fore.YELLOW}┌───────────── Privacy & Analysis ────────────────┐{Style.RESET_ALL}
        {Fore.CYAN}[9]{Style.RESET_ALL} Email Validator      {Fore.CYAN}[10]{Style.RESET_ALL} Email Leak Check
        {Fore.CYAN}[11]{Style.RESET_ALL} Proxy Detector      {Fore.CYAN}[12]{Style.RESET_ALL} VPN Detector

        {Fore.YELLOW}┌───────────── System ────────────────────────────┐{Style.RESET_ALL}
        {Fore.CYAN}[0]{Style.RESET_ALL} Exit

        {Fore.YELLOW}Choose an option:{Style.RESET_ALL} """
        return input(menu)

    def get_target(self, service_name):
        return input(f"\n{Fore.YELLOW}Enter target for {service_name}:{Style.RESET_ALL} ")

    def find_subdomains(self, domain):
        """Find subdomains for a given domain"""
        # Clean domain (remove http/https if present)
        domain = domain.replace('https://', '').replace('http://', '').strip()
        print(f"\n{Fore.YELLOW}[*] Searching for subdomains for: {domain}{Style.RESET_ALL}")
        
        found_domains = []
        
        # First try with C99 API
        url = f"https://api.c99.nl/subdomainfinder?key={API_KEY1}&domain={domain}"
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200 and response.text.strip():
                subdomains = response.text.split('<br>')
                for sub in subdomains:
                    if sub.strip():
                        found_domains.append(sub.strip())
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[!] C99 API request failed, switching to backup method...{Style.RESET_ALL}")
            
            # Backup method using DNS query
            try:
                common_subdomains = [
                    'www', 'mail', 'remote', 'blog', 'webmail', 'server',
                    'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
                    'm', 'staging', 'test', 'portal', 'admin', 'intranet',
                    'gateway', 'host', 'dns', 'proxy', 'apps', 'web'
                ]
                
                print(f"{Fore.YELLOW}[*] Checking common subdomains...{Style.RESET_ALL}")
                
                for subdomain in common_subdomains:
                    try:
                        hostname = f"{subdomain}.{domain}"
                        ip = socket.gethostbyname(hostname)
                        found_domains.append(f"{hostname} ({ip})")
                    except socket.gaierror:
                        continue

            except Exception as e:
                print(f"{Fore.RED}[!] Error during DNS lookup: {str(e)}{Style.RESET_ALL}")

        if found_domains:
            print(f"\n{Fore.GREEN}[+] Found {len(found_domains)} subdomains:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            for i, subdomain in enumerate(found_domains, 1):
                print(f"{Fore.YELLOW}{i:2d}.{Style.RESET_ALL} {subdomain}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

            # Save results to file
            filename = f"subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for subdomain in found_domains:
                    f.write(subdomain + '\n')
            print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No subdomains found for {domain}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another domain")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_target = input(f"\n{Fore.YELLOW}Enter domain:{Style.RESET_ALL} ").strip()
                if new_target:
                    return self.find_subdomains(new_target)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")


    def detect_waf(self, url):
        """Detect WAF on a given URL"""
        # Add http:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        print(f"\n{Fore.YELLOW}[*] Checking for WAF on: {url}{Style.RESET_ALL}")
        
        api_url = f"https://api.c99.nl/firewalldetector?key={API_KEY1}&url={url}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(api_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                if response.text.strip():
                    print(f"\n{Fore.GREEN}[+] WAF Detection Results:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    results = response.text.split('<br>')
                    for result in results:
                        if result.strip():
                            if 'WAF' in result:
                                print(f"{Fore.GREEN}[+] {result.strip()}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.YELLOW}[i] {result.strip()}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No WAF detected on this target.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out. Try again or check the URL.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check the URL and your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another URL")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_url = input(f"\n{Fore.YELLOW}Enter URL:{Style.RESET_ALL} ").strip()
                if new_url:
                    return self.detect_waf(new_url)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def validate_email(self, email):
        """Validate email format"""
        import re
        
        # Check if empty
        if not email:
            return False
            
        # Basic checks before regex
        if len(email) < 5 or ' ' in email or '@' not in email:
            return False
        
        # Regular expression for email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def email_validator(self, email):
        """Validate if email exists and is valid"""
        # First check format
        if not self.validate_email(email):
            print(f"\n{Fore.RED}[✗] Invalid email format{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Email should be in format: user@domain.com{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to try again...{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.YELLOW}[*] Checking email validity for: {email}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/emailvalidator?key={API_KEY1}&email={email}"
        
        try:
            response = self.make_request(url)
            if response and response.text.strip():
                print(f"\n{Fore.GREEN}[+] Email Validation Results:{Style.RESET_ALL}")
                
                # Parse and format the response
                results = response.text.split('<br>')
                
                print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
                for result in results:
                    if result.strip():
                        if 'VALID' in result:
                            print(f"{Fore.GREEN}[✓] {result.strip()}{Style.RESET_ALL}")
                        elif 'INVALID' in result:
                            print(f"{Fore.RED}[✗] {result.strip()}{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.YELLOW}[i] {result.strip()}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
                    
            elif response:
                print(f"{Fore.YELLOW}[!] Could not validate this email address.{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another email")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                return self.email_validator(input(f"\n{Fore.YELLOW}Enter email address:{Style.RESET_ALL} ").strip())
            elif choice == '2':
                return True
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")


    def dns_lookup(self, domain):
        """Advanced DNS lookup for domain"""
        # Clean domain (remove http/https if present)
        domain = domain.replace('https://', '').replace('http://', '').strip()
        print(f"\n{Fore.YELLOW}[*] Advanced DNS Check in progress for: {domain}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/dnschecker?key={API_KEY1}&url={domain}&type=ns"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(url, headers=headers, timeout=60)
            
            if response.status_code == 200:
                content = response.text.strip()
                if not content:
                    print(f"{Fore.RED}[!] No DNS records found{Style.RESET_ALL}")
                    return
                    
                # Process and display results
                servers = content.split("#########")
                found_records = False
                
                for server in servers:
                    if server.strip():
                        found_records = True
                        # Clean and parse the server information
                        lines = server.replace('<br />', '\n').strip().split('\n')
                        
                        # Print server information
                        if lines[0]:
                            server_name = lines[0].replace('Server ', '').strip()
                            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}[+] {server_name}{Style.RESET_ALL}")
                            
                            # Process server details
                            current_section = None
                            for line in lines[1:]:
                                line = line.strip()
                                if line:
                                    if ':' in line:
                                        key, value = line.split(':', 1)
                                        key = key.strip()
                                        value = value.strip()
                                        if value:  # Only print if there's a value
                                            print(f"{Fore.YELLOW}{key:12}:{Style.RESET_ALL} {value}")
                                            if key == "Data":
                                                current_section = "nameservers"
                                    elif current_section == "nameservers" and line:
                                        print(f"  └─ {line}")
                
                if not found_records:
                    print(f"{Fore.YELLOW}[!] No DNS records were returned{Style.RESET_ALL}")
                        
            elif response.status_code == 404:
                print(f"{Fore.RED}[!] Domain not found or invalid{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] API returned status code: {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Request timed out. The server took too long to respond.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Connection error. Please check your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another domain")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_target = input(f"\n{Fore.YELLOW}Enter domain:{Style.RESET_ALL} ").strip()
                if new_target:
                    return self.dns_lookup(new_target)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")


    def phone_info(self, phone):
        """Phone number information scanner"""
        print(f"\n{Fore.YELLOW}[*] Phone number format guide:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Format: +[country code][number]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}• Example: +966598653555{Style.RESET_ALL}")
        
        if not phone.startswith("+"):
            print(f"{Fore.RED}[!] Invalid format. Phone number must start with '+'{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}1.{Style.RESET_ALL} Try another number")
            print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
            
            while True:
                choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
                if choice == '1':
                    new_phone = input(f"\n{Fore.YELLOW}Enter phone number:{Style.RESET_ALL} ").strip()
                    return self.phone_info(new_phone)
                elif choice == '2':
                    return
                else:
                    print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}[*] Scanning phone number: {phone}{Style.RESET_ALL}")
        url = f"https://api.c99.nl/phonelookup?key={API_KEY1}&number={phone}"
        
        try:
            response = requests.get(url, timeout=60)
            if response.status_code == 200 and response.text.strip():
                print(f"\n{Fore.GREEN}[+] Phone Information Results:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
                info_lines = response.text.strip().split('<br>')
                for line in info_lines:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        print(f"{Fore.YELLOW}{key:12}:{Style.RESET_ALL} {value}")
                
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] No information found for this number.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error occurred: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another number")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_phone = input(f"\n{Fore.YELLOW}Enter phone number:{Style.RESET_ALL} ").strip()
                return self.phone_info(new_phone)
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def check_website(self, url):
        """Check if website is up or down"""
        # Clean URL (remove http:// or https:// if present)
        url = url.replace('http://', '').replace('https://', '').strip()
        
        print(f"\n{Fore.YELLOW}[*] Checking website status for: {url}{Style.RESET_ALL}")
        
        api_url = f"https://api.c99.nl/upordown?key={API_KEY1}&host={url}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(api_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                if response.text.strip():
                    print(f"\n{Fore.GREEN}[+] Website Status Results:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    
                    results = response.text.strip().split('<br>')
                    for result in results:
                        if ':' in result:
                            key, value = result.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Color-code status and response code
                            if key == 'Status':
                                if value.upper() == 'UP':
                                    print(f"{Fore.YELLOW}{key:13}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.YELLOW}{key:13}:{Style.RESET_ALL} {Fore.RED}{value}{Style.RESET_ALL}")
                            elif key == 'Response code':
                                code = int(value)
                                if 200 <= code < 300:
                                    print(f"{Fore.YELLOW}{key:13}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
                                elif 300 <= code < 400:
                                    print(f"{Fore.YELLOW}{key:13}:{Style.RESET_ALL} {Fore.YELLOW}{value}{Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.YELLOW}{key:13}:{Style.RESET_ALL} {Fore.RED}{value}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.YELLOW}{key:13}:{Style.RESET_ALL} {value}")
                                
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No response from website{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out. Try again or check the URL.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check the URL and your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another website")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_url = input(f"\n{Fore.YELLOW}Enter URL:{Style.RESET_ALL} ").strip()
                if new_url:
                    return self.check_website(new_url)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")


    def proxy_detector(self, ip):
        """Proxy detection"""
        print(f"\n{Fore.YELLOW}[*] Checking proxy status for: {ip}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/proxydetector?key={API_KEY1}&ip={ip}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text.strip()
                
                print(f"\n{Fore.GREEN}[+] Proxy Detection Results:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
                if 'No proxy detected' in content:
                    print(f"{Fore.GREEN}[✓] No proxy detected{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] Proxy Detected!{Style.RESET_ALL}")
                    # Format any additional details
                    for line in content.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            print(f"{Fore.YELLOW}{key.strip():15}{Style.RESET_ALL}: {value.strip()}")
                        else:
                            print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} {line.strip()}")
                
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out. Try again or check the IP.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another IP")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_ip = input(f"\n{Fore.YELLOW}Enter IP address:{Style.RESET_ALL} ").strip()
                if new_ip:
                    return self.proxy_detector(new_ip)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")


    def ssl_checker(self, domain):
        """SSL certificate checker"""
        url = f"https://api.c99.nl/sslinfo?key={API_KEY1}&domain={domain}"
        self._process_request(url, "SSL Certificate")

    def scan_ports(self, target):
        """Scan ports on a given host"""
        # Clean target (remove http/https if present)
        target = target.replace('https://', '').replace('http://', '').strip()
        print(f"\n{Fore.YELLOW}[*] Scanning ports for: {target}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/portscanner?key={API_KEY1}&host={target}&timeout=30"
        
        try:
            response = requests.get(url, timeout=60)
            if response.status_code == 200 and response.text.strip():
                # Split ports and format them nicely
                ports = response.text.strip().split(',')
                open_ports = [port.strip() for port in ports]
                
                if open_ports:
                    print(f"\n{Fore.GREEN}[+] Port Scan Results:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    
                    # Common port services
                    port_services = {
                        '21': 'FTP',
                        '22': 'SSH',
                        '23': 'Telnet',
                        '25': 'SMTP',
                        '80': 'HTTP',
                        '443': 'HTTPS',
                        '3306': 'MySQL',
                        '8080': 'HTTP Proxy',
                        '110': 'POP3',
                        '143': 'IMAP',
                        '1433': 'MSSQL',
                        '3389': 'RDP',
                        '5900': 'VNC'
                    }
                    
                    # Display ports with their services
                    for port in sorted(open_ports, key=int):
                        port = port.strip()
                        service = port_services.get(port, 'Unknown service')
                        print(f"{Fore.YELLOW}Port {port:5}{Style.RESET_ALL} | {Fore.GREEN}{service}{Style.RESET_ALL}")
                    
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No open ports found{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] No results returned from the scan{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Request timed out. The scan took too long to complete.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Connection error. Please check your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error occurred: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Scan another target")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_target = input(f"\n{Fore.YELLOW}Enter IP or domain:{Style.RESET_ALL} ").strip()
                if new_target:
                    return self.scan_ports(new_target)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def resolve_cloudflare(self, domain):
        """Resolve real IP behind Cloudflare"""
        # Clean domain
        domain = domain.replace('https://', '').replace('http://', '').strip()
        
        print(f"\n{Fore.YELLOW}[*] Resolving Cloudflare IP for: {domain}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/cfresolver?key={API_KEY1}&domain={domain}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text.strip()
                if content:
                    print(f"\n{Fore.GREEN}[+] Cloudflare Resolution Results:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    
                    # Split content by <br> tags and process each result
                    results = content.split('<br>')
                    for result in results:
                        result = result.strip()
                        if result:
                            if '=>' in result:
                                domain_part, ip_part = result.split('=>', 1)
                                print(f"{Fore.YELLOW}{domain_part.strip():30}{Style.RESET_ALL} → {Fore.GREEN}{ip_part.strip()}{Style.RESET_ALL}")
                    
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No results found{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out. Try again or check the domain.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Resolve another domain")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_domain = input(f"\n{Fore.YELLOW}Enter domain:{Style.RESET_ALL} ").strip()
                if new_domain:
                    return self.resolve_cloudflare(new_domain)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def vpn_detector(self, ip):
        """VPN detection"""
        print(f"\n{Fore.YELLOW}[*] Checking VPN status for: {ip}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/proxydetector?key={API_KEY1}&ip={ip}"  # Using proxydetector endpoint
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text.strip()
                
                print(f"\n{Fore.GREEN}[+] VPN Detection Results:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
                if 'No proxy detected' in content:
                    print(f"{Fore.GREEN}[✓] No VPN detected{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] VPN Detected!{Style.RESET_ALL}")
                    # Format any additional details
                    for line in content.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            print(f"{Fore.YELLOW}{key.strip():15}{Style.RESET_ALL}: {value.strip()}")
                        else:
                            print(f"{Fore.YELLOW}[i]{Style.RESET_ALL} {line.strip()}")
                
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out. Try again or check the IP.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another IP")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_ip = input(f"\n{Fore.YELLOW}Enter IP address:{Style.RESET_ALL} ").strip()
                if new_ip:
                    return self.vpn_detector(new_ip)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def ip_logger(self, domain):
        """IP Logger setup"""
        # Clean domain
        domain = domain.replace('https://', '').replace('http://', '').strip()
        
        print(f"\n{Fore.YELLOW}[*] Setting up IP logger for: {domain}{Style.RESET_ALL}")
        
        url = f"https://api.c99.nl/iplogger?key={API_KEY1}&domain={domain}&action=loggers"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'text/plain'
            }
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text.strip()
                if content:
                    print(f"\n{Fore.GREEN}[+] IP Logger Results:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                    
                    # Process and format the results
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                print(f"{Fore.YELLOW}{key.strip():15}{Style.RESET_ALL}: {Fore.GREEN}{value.strip()}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.GREEN}[i] {line}{Style.RESET_ALL}")
                    
                    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[!] No results returned from IP Logger{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out. Try again or check the domain.{Style.RESET_ALL}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[!] Error: Connection failed. Please check your internet connection.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Try another domain")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_domain = input(f"\n{Fore.YELLOW}Enter domain:{Style.RESET_ALL} ").strip()
                if new_domain:
                    return self.ip_logger(new_domain)
                print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def _process_request(self, url, service_name):
        """Central request processor with consistent error handling"""
        try:
            print(f"\n{Fore.YELLOW}[*] Querying {service_name}...{Style.RESET_ALL}")
            
            # Add basic validation for API key
            if not API_KEY1:
                print(f"{Fore.RED}[!] Error: API_KEY1 is not set{Style.RESET_ALL}")
                return None

            # Make the request
            response = requests.get(url, timeout=30)
            
            # Handle different status codes
            if response.status_code == 200:
                if response.text.strip():
                    print(f"\n{Fore.GREEN}[+] {service_name} Results:{Style.RESET_ALL}")
                    formatted_response = response.text.replace('<br>', '\n')
                    print(formatted_response)
                else:
                    print(f"{Fore.YELLOW}[!] No results found{Style.RESET_ALL}")
            elif response.status_code == 401:
                print(f"{Fore.RED}[!] Error: Invalid API key{Style.RESET_ALL}")
            elif response.status_code == 404:
                print(f"{Fore.RED}[!] Error: Service endpoint not found. Please check your C99 subscription.{Style.RESET_ALL}")
            elif response.status_code == 429:
                print(f"{Fore.RED}[!] Error: Rate limit exceeded{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                    
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Error: Request timed out{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Unexpected error: {str(e)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        input()

    def check_email_leak(self, email):
        """Check if email has been leaked"""
        if not self.validate_email(email):
            print(f"\n{Fore.RED}[✗] Invalid email format{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Email should be in format: user@domain.com{Style.RESET_ALL}")
            return False
        
        print(f"\n{Fore.YELLOW}[*] Checking email leaks...{Style.RESET_ALL}")
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {
            'User-Agent': 'SecurityScanner',
            'hibp-api-key': API_KEY2
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                breaches = response.json()
                breaches = sorted(breaches, key=lambda x: x.get('BreachDate', ''), reverse=True)
                
                print(f"\n{Fore.RED}[!] Email was found in {len(breaches)} data breaches:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
                for i, breach in enumerate(breaches, 1):
                    print(f"\n{Fore.RED}Breach #{i}:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Name:{Style.RESET_ALL}          {breach.get('Name', 'N/A')}")
                    print(f"{Fore.YELLOW}Domain:{Style.RESET_ALL}        {breach.get('Domain', 'N/A')}")
                    print(f"{Fore.YELLOW}Breach Date:{Style.RESET_ALL}   {breach.get('BreachDate', 'N/A')}")
                    
                    if 'PwnCount' in breach:
                        print(f"{Fore.YELLOW}Compromised:{Style.RESET_ALL}    {breach['PwnCount']:,} accounts")
                        
                    if breach.get('DataClasses'):
                        print(f"{Fore.YELLOW}Leaked Data:{Style.RESET_ALL}")
                        for data_class in breach['DataClasses']:
                            print(f"  • {data_class}")
                    
                    # Add breach status indicators
                    statuses = []
                    if breach.get('IsVerified'): statuses.append("Verified")
                    if breach.get('IsSensitive'): statuses.append("Sensitive")
                    if breach.get('IsSpamList'): statuses.append("Spam List")
                    if breach.get('IsMalware'): statuses.append("Malware")
                    
                    if statuses:
                        print(f"{Fore.YELLOW}Status:{Style.RESET_ALL}        {' | '.join(statuses)}")
                    
                print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
            elif response.status_code == 404:
                print(f"\n{Fore.GREEN}[+] Good news! Email not found in any known data breaches{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}[!] Error: API returned status code {response.status_code}{Style.RESET_ALL}")
                
        except requests.exceptions.RequestException as e:
            print(f"\n{Fore.RED}[!] Error connecting to the API: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}1.{Style.RESET_ALL} Check another email")
        print(f"{Fore.CYAN}2.{Style.RESET_ALL} Return to main menu")
        
        while True:
            choice = input(f"\n{Fore.YELLOW}Enter your choice (1-2):{Style.RESET_ALL} ").strip()
            if choice == '1':
                new_email = input(f"\n{Fore.YELLOW}Enter email:{Style.RESET_ALL} ").strip()
                return self.check_email_leak(new_email)
            elif choice == '2':
                return
            else:
                print(f"{Fore.RED}Invalid choice! Please enter 1 or 2.{Style.RESET_ALL}")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    

def main():
    scanner = SecurityScanner()
    
    while True:
        scanner.clear_screen()
        scanner.print_banner()
        choice = scanner.print_menu()
        
        try:
            if choice == '0':
                print(f"\n{Fore.GREEN}Thank you for using Security Scanner Tool!{Style.RESET_ALL}")
                sys.exit(0)

                # Update the services dictionary:
            services = {
                '1': ('Subdomain Finder', 'domain', scanner.find_subdomains),
                '2': ('DNS Lookup', 'domain', scanner.dns_lookup),
                '3': ('Phone Info', 'phone number', scanner.phone_info),
                '4': ('Port Scanner', 'IP or domain', scanner.scan_ports),
                '5': ('WAF Detector', 'URL', scanner.detect_waf),
                '6': ('Website Up/Down', 'URL', scanner.check_website),
                '7': ('Cloudflare Resolver', 'domain', scanner.resolve_cloudflare),
                '8': ('IP Logger', 'domain', scanner.ip_logger),
                '9': ('Email Validator', 'email', scanner.email_validator),
                '10': ('Email Leak Checker', 'email', scanner.check_email_leak),
                '11': ('Proxy Detector', 'IP address', scanner.proxy_detector),
                '12': ('VPN Detector', 'IP address', scanner.vpn_detector)
            }
                
            # This is the missing part that handles service selection and input
            if choice in services:
                service_name, input_type, func = services[choice]
                while True:
                    target = input(f"\n{Fore.YELLOW}Enter {input_type} for {service_name}:{Style.RESET_ALL} ").strip()
                    if target:
                        if input_type == 'email' and not scanner.validate_email(target):
                            print(f"{Fore.RED}[!] Invalid email format. Please try again.{Style.RESET_ALL}")
                            continue
                        func(target)
                        break
                    print(f"{Fore.RED}[!] Input cannot be empty. Please try again.{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to return to menu...{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to return to menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program terminated by user{Style.RESET_ALL}")
        sys.exit(0)