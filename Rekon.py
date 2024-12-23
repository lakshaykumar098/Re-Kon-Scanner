import socket
import nmap
import validators
import requests
import ipaddress
import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Back, Style

#Display Tool Name
print(Fore.GREEN +Back.BLACK+"""
``````````````````````````````````````````````````````````````````````  /**////**  /**/////       /**  **    **/////**  /**/**   /**  ``````````````````````````````````````````````````````````````````````
``````````````````````````````````````````````````````````````````````  /**   /**  /**            /** **    **     //** /**//**  /**  ``````````````````````````````````````````````````````````````````````
``````````````````````````````````````````````````````````````````````  /*******   /******* ***** /****    /**      /** /** //** /**  ``````````````````````````````````````````````````````````````````````
``````````````````````````````````````````````````````````````````````  /**///**   /**////  ///// /**/**   /**      /** /**  //**/**  ``````````````````````````````````````````````````````````````````````
``````````````````````````````````````````````````````````````````````  /**  //**  /**            /**//**  //**     **  /**   //****  ``````````````````````````````````````````````````````````````````````
``````````````````````````````````````````````````````````````````````  /**   //*  /*******       /** //**  //*******   /**    //***  ``````````````````````````````````````````````````````````````````````
``````````````````````````````````````````````````````````````````````  //    ///  ////////       //   //    ///////    ///     //// ```````````````````````````````````````````````````````````````````````
`````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````By- Lakshay"""+ Style.RESET_ALL)

# Gives Details Such as Domain ip, Loaction, Dns records, Connected Domains 
def dnsLookUp(Input):
    
    def infrastructureAnalysis(domainName, api_key):
        # Define the API endpoint
        api_url = f"https://api.threatintelligenceplatform.com/v1/infrastructureAnalysis"  # Threat Intelligence API endpoint

        # Set up the parameters for the GET request
        params = {
            "domainName": domainName,  # The domain name for which to analyze infrastructure
            "apiKey": api_key  # The API key to authenticate with the service
        }

        try:
            # Make the GET request to the API with the specified URL and parameters
            response = requests.get(api_url, params=params)

            # Check if the request was successful (HTTP status code 200)
            if response.status_code == 200:
                # Parse the JSON response from the API
                data = response.json()[0]  # Access the first object in the response data

                # Print the DNS Lookup section header
                print(Fore.GREEN + f"\nDNS Lookup for {domainName}:" + Style.RESET_ALL)

                # Iterate over the response data, printing all sections except "subnetwork"
                for info in data.items():
                    if not info[0] == 'subnetwork':  # Skip the "subnetwork" section
                        # If the current section is "geolocation", process its nested data
                        if info[0] == 'geolocation':
                            # Loop through each geolocation detail and print its key-value pair
                            for j in info[1]:
                                print(Fore.GREEN + f"[+]{j}: {info[1][j]}" + Style.RESET_ALL)
                        else:
                            # For other sections, print the key-value pair directly
                            print(Fore.GREEN + f"[+]{info[0]}: {info[1]}" + Style.RESET_ALL)
            else:
                # If the request failed, print the status code and error message
                print(Fore.GREEN + f"Failed to fetch data. Status code: {response.status_code}" + Style.RESET_ALL)
                print(Fore.GREEN + f"Error message: {response.text}" + Style.RESET_ALL)

        except Exception as e:
            # Catch any exceptions that occur and print the error message
            print(Fore.GREEN + f"An error occurred: {e}" + Style.RESET_ALL)


    def dnsRecords(domainName):
    # Initialize a list to store DNS records
        dns_records = []

        # List of DNS record types to query
        rtypes = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME"]

        # Create a DNS resolver instance
        rs = dns.resolver.Resolver()

        # Loop through each DNS record type to query
        for rtype in rtypes:
            try:
                # Attempt to resolve the DNS records for the current record type
                for rdata in rs.resolve(domainName, rtype):
                    # Append the resolved DNS record to the list
                    dns_records.append(f"{rtype} Records: {str(rdata)}")
            except:
                # Silently ignore any exceptions 
                pass

        # Check if any DNS records were found
        if len(dns_records) > 0:
            # Print a success message and list the DNS records
            print(Fore.GREEN + "\nDNS records found:" + Style.RESET_ALL)
            for record in dns_records:
                print(Fore.GREEN + f"[+] {record}" + Style.RESET_ALL)
        else:
            # If no records were found, print a message indicating so
            print(Fore.GREEN + "No DNS records found." + Style.RESET_ALL)


    def connected_domains(domainName, api_key):
        api_url = f"https://api.threatintelligenceplatform.com/v1/connectedDomains"

        params = {
            "domainName": domainName,  
            "apiKey": api_key 
        }

        try:
            response = requests.get(api_url, params=params)

            # Check if the request was successful (HTTP status code 200)
            if response.status_code == 200:
                # Parse the JSON response from the API
                data = response.json()
                print(Fore.GREEN + f"\nConnected Domains of {domainName}:" + Style.RESET_ALL)

                # Print the number of connected domains if available, or "N/A" if missing
                print(Fore.GREEN + f"[+] Number of domains: {data.get('numberOfDomains', 'N/A')}" + Style.RESET_ALL)

                # Print the list of connected domains if available, or "N/A" if missing
                print(Fore.GREEN + f"[+] List of domains: {data.get('domains', 'N/A')}" + Style.RESET_ALL)

            else:
                # If the request failed, print the status code and error message
                print(Fore.GREEN + f"Failed to fetch data. Status code: {response.status_code}" + Style.RESET_ALL)
                print(Fore.GREEN + f"Error message: {response.text}" + Style.RESET_ALL)

        except Exception as e:
            print(Fore.GREEN + f"An error occurred: {e}" + Style.RESET_ALL)

    # Strip any leading/trailing whitespace from the input
    Input = Input.strip()
    # Define your API key
    api_key = "Your_API_Key" # Api key

    # Check if the input is a valid URL
    if validators.url(Input):
        # Extract the domain name from the URL
        domainName = Input.split("//")[-1].split("/")[0]
        
        infrastructureAnalysis(domainName, api_key)
        dnsRecords(domainName)
        connected_domains(domainName, api_key)

    # Check if the input is a valid domain name
    elif validators.domain(Input):
        # Assign the domain name directly from the input
        domainName = Input
        
        infrastructureAnalysis(domainName, api_key)
        dnsRecords(domainName)
        connected_domains(domainName, api_key)

    # If the input is neither a valid URL nor a domain name, print an error message
    else:
        return print(Fore.GREEN + "Invalid Input" + Style.RESET_ALL)


def iplookup(Ip):
    try:
        # Strip any leading or trailing whitespace from the input
        Ip = Ip.strip()
        # Validate the IP address
        if ipaddress.ip_address(Ip):
            # Define the API key for the reverse IP lookup service
            api_key = "Your_API_Key"  # API key
            
            # Construct the API URL with the IP address, API key, and output format
            url = f'https://api.viewdns.info/reverseip/?host={Ip}&apikey={api_key}&output=json'
            
            # Make the GET request to the API
            response = requests.get(url)
            
            # Check if the response status code indicates success (200 OK)
            if response.status_code == 200:
                # Parse the JSON response from the API
                data = response.json()
                
                # Extract the list of domains associated with the IP address
                domains = data['response'].get('domains', [])
                
                # Print the header for the list of domains
                print(Fore.GREEN + f"\nThe Domain Names Associated with {Ip} are:" + Style.RESET_ALL)
                
                # Iterate over the domains and print each one
                for domain in domains:
                    print(Fore.GREEN + f"[+] {domain}" + Style.RESET_ALL)
            else:
                # If the response status code is not 200, print the error status
                print(Fore.GREEN + f"Error: {response.status_code}" + Style.RESET_ALL)
    except:
        # Catch any exceptions and print an error message for invalid input
        print(Fore.GREEN + "Invalid Input" + Style.RESET_ALL)

def nmapScan(input, typ):
    """
    Perform an Nmap scan on the given input (IP address or domain or Url).
    Scans can be either 'normal' or 'complete' based on the `typ` parameter.
    """

    # Perform a quick scan (-F) for common ports
    def normalScan(nm, ip_address):
        print(Fore.GREEN + f"\nStarting normal scan for {input}...\n" + Style.RESET_ALL)
        nm.scan(ip_address, arguments="-F")  # Quick scan with -F for fewer ports
        portScan(nm, ip_address, False)  # Process port scan results (no service version details)


    # Perform a complete scan (-A) with OS detection and service version info
    def completeScan(nm, ip_address):
        print(Fore.GREEN + f"\nStarting complete scan for {input}...\n" + Style.RESET_ALL)
        nm.scan(ip_address, arguments="-A")  # Detailed scan with -A for OS detection and versioning
        portScan(nm, ip_address, True)  # Process port scan results (with service version details)
        osInfo(nm, ip_address)  # Display OS detection results
        scriptScans(nm, ip_address)  # Display script scan results


    # Extract open and closed ports and their service versions
    def portScan(nm, ip_address, serviceVersion):
        open_ports = []
        closed_ports = []
        scanned_ports = nm[ip_address]['tcp'].keys()  # Get all scanned TCP ports

        # Categorize ports as open or closed
        for port in scanned_ports:
            if nm[ip_address]['tcp'][port]['state'] == "open":
                open_ports.append(port)
            elif nm[ip_address]['tcp'][port]['state'] == "closed":
                closed_ports.append(port)

        # Display open ports
        if open_ports:
            print(Fore.GREEN + "Open ports found:" + Style.RESET_ALL)
            for port in open_ports:
                if serviceVersion:  # Display additional service version info if enabled
                    print(Fore.GREEN +
                          f"[+] Port {port}: {nm[ip_address]['tcp'][port]['name']} {nm[ip_address]['tcp'][port]['product']} {nm[ip_address]['tcp'][port]['version']}" +
                          Style.RESET_ALL)
                else:
                    print(Fore.GREEN + f"[+] Port {port}: {nm[ip_address]['tcp'][port]['name']}" + Style.RESET_ALL)
            print()
        else:
            print(Fore.GREEN + "No open ports found.\n" + Style.RESET_ALL)

        # Display closed ports
        if closed_ports:
            print(Fore.GREEN + "Closed ports found:" + Style.RESET_ALL)
            for port in closed_ports:
                print(Fore.GREEN + f"[+] Port {port}: {nm[ip_address]['tcp'][port]['name']}" + Style.RESET_ALL)


    # Extract and display OS detection information
    def osInfo(nm, ip_address):
    
        try:
            # Retrieve OS classification and matches from the scan results
            os_classes = nm[ip_address].get('osclass', [])  # List of OS classifications
            os_matches = nm[ip_address].get('osmatch', [])  # List of OS matches

            # Print the OS Detection header
            print(Fore.GREEN + "\nOS Detection Results:" + Style.RESET_ALL)

            # Display OS class information if available
            if os_classes:
                for os_class in os_classes:
                    print(Fore.GREEN + f"[+] Type: {os_class.get('type')}" + Style.RESET_ALL)  # OS type (e.g., general purpose)
                    print(Fore.GREEN + f"[+] Vendor: {os_class.get('vendor')}" + Style.RESET_ALL)  # Vendor name
                    print(Fore.GREEN + f"[+] OS Family: {os_class.get('osfamily')}" + Style.RESET_ALL)  # OS family (e.g., Windows)
                    print(Fore.GREEN + f"[+] OS Generation: {os_class.get('osgen')}" + Style.RESET_ALL)  # OS generation (e.g., 10 for Windows 10)
                    print(Fore.GREEN + f"[+] Accuracy: {os_class.get('accuracy')}" + Style.RESET_ALL)  # Accuracy of detection
            else:
                # Print "NA" if no OS class information is available
                print(Fore.GREEN + "NA" + Style.RESET_ALL)

            # Display OS match information if available
            if os_matches:
                print(Fore.GREEN + "OS Matches:" + Style.RESET_ALL)
                for os_match in os_matches:
                    print(Fore.GREEN + f"[+] Name: {os_match.get('name')}" + Style.RESET_ALL)  # OS match name
                    print(Fore.GREEN + f"[+] Accuracy: {os_match.get('accuracy')}" + Style.RESET_ALL)  # Accuracy of the match
            else:
                # Print a message if no OS matches are available
                print(Fore.GREEN + "No OS detection results available.\n" + Style.RESET_ALL)
        except KeyError:
            # Handle cases where OS detection results are missing or the IP address is invalid
            print(Fore.GREEN + "OS detection information is not available.\n" + Style.RESET_ALL)


    # Extract and display script scan results
    def scriptScans(nm, ip_address):

        # Print header for script scanning results
        print(Fore.GREEN + "\nScript Scanning Results:" + Style.RESET_ALL)
        try:
            # Retrieve all scanned TCP ports for the target IP
            scanned_ports = nm[ip_address]['tcp'].keys()

            # Iterate through each scanned port
            for port in scanned_ports:
                # Retrieve scripts associated with the current port
                scripts = nm[ip_address]['tcp'][port].get('script', {})

                # Check if any scripts are present for the port
                if scripts:
                    print(Fore.GREEN + f"\n[+] Port {port} Scripts:\n" + Style.RESET_ALL)

                    # Iterate through each script and its output
                    for script_name, script_output in scripts.items():
                        print(Fore.GREEN + f"[+] Script Name -> {script_name} : Output -> {script_output}" + Style.RESET_ALL)
                else:
                    # Indicate no scripts found for the current port
                    print(Fore.GREEN + f"  No scripts found for port {port}" + Style.RESET_ALL)
        except Exception as e:
            # Handle cases where script scan results are unavailable or other errors occur
            print(Fore.GREEN + f"No script scanning results available. Error: {str(e)}\n" + Style.RESET_ALL)


    # Input validation and IP/domain resolution
    try:
        input = input.strip()
        if validators.url(input):
            domainName = input.split("//")[-1].split("/")[0]
            ip_address = socket.gethostbyname(domainName)  # Resolve IP address from domain
        elif validators.domain(input):
            ip_address = socket.gethostbyname(input)  # Resolve IP address from domain
        elif ipaddress.ip_address(input):
            ip_address = input  # Use the input directly as an IP address
    except:
        print(Fore.GREEN + "Invalid IP or URL" + Style.RESET_ALL)
        return

    # Initialize Nmap scanner
    nmap_path = [r"C:\Program Files (x86)\Nmap\nmap.exe"]  # Specify path to Nmap executable
    nm = nmap.PortScanner(nmap_search_path=nmap_path)

    # Determine the type of scan to perform
    if typ == "n":
        normalScan(nm, ip_address)
    elif typ == "c":
        completeScan(nm, ip_address)
    else:
        return print(Fore.GREEN + "Incorrect Option" + Style.RESET_ALL)

        
# Shows progress of a task
def progressBar(currentValue, TotalValue):
    percentage = int((currentValue / TotalValue) * 100)  # Calculate percentage completed
    progress = int((50 * currentValue) / TotalValue)  # Calculate filled portion of the bar
    # Format the progress bar with filled blocks and percentage
    loadbar = "Progress: |{:{len}}| {}%".format(progress * "█", percentage, len=50)
    # Print the progress bar in green, overwriting the previous line
    print(Fore.GREEN + loadbar + Style.RESET_ALL, end='\r')


# Converts the given input into Domain Name
def validDomain(Input):
    if validators.url(Input):
        return Input.split("//")[-1].split("/")[0]
    elif validators.domain(Input):
        return Input
    else:
        return "Invalid Input"


def subDomainFinder(Input):

    # Clean up the input and validate it as a domain name
    Input = Input.strip()
    domainName = validDomain(Input)  # Assumes validDomain() validates and extracts the domain name
    if domainName == "Invalid Input":
        return print(Fore.GREEN + domainName + Style.RESET_ALL)

    # Print a status message indicating the start of the search
    print(Fore.GREEN + f"Searching for sub-domains of {domainName}" + Style.RESET_ALL)

    # Read subdomain names from the file
    with open('subdomains/subdomains-10000.txt', 'r') as file:
        subDomains = file.read().splitlines()  # Load subdomains from file into a list

    # List to store discovered subdomains
    foundDomains = []

    # Use ThreadPoolExecutor to check subdomains concurrently
    with ThreadPoolExecutor(max_workers=50) as executor:  # Adjust max_workers as needed
        # Submit HTTP GET requests for each subdomain
        futures = {
            executor.submit(requests.get, f"https://{subDomain}.{domainName}", timeout=3): subDomain
            for subDomain in subDomains
        }

        # Process completed tasks and update the progress
        for idx, future in enumerate(as_completed(futures)):
            progressBar(idx + 1, len(subDomains))  # Update the progress bar

            try:
                # Get the result of the completed future
                response = future.result()
                # If the request is successful, add the subdomain to the found list
                if response.status_code == 200:
                    foundDomains.append(f"https://{futures[future]}.{domainName}")
            except requests.ConnectionError:
                pass  # Ignore connection errors and continue

    # Output the results
    if not foundDomains:
        # Print a message if no subdomains were found
        print(Fore.GREEN + "No Domains Found" + Style.RESET_ALL)
    else:
        # Print all found subdomains
        print(Fore.GREEN + "Domains Found:" + Style.RESET_ALL)
        for domain in foundDomains:
            print(Fore.GREEN + f"[+] {domain}" + Style.RESET_ALL)


def fuzzer(Input):

    # Clean up the input and validate it as a domain name
    Input = Input.strip()
    domainName = validDomain(Input)  # Assumes `validDomain()` validates and extracts the domain name
    if domainName == "Invalid Input":
        return print(Fore.GREEN + domainName + Style.RESET_ALL)

    # List to store valid URLs found during fuzzing
    Valid_sub_Domains = []

    # Read potential subdirectories or endpoints from the file
    with open('Fuzzing/locations.txt', 'r') as f:
        subdir = f.read().splitlines()  # Load each line as a potential directory or endpoint

    # Use ThreadPoolExecutor to make concurrent requests
    with ThreadPoolExecutor(max_workers=50) as executor:  # Adjust `max_workers` for performance
        # Submit HTTP GET requests for each directory or endpoint
        futures = {
            executor.submit(requests.get, f"https://{domainName}{dir}"): dir for dir in subdir
        }

        # Process completed tasks and update the progress bar
        for idx, future in enumerate(as_completed(futures)):
            progressBar(idx + 1, len(subdir))  # Update the progress bar

            try:
                # Get the result of the completed request
                response = future.result()
                # If the request is successful, add the URL to the valid list
                if response.status_code == 200:
                    Valid_sub_Domains.append(f"https://{domainName}{futures[future]}")
            except requests.ConnectionError:
                pass  # Ignore connection errors and continue

    # Output the results
    if len(Valid_sub_Domains) > 0:
        # Print all valid URLs found
        print(Fore.GREEN + f"Valid URLs:" + Style.RESET_ALL)
        for dir in Valid_sub_Domains:
            print(Fore.GREEN + f"{dir}" + Style.RESET_ALL)
    else:
        # Print a message if no valid URLs were found
        print(Fore.GREEN + "\nNo Valid URL Found" + Style.RESET_ALL)


def validUrl(Input):

    # Check if the input is a valid URL
    if validators.url(Input):
        return Input  # Return the URL as-is if valid

    # Check if the input is a valid domain
    elif validators.domain(Input):
        return f"https://{Input}/"  # Convert the domain into a URL format

    # Return an error message if the input is neither a URL nor a domain
    else:
        return "Invalid Input"


def webServer(Input):

    # Clean up the input and validate it as a URL
    Input = Input.strip()
    url = validUrl(Input)  # Validate and standardize the URL
    if url == "Invalid Input":
        return print(Fore.GREEN + url + Style.RESET_ALL)  # Print an error message for invalid input
    try:
        # Make an HTTP GET request to the URL
        response = requests.get(url)
        # Extract response headers
        header = response.headers

        # Loop through headers to find server-related information
        for hdr in header:
            try:
                # Check if the "Server" header is present and print its value
                if hdr == "Server":
                    print(Fore.GREEN + f"[+] The web server is running {header.get(hdr)}." + Style.RESET_ALL)
                # Check if the "X-Powered-By" header is present and print its value
                if hdr == "X-Powered-By":
                    print(Fore.GREEN + f"[+] X-Powered-By: {header.get(hdr)}." + Style.RESET_ALL)
            except Exception as e:
                # Handle unexpected errors while processing headers
                print(Fore.GREEN + f"Error while processing headers: {e}" + Style.RESET_ALL)
    except requests.ConnectionError as e:
        # Handle connection errors while making the HTTP request
        print(Fore.GREEN + f"Error: {e}" + Style.RESET_ALL)


def WhoisInfo(Input):
    # Clean up the input and validate it as a URL
    Input = Input.strip()
    url = validUrl(Input)  # Validate and standardize the URL
    if url == "Invalid Input":
        return print(Fore.GREEN + url + Style.RESET_ALL)  # Print an error message for invalid input

    try:
        # Perform a WHOIS query using the `whois` library
        whois_Info = whois.whois(url)

        # Print the WHOIS information in a formatted and user-friendly way
        print(Fore.GREEN + "\n=== WHOIS Information ===" + Style.RESET_ALL)
        print(Fore.GREEN + f"Domain name: {whois_Info.domain_name}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrar: {whois_Info.registrar}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Creation date: {whois_Info.creation_date}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Expiration date: {whois_Info.expiration_date}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Updated date: {whois_Info.updated_date}" + Style.RESET_ALL)

        print(Fore.GREEN + "\n=== Registrant Details ===" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant name: {whois_Info.name}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant phone: {whois_Info.phone}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant organization: {whois_Info.org}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant email: {whois_Info.emails}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant country: {whois_Info.country}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant state: {whois_Info.state}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant city: {whois_Info.city}" + Style.RESET_ALL)
        print(Fore.GREEN + f"Registrant address: {whois_Info.address}\n" + Style.RESET_ALL)

    except Exception as e:
        # Handle any exceptions during the WHOIS query
        print(Fore.GREEN + f"Error fetching WHOIS information: {str(e)}" + Style.RESET_ALL)


def httpSecurityHeader(Input):
    
    # Clean up the input and validate it as a URL
    Input = Input.strip()
    url = validUrl(Input)  # Validate and standardize the URL
    if url == "Invalid Input":
        return print(Fore.GREEN + url + Style.RESET_ALL)  # Print an error message for invalid input

    # Perform an HTTP GET request to fetch headers
    headers = requests.get(url).headers

    # List of HTTP security headers to check for
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "X-Content-Type-Options",
        "Feature-Policy",
        "Referrer-Policy"
    ]

    # List to store headers that are found
    found_header = []

    # Iterate over the list of security headers and check their presence
    for idx, header in enumerate(security_headers):
        progressBar(idx+1, len(security_headers))  # Update progress bar dynamically
        if header in headers:
            found_header.append(header)  # Add header to the list if it's present
    print()
    # Display the results for each security header
    for hdr in security_headers:
        if hdr in found_header:
            print(Fore.GREEN + f"[+] The {hdr} Header is Present" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + f"[+] The {hdr} Header is Missing" + Style.RESET_ALL)


while True:
    # Display menu options
    z = input(Fore.GREEN + """
    1. DNS LookUp
    2. IP LookUp
    3. Nmap Scan
    4. Sub-Domains Finder
    5. Fuzzer
    6. WebServer Info
    7. WhoIs Info
    8. HTTP Security Header Checker

Select from (1-8): """ + Style.RESET_ALL)

    # Convert user input to an integer
    z = int(z)

    if z == 1:  # Option 1: DNS Lookup
        Input = input(Fore.GREEN + "Enter Website Url/Domain: " + Style.RESET_ALL)
        dnsLookUp(Input)  # Call the function for DNS lookup
        print()

    elif z == 2:  # Option 2: IP Lookup
        Input = input(Fore.GREEN + "Enter Website IP Address: " + Style.RESET_ALL)
        iplookup(Input)  # Call the function for IP lookup
        print()

    elif z == 3:  # Option 3: Nmap Scan
        Input = input(Fore.GREEN + "Enter Website Url/Domain/IP: " + Style.RESET_ALL)
        typ = input(Fore.GREEN + "Type of Scan - Normal(n)/Complete(c): " + Style.RESET_ALL).lower()
        nmapScan(Input, typ)  # Call the function for Nmap scanning with the chosen type
        print()

    elif z == 4:  # Option 4: Sub-Domain Finder
        Input = input(Fore.GREEN + "Enter Website Url/Domain: " + Style.RESET_ALL)
        subDomainFinder(Input)  # Call the function to find subdomains
        print()

    elif z == 5:  # Option 5: Fuzzer
        Input = input(Fore.GREEN + "Enter Website Url/Domain: " + Style.RESET_ALL)
        fuzzer(Input)  # Call the function for fuzzing
        print()

    elif z == 6:  # Option 6: WebServer Info
        Input = input(Fore.GREEN + "Enter Website Url/Domain: " + Style.RESET_ALL)
        webServer(Input)  # Call the function to fetch web server information
        print()

    elif z == 7:  # Option 7: Whois Information
        Input = input(Fore.GREEN + "Enter Website Url/Domain: " + Style.RESET_ALL)
        WhoisInfo(Input)  # Call the function to fetch WHOIS information
        print()

    elif z == 8:  # Option 8: HTTP Security Header Checker
        Input = input(Fore.GREEN + "Enter Website Url/Domain: " + Style.RESET_ALL)
        httpSecurityHeader(Input)  # Call the function to check HTTP security headers
        print()

    # Ask the user if they want to continue or exit
    if input(Fore.GREEN + "Do you wish to continue (y/n): " + Style.RESET_ALL).lower() == "n":
        break  # Exit the loop if the user chooses "n"

