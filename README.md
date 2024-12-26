# RE-KON TOOL

**RE-KON TOOL** is a powerful and versatile reconnaissance toolkit designed for cybersecurity professionals and enthusiasts. This tool integrates various functionalities for efficient information gathering and vulnerability assessment.

---

## Features

- **DNS Lookup**: Perform DNS lookups to retrieve record information.
- **IP Lookup**: Gather geolocation and ownership details of IP addresses.
- **Nmap Scan**: Conduct port scanning, service version detection, OS detection, and script scanning.
- **Subdomain Finder**: Discover subdomains for a target domain.
- **Fuzzer**: Test endpoints and directories using included wordlists.
- **Webserver Info**: Retrieve server-related headers and information.
- **WHOIS Info**: Fetch WHOIS details for a domain.
- **HTTP Security Header Checker**: Analyze HTTP headers for security configurations.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Required Python libraries (installed during setup)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/re-kon-tool.git
   cd re-kon-tool
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## File Structure

```
RE-KON TOOL/
├── Rekon.py        # Core script with all features
├── Fuzzing/                
│   ├── fuzz.txt             # Sample fuzzing wordlist
│   ├── locations.txt        # Endpoint wordlist
│   └── sample.txt           # Additional sample wordlist
├── subdomains/             
│   ├── Subdomain.txt        # Subdomain script
│   ├── subdomains-10000.txt # Large subdomain wordlist
│   └── subdomain_names.txt  # Additional subdomain names
├── requirements.txt         # Dependencies
```

---

## Contribution

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature/bugfix.
3. Commit your changes.
4. Submit a pull request.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Disclaimer

This tool is intended for ethical and legal purposes only. Ensure you have appropriate permissions before using it on any target.

