# Aegis VAPT Engine

Aegis is an automated Vulnerability Assessment and Penetration Testing (VAPT) engine designed for rapid network security auditing.

## Features
*   *Automated Scanning*: Integrates Nmap for network reconnaissance.
*   *CVE Analysis*: Automatically retrieves vulnerability data for discovered ports.
*   *Secure Reporting*: Generates downloadable PDF security reports.
*   *Admin Audit*: Includes a restricted backend endpoint for secure scan history management.

## Setup & Installation
1.  *Environment*: Ensure Python 3.13 and VirtualBox/Kali Linux are configured.
2.  *Dependencies*: Run pip install -r requirements.txt.
3.  *Running*: Start the application using uvicorn app.main:app --reload.

## Security Disclaimer
This tool is for educational and authorized security auditing purposes only. Use exclusively on networks you own or have explicit permission to test.
