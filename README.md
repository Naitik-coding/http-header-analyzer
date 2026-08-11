HTTP Header Analyzer

A Python-based web security tool that analyzes HTTP security headers, HTTPS behavior, CSP directives, and cookie security attributes. It provides security findings, recommendations, and a weighted security score.

Features
HTTP status code analysis
HTTPS and redirect analysis
HSTS validation
Content-Security-Policy analysis
CSP directive parsing
X-Frame-Options validation
X-Content-Type-Options validation
Referrer-Policy validation
Permissions-Policy detection
Cookie security analysis
Secure cookie detection
HttpOnly cookie detection
SameSite analysis
Security recommendations
Weighted security score
Security rating
CLI URL input
JSON report export
Network and URL error handling
Security Headers Analyzed
Header	Purpose
Strict-Transport-Security	Enforces HTTPS connections
Content-Security-Policy	Controls allowed content sources
X-Frame-Options	Helps protect against clickjacking
X-Content-Type-Options	Helps prevent MIME sniffing
Referrer-Policy	Controls referrer information
Permissions-Policy	Controls access to browser features
Cookie Security

The analyzer checks:

Secure
HttpOnly
SameSite

It also identifies the actual SameSite value:

Strict
Lax
None
Missing
Installation

Clone the repository:

git clone https://github.com/Naitik-coding/http-header-analyzer.git
cd http-header-analyzer

Install the required dependency:

py -m pip install -r requirements.txt
Usage

Analyze a target:

py analyzer.py --url https://example.com

You can also provide a URL without the protocol:

py analyzer.py --url example.com

The analyzer will default to HTTPS.

JSON Report

To save the results as a JSON file:

py analyzer.py --url https://example.com --json report.json

The JSON report contains information such as:

Target URL
Final URL
HTTP status code
HTTPS status
Redirect count
Security score
Security rating
Security header findings
Cookie analysis
Example Output
=======================================================
              HTTP HEADER ANALYZER
=======================================================

Target      : https://example.com
Final URL   : https://example.com/
Status Code : 200
HTTPS       : YES
Redirects   : 1

-------------------------------------------------------
                 SECURITY SCORE
-------------------------------------------------------

Score       : 85.0/100
Rating      : Good

-------------------------------------------------------
               SECURITY HEADERS
-------------------------------------------------------

[INFO] Strict-Transport-Security
Status         : Secure
Message        : HSTS is enabled.
Recommendation : No action required.
Project Structure
http-header-analyzer/
│
├── analyzer.py
├── requirements.txt
├── README.md
└── .gitignore
Technologies
Python
Requests
HTTP/HTTPS
Web Security
Disclaimer

This project is intended for educational purposes and authorized security testing only.

Only analyze websites and systems that you own or have explicit permission to test.

Future Improvements

Possible future improvements include:

HTML report generation
More advanced CSP analysis
Additional security headers
Automated test suite
Better cookie risk classification
Integration with security dashboards

Author
Naitik Jain
