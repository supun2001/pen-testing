# Web Hacking & Bug Bounty Scripts

> A curated collection of penetration testing and web security automation scripts.  
> During my bug bounty and pentesting journey, I developed these tools to automate common security testing tasks, including **Auth0 analysis**, **JWT inspection**, **security header validation**, and **modern web vulnerability testing**.

## Disclaimer

These scripts are intended **for educational and research purposes only**.  
Use them **only on systems you own or have explicit authorization to test**.  
Any illegal or unauthorized use is strictly prohibited.

---

## Overview

This repository contains Python-based tools designed to help **security researchers, bug bounty hunters, and developers** automate common and repeatable web security checks.

The goal is to reduce manual effort while improving consistency when testing authentication and authorization flows—especially **Auth0-based applications**.

### Included (and Planned) Capabilities

- Auth0 security testing automation  
- JWT token analyzers 
- HTTP security header checkers  
- Open redirect & CORS testing  
- Session fixation & CSRF testing  
- XSS payload generators  
- Rate limiting & PKCE enforcement tests  

> **Warning:**  
> These scripts must only be used on systems you own or have explicit permission to test.  
> Unauthorized testing is illegal and unethical.

---

## Features

- **Auth0 Security Tester**  
  Automated testing for:
  - Open redirects
  - JWT weaknesses & algorithm confusion
  - Token replay risks
  - CORS misconfigurations
  - Session fixation
  - CSRF exposure
  - PKCE enforcement issues

- **Header Checker** *(coming soon)*  
  Validate security headers such as:
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - Strict-Transport-Security (HSTS)

- **JWT Analyzer** *(coming soon)*  
  Decode and inspect JWTs for:
  - Weak algorithms
  - Overly long expiration times
  - Embedded sensitive data

- **XSS Payload Generator** *(coming soon)*  
  Generate payloads for safe, manual testing of user input fields.

---

## Scripts

### Auth0 Security Tester (React SDK v2.6.0) 
[Script](scripts/auth0_test.py)

This script automates multiple security checks against applications using **Auth0 React SDK version 2.6.0**.

**Run example:**
```bash
python3 auth0_test.py --domain your-domain.auth0.com --client-id YOUR_CLIENT_ID --token YOUR_ACCESS_TOKEN
```

**Example Output:**
```bash
============================================================
SECURITY TEST REPORT
============================================================
Test completed at: 2025-12-25T12:00:00
Target Domain: example.auth0.com
Client ID: abc123

Vulnerabilities: 5
Warnings: 1
Secure: 4

⚠️  VULNERABILITIES FOUND:
  - Open Redirect: Redirect to https://evil.com was accepted
  - CORS: Wildcard CORS origin allowed
  - CSRF: Logout endpoint https://example.com/logout has no CSRF protection
  - JWT Algorithm: Weak algorithm detected: HS256
  - Sensitive Data: Possible sensitive data in token: api_key

⚡ WARNINGS:
  - Token Expiration: Token valid for 48.00 hours

Full report saved to: auth0_security_report_20251225_120000.json
```

## Disclaimer

- Only use these scripts on systems you own or are authorized to test.
- This repository is for educational and research purposes only.
- Do not attempt to exploit or harm third-party systems without permission.

## Recommended Tools for Use

- Bug Bounty & Pentesting: Burp Suite, Nmap, Nikto, Sublist3r, Gobuster
- SOC & Security Analysis: Splunk, ELK Stack, Wireshark, OpenCanary
- Software & Dev: Python, MERN Stack, Docker, Git
- Security Concepts: XSS, CSRF, Open Redirect, JWT attacks, PKCE, OAuth 2.0

## Contact

- Email: supun2001hasanka.com
- LinkedIn: [supun2001](https://www.linkedin.com/in/supun-hasanka-908741186/)
- Portfolio: [supunhasanka.tech](https://supunhasanka.tech/)

## More Labs & Hands-On Practice
For additional security labs, automation scripts, and practical exercises, check out my blog: [Blog](https://supunhasanka.tech/blog)

