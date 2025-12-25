# 🔐 Auth0 & Web Security Automation Scripts

> A collection of penetration testing and security automation scripts for Auth0, JWT analysis, header validation, and modern web security testing.

---

## 🚀 Overview

This repository contains Python-based tools designed to help **security researchers, bug bounty hunters, and developers** automate common and repeatable web security checks.

The goal is to reduce manual effort while improving consistency when testing authentication and authorization flows—especially **Auth0-based applications**.

### Included (and Planned) Capabilities

- ✅ Auth0 security testing automation  
- 🔜 JWT token analyzers  
- 🔜 HTTP security header checkers  
- 🔜 Open redirect & CORS testing  
- 🔜 Session fixation & CSRF testing  
- 🔜 XSS payload generators  
- 🔜 Rate limiting & PKCE enforcement tests  

> ⚠️ **Warning:**  
> These scripts must only be used on systems you own or have explicit permission to test.  
> Unauthorized testing is illegal and unethical.

---

## 🧪 Features

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

## 🧾 Scripts

### 🔹 Auth0 Security Tester (React SDK v2.6.0)

This script automates multiple security checks against applications using **Auth0 React SDK version 2.6.0**.

**Run example:**
```bash
python3 auth0_test.py \
  --domain your-domain.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --token YOUR_ACCESS_TOKEN
```

## 🛡️ Disclaimer

- Only use these scripts on systems you own or are authorized to test.
- This repository is for educational and research purposes only.
- Do not attempt to exploit or harm third-party systems without permission.

## 📚 Recommended Tools for Use

- Bug Bounty & Pentesting: Burp Suite, Nmap, Nikto, Sublist3r, Gobuster
- SOC & Security Analysis: Splunk, ELK Stack, Wireshark, OpenCanary
- Software & Dev: Python, MERN Stack, Docker, Git
- Security Concepts: XSS, CSRF, Open Redirect, JWT attacks, PKCE, OAuth 2.0

## 📫 Contact

- Email: supun2001hasanka.com
- LinkedIn: [supun2001](https://www.linkedin.com/in/supun-hasanka-908741186/)
- Portfolio: [supunhasanka.tech](https://supunhasanka.tech/)

## 📖 More Labs & Hands-On Practice
For additional security labs, automation scripts, and practical exercises, check out my blog: [Blog](https://supunhasanka.tech/blog)

