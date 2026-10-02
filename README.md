# PhishGuard - Email Phishing Detection System

PhishGuard is a Python-based email phishing detection system designed to identify suspicious and potentially malicious emails.

The system analyzes different parts of an email, including the sender, subject, message content, links, authentication results, and attachments. It assigns a risk score and provides a clear verdict to help users understand whether an email appears safe, suspicious, or potentially phishing.

## Features

- 📧 Email content analysis
- 🔍 Sender and domain verification
- 🔗 Suspicious URL detection
- 🎯 Lookalike and typosquatting domain detection
- ⚠️ Phishing keyword detection
- 📎 Suspicious attachment detection
- 🔐 SPF, DKIM, and DMARC result analysis
- 📊 Risk score from 0–100
- 📝 Scan history
- 📄 Report generation
- 🏷️ Custom brand protection
- 🖥️ Simple graphical user interface

## How It Works

PhishGuard follows a rule-based risk scoring approach.

It examines multiple indicators in an email and assigns points when suspicious characteristics are detected. The points are combined to generate an overall risk score.

### Risk Levels

| Score | Verdict |
|------:|---------|
| 0–24 | Looks Safe |
| 25–54 | Suspicious - Be Careful |
| 55–100 | Phishing - Do Not Trust |

## Detection Checks

PhishGuard checks for several common phishing indicators, including:

- Suspicious sender domains
- Lookalike or typosquatted domains
- Mismatched sender and Reply-To addresses
- Failed email authentication results
- Urgent or threatening language
- Requests for passwords, OTPs, banking information, or payments
- Suspicious or shortened URLs
- Raw IP addresses in links
- Unusual domain structures
- Dangerous file attachments
- Macro-enabled Office files
- HTML attachments
- Links that display one website but redirect to another

## Technologies Used

- **Python 3.8+**
- **Tkinter** - Graphical User Interface
- **Python Standard Library**
- Regular Expressions
- JSON
- Email Parsing
- URL Analysis

## Installation
No external Python packages are required.
Make sure Python 3.8 or later is installed on your system.

Check your Python version:
```bash
python --version
```

## How to Run
```bash
python phishguard.py
```

## How to Use
1. Open PhishGuard.
2. Paste an email into the email content area or open an .eml file.
3. Click **Analyze**.
4. Review the risk score and detected findings.
5. Check the Link Scanner, What to Do, and History sections.
6. Save the analysis report if required.

## Project Structure

```text
PhishGuard/
└── phishguard.py
```

## Purpose
The purpose of this project is to provide a simple security tool for analyzing emails and identifying common phishing indicators using a rule-based detection approach.
It can also serve as a learning project for understanding email security, phishing techniques, URL analysis, and basic threat detection.

## Disclaimer
PhishGuard is a rule-based detection tool and should not be considered a replacement for professional email security solutions.
A "Looks Safe" result does not guarantee that an email is completely safe. Users should always verify suspicious emails through trusted channels.

## Author
**Syed Ali Fathima**
B.Tech - Cyber Security
