# 🛡️ PhishShield Pro

<div align="center">

```
 ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
 ██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
 ██████╔╝███████║██║███████╗███████║    ███████╗███████║██║█████╗  ██║     ██║  ██║
 ██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
 ██║     ██║  ██║██║███████║██║  ██║    ███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
```

**A Python-Based Phishing Attack Simulation and Detection Toolkit**

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-26%20Passed-brightgreen?style=flat-square)](#testing)
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)](#)

*Built by **SOUVIK DUTTA** 
</div>

---

## 📌 Overview

**PhishShield Pro** is a comprehensive cybersecurity toolkit designed to **detect phishing attempts** and **simulate phishing attacks** for educational awareness training. It helps security professionals, students, and organizations understand, identify, and defend against phishing threats.

### What is Phishing?
Phishing is a cyberattack technique where attackers impersonate legitimate entities via emails, URLs, or websites to steal sensitive information such as login credentials, credit card numbers, or personal data.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **URL Analyzer** | Detects suspicious URLs using 10+ heuristic checks |
| 📧 **Email Analyzer** | Scans email content for phishing indicators |
| 🎭 **Phishing Simulator** | Generates realistic phishing email templates for training |
| 📦 **Quarantine System** | Stores, tracks, and manages flagged threats |
| 📊 **Report Exporter** | Exports full JSON reports for audit/review |
| 🎓 **Awareness Quiz** | Interactive quiz to test phishing recognition skills |

---

## 🏗️ Project Structure

```
PhishShieldPro/
│
├── phishshield/                  # Core library
│   ├── __init__.py               # Package exports
│   ├── detector.py               # URL & Email phishing detection engine
│   ├── simulator.py              # Phishing simulation engine
│   └── quarantine.py             # Quarantine & report system
│
├── tests/
│   └── test_phishshield.py       # Full test suite (26 tests)
│
├── main.py                       # CLI entry point
├── requirements.txt              # Dependencies
└── README.md
```

---

## 🔍 Detection Capabilities

### URL Analyzer — 10 Checks
- ✅ HTTPS verification
- ✅ IP address as hostname detection
- ✅ `@` symbol in URL (classic trick)
- ✅ Suspicious TLD detection (`.tk`, `.xyz`, `.ml`, etc.)
- ✅ URL shortener detection (`bit.ly`, `tinyurl`, etc.)
- ✅ Brand spoofing with leet-speak (`paypa1`, `g00gle`)
- ✅ Excessive subdomains
- ✅ Suspicious path keywords
- ✅ URL length anomaly
- ✅ Known legitimate domain cross-check

### Email Analyzer — 7 Checks
- ✅ Urgency language detection
- ✅ Phishing keyword matching (18+ patterns)
- ✅ Embedded suspicious URL scanning
- ✅ Sender/domain spoofing detection
- ✅ Sensitive information requests
- ✅ Generic greeting patterns
- ✅ Excessive link count

### Risk Scoring
| Score | Level | Action |
|---|---|---|
| 0–19 | 🟢 LOW | Safe |
| 20–44 | 🟡 MEDIUM | Monitor |
| 45–69 | 🔴 HIGH | Quarantine |
| 70–100 | 🚨 CRITICAL | Block immediately |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- No external dependencies required (uses standard library only)

### Installation

```bash
# Clone the repository
git clone https://github.com/souvikdutta002/PhishShieldPro.git
cd PhishShieldPro
```

### Running the CLI

```bash
python main.py
```

You'll see the interactive menu:

```
[1] 🔍 Analyze a URL
[2] 📧 Analyze an Email
[3] 🎭 Generate Phishing Simulation
[4] 📦 View Quarantine Log
[5] 📊 Export Report
[6] 🎓 Awareness Quiz
[0] ❌ Exit
```

---

## 💻 Usage Examples

### Analyze a URL
```python
from phishshield import PhishingDetector

detector = PhishingDetector()
result = detector.analyze_url("http://paypa1-login.xyz/verify")

print(result.risk_level)   # CRITICAL
print(result.is_phishing)  # True
print(result.flags)        # List of detected indicators
```

### Analyze an Email
```python
result = detector.analyze_email("""
From: security@paypa1-alerts.tk
Subject: URGENT: Verify your account

Dear Customer, click here to verify your credit card...
""")

print(result.risk_score)  # 85.0
```

### Generate a Simulation
```python
from phishshield import PhishingSimulator

simulator = PhishingSimulator()
email = simulator.generate("bank_alert")
print(email.display())
```

### Quarantine Management
```python
from phishshield import QuarantineSystem

q = QuarantineSystem()
entry = q.quarantine(
    target="http://evil-phish.tk",
    target_type="url",
    risk_score=90.0,
    risk_level="CRITICAL",
    flags=["Suspicious TLD", "Brand spoofing"]
)
q.export_report()  # Saves to phishshield_report.json
```

---

## 🧪 Testing

```bash
python tests/test_phishshield.py
```

```
── URL Analyzer Tests ───────────────────────────
  ✅ PASS  IP-based URL flagged as phishing
  ✅ PASS  Legitimate Google URL has LOW risk
  ✅ PASS  PayPal spoofing URL detected as phishing
  ...

Results: 26 passed / 0 failed / 26 total
🎉 All tests passed!
```

---

## 🎯 Skills Demonstrated

- **Python OOP** — Modular class design (Detector, Simulator, Quarantine)
- **Regex & Pattern Matching** — Heuristic URL and email analysis
- **Cybersecurity Concepts** — Phishing techniques, detection systems, email security
- **Data Persistence** — JSON-based quarantine logging
- **CLI Development** — Rich terminal interface with ANSI colors
- **Test-Driven Development** — 26 unit/integration tests

---

## ⚠️ Disclaimer

This tool is built **for educational purposes only** as part of a cybersecurity internship project. The phishing simulation templates are intended solely for **security awareness training** within authorized environments. Do not use this tool to conduct unauthorized phishing attacks.

---

## 👤 Author (Souvik Dutta)
  
<h2 align="center">✨ Thank You for Visiting My Profile ✨</h2>

<p align="center">
I truly appreciate you taking the time to explore my GitHub profile.<br>
I'm constantly learning and building projects in <b>Cybersecurity, Ethical Hacking, and Software Development</b>.
</p>

<p align="center">
⭐ Consider giving a <b>Star</b> to the repositories you like <br>
🍴 Feel free to <b>Fork</b> and explore the code <br>
🤝 Let's connect and collaborate
</p>

<p align="center">
<img src="https://img.shields.io/badge/Focus-Cybersecurity-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Learning-Ethical%20Hacking-green?style=for-the-badge">
<img src="https://img.shields.io/badge/Goal-Penetration_Testing-red?style=for-the-badge">
</p>

<p align="center">
<i>“Security is not a product, but a continuous process.”</i>
</p>

<p align="center">


---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
