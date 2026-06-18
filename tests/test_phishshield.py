"""
PhishShield Pro - Test Suite
Author: Souvik Dutta
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishshield.detector import PhishingDetector, URLAnalyzer, EmailAnalyzer
from phishshield.simulator import PhishingSimulator
from phishshield.quarantine import QuarantineSystem

# ─── Colors ───────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed = 0
failed = 0


def check(description: str, condition: bool):
    global passed, failed
    if condition:
        print(f"  {GREEN}✅ PASS{RESET}  {description}")
        passed += 1
    else:
        print(f"  {RED}❌ FAIL{RESET}  {description}")
        failed += 1


def section(title: str):
    print(f"\n{BOLD}{CYAN}── {title} {'─' * (45 - len(title))}{RESET}")


# ─── URL Detection Tests ───────────────────────────────────────────────────────
section("URL Analyzer Tests")
detector = PhishingDetector()

r = detector.analyze_url("http://192.168.1.1/paypal/login")
check("IP-based URL flagged as phishing", r.is_phishing)
check("IP URL has HIGH or CRITICAL risk", r.risk_level in ("HIGH", "CRITICAL"))

r = detector.analyze_url("https://www.google.com")
check("Legitimate Google URL has LOW risk", r.risk_level == "LOW")
check("Google URL not flagged as phishing", not r.is_phishing)

r = detector.analyze_url("http://paypa1-secure-login.xyz/verify?account=true")
check("PayPal spoofing URL detected as phishing", r.is_phishing)

r = detector.analyze_url("https://bit.ly/3abcDEF")
check("URL shortener gets a medium+ score", r.risk_score >= 15)

r = detector.analyze_url("http://secure-amazon-login-verify.tk/update?user=123&redirect=bank")
check("Long suspicious amazon-fake URL is phishing", r.is_phishing)

# ─── Email Detection Tests ─────────────────────────────────────────────────────
section("Email Analyzer Tests")

phishing_email = """
From: security-noreply <alerts@paypa1-secure.xyz>
Subject: URGENT: Verify your account immediately

Dear Customer,

Unusual activity detected on your account. Click immediately to verify:
http://paypal-login-secure.tk/verify?token=abc123

Provide your credit card number and password to continue.
Your account expires in 24 hours. Act now!
"""

r = detector.analyze_email(phishing_email)
check("Phishing email correctly detected", r.is_phishing)
check("Phishing email has HIGH/CRITICAL risk", r.risk_level in ("HIGH", "CRITICAL"))
check("Phishing email has multiple flags", len(r.flags) >= 2)

legit_email = """
From: support@github.com
Subject: Your pull request was merged

Hi, your pull request #42 has been successfully merged into main.
You can view the changes at https://github.com/your-repo/pulls/42
Thanks for contributing!
"""

r = detector.analyze_email(legit_email)
check("Legitimate GitHub email has low risk", r.risk_score < 45)

# ─── Simulator Tests ───────────────────────────────────────────────────────────
section("Phishing Simulator Tests")
simulator = PhishingSimulator()

sim = simulator.generate()
check("Simulator generates an email", sim is not None)
check("Simulated email has a subject", len(sim.subject) > 0)
check("Simulated email has a body", len(sim.body) > 0)
check("Simulated email has indicators", len(sim.indicators) > 0)
check("Simulated email has a category", len(sim.category) > 0)

sim2 = simulator.generate("bank_alert")
check("Template 'bank_alert' generates correctly", sim2.template_name == "bank_alert")

templates = simulator.list_templates()
check("Simulator has at least 3 templates", len(templates) >= 3)

quiz = simulator.generate_awareness_quiz(sim)
check("Quiz has question field", "question" in quiz)
check("Quiz answer is PHISHING", quiz["answer"] == "PHISHING")

# ─── Quarantine Tests ──────────────────────────────────────────────────────────
section("Quarantine System Tests")
import tempfile

with tempfile.TemporaryDirectory() as tmpdir:
    q = QuarantineSystem(storage_path=tmpdir)

    entry = q.quarantine(
        target="http://evil-phish.tk/login",
        target_type="url",
        risk_score=85.0,
        risk_level="CRITICAL",
        flags=["IP address used", "Suspicious TLD"]
    )
    check("Entry quarantined successfully", entry.entry_id is not None)
    check("Entry has correct risk level", entry.risk_level == "CRITICAL")

    entries = q.list_quarantined()
    check("Quarantine list has 1 entry", len(entries) == 1)

    updated = q.update_status(entry.entry_id, "reviewed")
    check("Status updated to 'reviewed'", updated)

    stats = q.get_stats()
    check("Stats total = 1", stats["total_quarantined"] == 1)

    import os
    report_path = os.path.join(tmpdir, "report.json")
    exported = q.export_report(output_path=report_path)
    check("Report exported to file", os.path.exists(exported))

# ─── Summary ──────────────────────────────────────────────────────────────────
total = passed + failed
print(f"\n{BOLD}{'─' * 52}{RESET}")
print(f"{BOLD}  Results: {GREEN}{passed} passed{RESET} / {RED}{failed} failed{RESET} / {total} total{RESET}")
if failed == 0:
    print(f"  {GREEN}{BOLD}🎉 All tests passed!{RESET}")
else:
    print(f"  {YELLOW}⚠  Some tests failed — review above.{RESET}")
print(f"{BOLD}{'─' * 52}{RESET}\n")

sys.exit(0 if failed == 0 else 1)
