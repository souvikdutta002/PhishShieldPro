"""
PhishShield Pro - Phishing Simulation Engine
Author: Souvik Dutta
"""

import random
import string
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


SIMULATION_TEMPLATES = {
    "bank_alert": {
        "subject": "URGENT: Your {bank} account has been suspended",
        "sender": "security-noreply@{bank}-secure-alerts.com",
        "body": """Dear Valued Customer,

We have detected unusual activity on your {bank} account. To prevent unauthorized access, 
your account has been temporarily suspended.

ACTION REQUIRED: Click the link below immediately to verify your identity and restore access:

http://secure-{bank}-verify.{tld}/restore?token={token}

You must complete verification within 24 hours or your account will be permanently closed.

Security Team
{bank} Customer Protection Department

This is an automated message. Do not reply.""",
        "category": "Banking Fraud"
    },
    "prize_winner": {
        "subject": "Congratulations! You have been selected as our lucky winner 🎉",
        "sender": "awards@{company}-global-lottery.tk",
        "body": """CONGRATULATIONS!

You have been randomly selected to receive a prize of $1,000,000 USD!

To claim your prize, click here: http://bit.ly/{token}

You must provide the following to release your funds:
- Full Name
- Bank Account Number  
- Date of Birth
- Copy of Government ID

Claim EXPIRES in 48 hours! Act NOW!

GlobalPrize International Committee""",
        "category": "Lottery Scam"
    },
    "password_reset": {
        "subject": "Action Required: Reset your {company} password",
        "sender": "noreply@{company}-account-security.xyz",
        "body": """Hello,

Someone requested a password reset for your {company} account associated with this email.

Click here to reset your password:
http://{company}-secure-reset.xyz/reset?id={token}&redirect=verify

If you did not make this request, your account may be compromised. 
Verify your account immediately at: http://1{company}secure.ml/verify

Do not share this link with anyone.

{company} Security Team""",
        "category": "Credential Theft"
    },
    "package_delivery": {
        "subject": "Your package could not be delivered — Action Required",
        "sender": "delivery@fedex-tracking-{token}.com",
        "body": """DELIVERY NOTIFICATION

We attempted to deliver your package but were unable to complete delivery.

Tracking Number: {token}
Status: FAILED DELIVERY

To schedule redelivery and avoid return to sender, click:
http://fedex-redelivery.{tld}/schedule?id={token}

A small redelivery fee of $1.99 will be charged to confirm your address.
Please provide your credit card details to proceed.

FedEx Delivery Services""",
        "category": "Delivery Scam"
    }
}

FAKE_BANKS = ["CitiBank", "WellsFargo", "ChaseBank", "BarclaysBank"]
FAKE_COMPANIES = ["Netflix", "PayPal", "Amazon", "Microsoft"]
SUSPICIOUS_TLDS = ["tk", "ml", "xyz", "cf", "ga", "top", "click"]


def _random_token(length=12):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


@dataclass
class SimulatedPhishingEmail:
    template_name: str
    subject: str
    sender: str
    body: str
    category: str
    indicators: List[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            "template": self.template_name,
            "subject": self.subject,
            "sender": self.sender,
            "body": self.body,
            "category": self.category,
            "indicators": self.indicators,
            "generated_at": self.generated_at
        }

    def display(self) -> str:
        sep = "─" * 60
        return f"""
{sep}
📧 SIMULATED PHISHING EMAIL
{sep}
Category  : {self.category}
Template  : {self.template_name}
From      : {self.sender}
Subject   : {self.subject}
{sep}
{self.body}
{sep}
🔍 Phishing Indicators:
{chr(10).join(f'  • {i}' for i in self.indicators)}
{sep}"""


class PhishingSimulator:
    """Generates realistic phishing email simulations for training."""

    def __init__(self):
        self.simulations_generated = 0

    def generate(self, template_name: Optional[str] = None) -> SimulatedPhishingEmail:
        """Generate a simulated phishing email."""
        if template_name and template_name in SIMULATION_TEMPLATES:
            tmpl_key = template_name
        else:
            tmpl_key = random.choice(list(SIMULATION_TEMPLATES.keys()))

        tmpl = SIMULATION_TEMPLATES[tmpl_key]
        token = _random_token()
        bank = random.choice(FAKE_BANKS)
        company = random.choice(FAKE_COMPANIES)
        tld = random.choice(SUSPICIOUS_TLDS)

        def fill(text):
            return text.format(
                bank=bank, company=company,
                tld=tld, token=token
            )

        subject = fill(tmpl["subject"])
        sender = fill(tmpl["sender"])
        body = fill(tmpl["body"])

        indicators = self._extract_indicators(subject, sender, body)
        self.simulations_generated += 1

        return SimulatedPhishingEmail(
            template_name=tmpl_key,
            subject=subject,
            sender=sender,
            body=body,
            category=tmpl["category"],
            indicators=indicators
        )

    def _extract_indicators(self, subject: str, sender: str, body: str) -> List[str]:
        indicators = []
        combined = (subject + sender + body).lower()

        if any(tld in sender for tld in [".tk", ".ml", ".xyz", ".ga", ".cf"]):
            indicators.append("Suspicious sender domain TLD (.tk, .xyz, etc.)")
        if any(w in combined for w in ["urgent", "immediately", "expires", "act now"]):
            indicators.append("Urgency/pressure language to force quick action")
        if any(w in combined for w in ["password", "credit card", "bank account", "ssn"]):
            indicators.append("Requests sensitive personal/financial information")
        if "bit.ly" in body or "tinyurl" in body:
            indicators.append("Shortened/hidden URL conceals true destination")
        if re.search(r"http://\d+", body) if __import__("re").search(r"http://\d+", body) else False:
            indicators.append("IP address used instead of domain name")
        if any(w in combined for w in ["congratulation", "winner", "selected", "prize"]):
            indicators.append("Too-good-to-be-true prize/reward offer")
        if "dear valued customer" in combined or "dear customer" in combined:
            indicators.append("Generic greeting — legitimate orgs use your name")
        if any(f"-secure" in sender or "secure-" in sender for _ in [1]):
            indicators.append("Fake 'secure' branding in sender domain")

        return indicators if indicators else ["Generic phishing template — review body carefully"]

    def list_templates(self) -> List[str]:
        return list(SIMULATION_TEMPLATES.keys())

    def generate_awareness_quiz(self, email: SimulatedPhishingEmail) -> dict:
        """Generate a quick quiz based on the simulated email."""
        return {
            "question": "Is the following email legitimate or a phishing attempt?",
            "email_preview": {
                "from": email.sender,
                "subject": email.subject,
                "body_snippet": email.body[:200] + "..."
            },
            "answer": "PHISHING",
            "explanation": f"This is a simulated {email.category} phishing email. Key red flags: {'; '.join(email.indicators[:3])}",
            "score_if_correct": 10,
            "score_if_wrong": 0
        }


# Needed for indicator extraction inside the class
import re
