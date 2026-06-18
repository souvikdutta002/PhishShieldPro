"""
PhishShield Pro - Phishing Detection Engine
Author: Souvik Dutta
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Tuple
import hashlib
import json
import os


# Known phishing keywords commonly found in phishing emails/URLs
PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "click here immediately",
    "your account has been suspended", "unusual activity detected",
    "update your payment", "limited time offer", "act now",
    "congratulations you won", "free gift", "claim your prize",
    "login to verify", "security alert", "account locked",
    "reset your password immediately", "urgent action required",
    "you have been selected", "bank account", "credit card information"
]

SUSPICIOUS_URL_PATTERNS = [
    r"@",                        # Username in URL
    r"//.*//",                   # Double slash
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address as host
    r"-.*-.*-",                  # Multiple hyphens (common in fake domains)
    r"\.xyz$|\.tk$|\.ml$|\.ga$|\.cf$",       # Suspicious TLDs
    r"bit\.ly|tinyurl|goo\.gl|t\.co",        # URL shorteners
    r"paypa1|g00gle|amaz0n|micros0ft",       # Common brand spoofing
    r"secure.*login|login.*secure",
    r"account.*verify|verify.*account",
]

LEGITIMATE_DOMAINS = {
    "google.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "paypal.com", "netflix.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "youtube.com"
}


@dataclass
class DetectionResult:
    target: str
    target_type: str  # 'url' or 'email'
    risk_score: float  # 0.0 to 100.0
    risk_level: str    # LOW, MEDIUM, HIGH, CRITICAL
    flags: List[str] = field(default_factory=list)
    is_phishing: bool = False

    def to_dict(self):
        return {
            "target": self.target,
            "type": self.target_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "flags": self.flags,
            "is_phishing": self.is_phishing
        }


class URLAnalyzer:
    """Analyzes URLs for phishing indicators."""

    def analyze(self, url: str) -> Tuple[float, List[str]]:
        score = 0.0
        flags = []

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            full_url = url.lower()

            # Check 1: HTTPS
            if parsed.scheme != "https":
                score += 10
                flags.append("⚠ Not using HTTPS — data may be unencrypted")

            # Check 2: IP address as host
            if hostname and re.search(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
                score += 50
                flags.append("🚨 IP address used as domain — highly suspicious")

            # Check 3: @ symbol in URL
            if "@" in url:
                score += 25
                flags.append("🚨 '@' symbol found in URL — classic phishing trick")

            # Check 4: Suspicious TLDs
            if re.search(r"\.(xyz|tk|ml|ga|cf|pw|top|click|link)$", hostname):
                score += 20
                flags.append("⚠ Suspicious TLD detected (common in phishing domains)")

            # Check 5: URL shorteners
            if re.search(r"bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd", hostname):
                score += 15
                flags.append("⚠ URL shortener detected — destination is hidden")

            # Compute base domain (used in checks 6 and 10)
            base_domain = ".".join(hostname.split(".")[-2:]) if hostname else ""

            # Check 6: Brand spoofing
            brands = ["paypal", "google", "amazon", "microsoft", "apple", "netflix", "facebook"]
            for brand in brands:
                is_legit = f"{brand}.com" == base_domain
                if is_legit:
                    continue
                # Fuzzy leet-speak pattern: vowels/l can be digit substitutes
                pattern = re.sub(r"[aeioul]", ".", brand)
                leet_match = bool(re.search(pattern, hostname))
                fake_tld = any(t in hostname for t in [".tk", ".xyz", ".ml", ".ga", ".cf", ".click"])
                hyphenated = f"{brand}-" in hostname or f"-{brand}" in hostname
                in_host = brand in hostname
                if (in_host or leet_match) and (fake_tld or hyphenated or leet_match):
                    score += 35
                    flags.append(f"🚨 Brand spoofing detected: fake '{brand}' domain")
                    break

            # Check 7: Excessive subdomains
            subdomain_count = hostname.count(".")
            if subdomain_count > 3:
                score += 15
                flags.append(f"⚠ Too many subdomains ({subdomain_count}) — obfuscation attempt")

            # Check 8: Suspicious keywords in path
            sus_path_keywords = ["verify", "login", "secure", "account", "update", "confirm", "banking"]
            matched_path = [k for k in sus_path_keywords if k in path.lower()]
            if len(matched_path) >= 2:
                score += 20
                flags.append(f"⚠ Suspicious path keywords: {', '.join(matched_path)}")

            # Check 9: URL length
            if len(url) > 100:
                score += 10
                flags.append(f"⚠ Unusually long URL ({len(url)} chars) — possible obfuscation")

            # Check 10: Known legitimate domain check
            if base_domain in LEGITIMATE_DOMAINS and score > 0:
                score = max(0, score - 10)
                flags.append("✅ Base domain is a known legitimate domain")

        except Exception as e:
            flags.append(f"Parse error: {str(e)}")
            score += 5

        return min(score, 100.0), flags


class EmailAnalyzer:
    """Analyzes email content for phishing indicators."""

    def analyze(self, email_content: str) -> Tuple[float, List[str]]:
        score = 0.0
        flags = []
        content_lower = email_content.lower()

        # Check 1: Urgency language
        urgency_words = ["urgent", "immediately", "act now", "expires", "limited time", "last chance"]
        urgency_found = [w for w in urgency_words if w in content_lower]
        if urgency_found:
            score += len(urgency_found) * 8
            flags.append(f"⚠ Urgency language detected: {', '.join(urgency_found)}")

        # Check 2: Phishing keywords
        phish_found = [k for k in PHISHING_KEYWORDS if k in content_lower]
        if phish_found:
            score += min(len(phish_found) * 10, 40)
            flags.append(f"🚨 Phishing keywords found: {len(phish_found)} match(es)")

        # Check 3: Suspicious links
        url_pattern = re.findall(r"https?://[^\s]+", email_content)
        url_analyzer = URLAnalyzer()
        for url in url_pattern[:3]:  # Check up to 3 URLs
            url_score, url_flags = url_analyzer.analyze(url)
            if url_score > 30:
                score += 15
                flags.append(f"🚨 Suspicious URL in email body: {url[:60]}...")

        # Check 4: Mismatched sender/domain
        sender_match = re.search(r"from:.*?<([^>]+)>", content_lower)
        if sender_match:
            sender_email = sender_match.group(1)
            for brand in ["paypal", "amazon", "google", "microsoft", "apple"]:
                if brand in sender_email and f"@{brand}.com" not in sender_email:
                    score += 30
                    flags.append(f"🚨 Sender spoofing: claims to be {brand} but domain doesn't match")

        # Check 5: Request for sensitive info
        sensitive_requests = [
            "password", "credit card", "ssn", "social security",
            "bank account", "pin number", "cvv", "date of birth"
        ]
        sensitive_found = [s for s in sensitive_requests if s in content_lower]
        if sensitive_found:
            score += min(len(sensitive_found) * 15, 45)
            flags.append(f"🚨 Requests sensitive data: {', '.join(sensitive_found)}")

        # Check 6: Poor grammar indicators
        grammar_flags = ["dear customer", "dear valued", "kindly do the needful", "do the needful"]
        grammar_found = [g for g in grammar_flags if g in content_lower]
        if grammar_found:
            score += 10
            flags.append("⚠ Generic/suspicious greeting detected (e.g., 'Dear Customer')")

        # Check 7: Excessive links
        link_count = len(re.findall(r"https?://", email_content))
        if link_count > 5:
            score += 15
            flags.append(f"⚠ Too many links in email ({link_count}) — unusual for legitimate emails")

        return min(score, 100.0), flags


class PhishingDetector:
    """Main detector — routes to URL or Email analyzer."""

    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.email_analyzer = EmailAnalyzer()

    def _score_to_level(self, score: float) -> Tuple[str, bool]:
        if score < 20:
            return "LOW", False
        elif score < 45:
            return "MEDIUM", False
        elif score < 70:
            return "HIGH", True
        else:
            return "CRITICAL", True

    def analyze_url(self, url: str) -> DetectionResult:
        score, flags = self.url_analyzer.analyze(url)
        level, is_phishing = self._score_to_level(score)
        return DetectionResult(
            target=url,
            target_type="url",
            risk_score=round(score, 1),
            risk_level=level,
            flags=flags,
            is_phishing=is_phishing
        )

    def analyze_email(self, email_content: str) -> DetectionResult:
        score, flags = self.email_analyzer.analyze(email_content)
        level, is_phishing = self._score_to_level(score)
        preview = email_content[:60].replace("\n", " ") + "..."
        return DetectionResult(
            target=preview,
            target_type="email",
            risk_score=round(score, 1),
            risk_level=level,
            flags=flags,
            is_phishing=is_phishing
        )

    def batch_analyze(self, items: List[str], item_type: str = "url") -> List[DetectionResult]:
        results = []
        for item in items:
            if item_type == "url":
                results.append(self.analyze_url(item))
            else:
                results.append(self.analyze_email(item))
        return results
