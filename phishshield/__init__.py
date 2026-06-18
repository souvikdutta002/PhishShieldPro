"""
PhishShield Pro
===============
A Python-based Phishing Attack Simulation and Detection Toolkit.

Author: Souvik Dutta
Version: 1.0.0
"""

from .detector import PhishingDetector, URLAnalyzer, EmailAnalyzer, DetectionResult
from .simulator import PhishingSimulator, SimulatedPhishingEmail
from .quarantine import QuarantineSystem, QuarantineEntry

__version__ = "1.0.0"
__author__ = "Souvik Dutta"
__all__ = [
    "PhishingDetector",
    "URLAnalyzer",
    "EmailAnalyzer",
    "DetectionResult",
    "PhishingSimulator",
    "SimulatedPhishingEmail",
    "QuarantineSystem",
    "QuarantineEntry"
]
