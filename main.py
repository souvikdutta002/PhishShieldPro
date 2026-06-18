#!/usr/bin/env python3
"""
PhishShield Pro - CLI Interface
Author: Souvik Dutta
"""

import sys
import os
import json
from typing import Optional

# Add parent dir to path so we can import phishshield
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishshield.detector import PhishingDetector
from phishshield.simulator import PhishingSimulator
from phishshield.quarantine import QuarantineSystem

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = f"""
{RED}{BOLD}
 ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
 ██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
 ██████╔╝███████║██║███████╗███████║    ███████╗███████║██║█████╗  ██║     ██║  ██║
 ██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
 ██║     ██║  ██║██║███████║██║  ██║    ███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
{RESET}{CYAN}                     P R O  ─  Phishing Detection & Simulation Toolkit{RESET}
{DIM}                              ─────────────────────────────────{RESET}
{WHITE}                                   Author: {MAGENTA}SOUVIK DUTTA{RESET}
"""

MENU = f"""
{BOLD}{BLUE}┌─────────────────────────────────────────┐{RESET}
{BOLD}{BLUE}│          PhishShield Pro — Menu          │{RESET}
{BOLD}{BLUE}├─────────────────────────────────────────┤{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[1]{RESET} 🔍 Analyze a URL                     {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[2]{RESET} 📧 Analyze an Email                  {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[3]{RESET} 🎭 Generate Phishing Simulation       {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[4]{RESET} 📦 View Quarantine Log               {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[5]{RESET} 📊 Export Report                     {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[6]{RESET} 🎓 Awareness Quiz                    {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}│{RESET}  {CYAN}[0]{RESET} ❌ Exit                              {BOLD}{BLUE}│{RESET}
{BOLD}{BLUE}└─────────────────────────────────────────┘{RESET}
"""


def color_risk(level: str, score: float) -> str:
    bars = int(score / 10)
    bar_str = "█" * bars + "░" * (10 - bars)
    if level == "CRITICAL":
        return f"{RED}{BOLD}[{level}] {score:.1f}/100  {bar_str}{RESET}"
    elif level == "HIGH":
        return f"{RED}[{level}]    {score:.1f}/100  {bar_str}{RESET}"
    elif level == "MEDIUM":
        return f"{YELLOW}[{level}]  {score:.1f}/100  {bar_str}{RESET}"
    else:
        return f"{GREEN}[{level}]     {score:.1f}/100  {bar_str}{RESET}"


def print_result(result):
    sep = f"{DIM}{'─' * 55}{RESET}"
    verdict = f"{RED}{BOLD}⛔ PHISHING DETECTED{RESET}" if result.is_phishing else f"{GREEN}✅ LIKELY SAFE{RESET}"
    print(f"\n{sep}")
    print(f"  Target  : {CYAN}{result.target[:70]}{RESET}")
    print(f"  Type    : {result.target_type.upper()}")
    print(f"  Risk    : {color_risk(result.risk_level, result.risk_score)}")
    print(f"  Verdict : {verdict}")
    print(f"\n  {BOLD}Flags:{RESET}")
    if result.flags:
        for flag in result.flags:
            print(f"    {flag}")
    else:
        print(f"    {GREEN}No suspicious indicators found.{RESET}")
    print(sep)


def analyze_url_flow(detector: PhishingDetector, quarantine: QuarantineSystem):
    url = input(f"\n{CYAN}Enter URL to analyze:{RESET} ").strip()
    if not url:
        print(f"{YELLOW}No URL entered.{RESET}")
        return
    print(f"\n{DIM}Analyzing...{RESET}")
    result = detector.analyze_url(url)
    print_result(result)
    if result.is_phishing:
        q = quarantine.quarantine(result.target, result.target_type,
                                  result.risk_score, result.risk_level, result.flags)
        print(f"  {YELLOW}📦 Added to quarantine (ID: {q.entry_id}){RESET}\n")


def analyze_email_flow(detector: PhishingDetector, quarantine: QuarantineSystem):
    print(f"\n{CYAN}Paste email content (type END on a new line when done):{RESET}")
    lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        lines.append(line)
    content = "\n".join(lines).strip()
    if not content:
        print(f"{YELLOW}No content entered.{RESET}")
        return
    print(f"\n{DIM}Analyzing...{RESET}")
    result = detector.analyze_email(content)
    print_result(result)
    if result.is_phishing:
        q = quarantine.quarantine(result.target, result.target_type,
                                  result.risk_score, result.risk_level, result.flags)
        print(f"  {YELLOW}📦 Added to quarantine (ID: {q.entry_id}){RESET}\n")


def simulation_flow(simulator: PhishingSimulator):
    templates = simulator.list_templates()
    print(f"\n{CYAN}Available templates:{RESET}")
    for i, t in enumerate(templates, 1):
        print(f"  [{i}] {t}")
    print(f"  [0] Random")
    choice = input(f"\n{CYAN}Choose template (or 0 for random):{RESET} ").strip()
    try:
        idx = int(choice) - 1
        tmpl = templates[idx] if 0 <= idx < len(templates) else None
    except (ValueError, IndexError):
        tmpl = None
    email = simulator.generate(tmpl)
    print(email.display())


def quarantine_flow(quarantine: QuarantineSystem):
    entries = quarantine.list_quarantined()
    if not entries:
        print(f"\n{GREEN}Quarantine is empty.{RESET}")
        return
    sep = f"{DIM}{'─' * 55}{RESET}"
    print(f"\n{sep}")
    print(f"  {BOLD}Quarantine Log ({len(entries)} entries){RESET}")
    print(sep)
    for e in entries:
        risk_color = RED if e.risk_level in ("CRITICAL", "HIGH") else YELLOW
        print(f"  {DIM}ID:{RESET} {e.entry_id}  "
              f"{risk_color}[{e.risk_level}]{RESET}  "
              f"{e.target_type.upper()}  "
              f"{DIM}{e.quarantined_at[:19]}{RESET}")
        print(f"     {e.target[:65]}")
    print(sep)
    stats = quarantine.get_stats()
    print(f"\n  {BOLD}Summary:{RESET} {stats['total_quarantined']} total | "
          f"By level: {stats['by_risk_level']}")


def quiz_flow(simulator: PhishingSimulator):
    email = simulator.generate()
    quiz = simulator.generate_awareness_quiz(email)
    print(f"\n{BOLD}🎓 Awareness Quiz{RESET}")
    print(f"\n{quiz['question']}\n")
    preview = quiz['email_preview']
    print(f"  From    : {preview['from']}")
    print(f"  Subject : {preview['subject']}")
    print(f"  Body    : {preview['body_snippet']}\n")
    answer = input(f"{CYAN}Your answer (L=Legitimate / P=Phishing):{RESET} ").strip().upper()
    if answer in ("P", "PHISHING"):
        print(f"\n{GREEN}{BOLD}✅ Correct! +{quiz['score_if_correct']} points{RESET}")
    else:
        print(f"\n{RED}❌ Incorrect. This was a phishing email.{RESET}")
    print(f"\n{CYAN}Explanation:{RESET} {quiz['explanation']}")


def main():
    print(BANNER)
    detector = PhishingDetector()
    simulator = PhishingSimulator()
    quarantine = QuarantineSystem()

    while True:
        print(MENU)
        choice = input(f"{CYAN}Select option:{RESET} ").strip()

        if choice == "1":
            analyze_url_flow(detector, quarantine)
        elif choice == "2":
            analyze_email_flow(detector, quarantine)
        elif choice == "3":
            simulation_flow(simulator)
        elif choice == "4":
            quarantine_flow(quarantine)
        elif choice == "5":
            path = quarantine.export_report()
            print(f"\n{GREEN}✅ Report exported to: {path}{RESET}")
        elif choice == "6":
            quiz_flow(simulator)
        elif choice == "0":
            print(f"\n{CYAN}Thank you for using PhishShield Pro. Stay safe! 🛡️{RESET}\n")
            sys.exit(0)
        else:
            print(f"{YELLOW}Invalid option. Please try again.{RESET}")


if __name__ == "__main__":
    main()
