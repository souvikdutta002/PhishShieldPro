"""
PhishShield Pro - Quarantine & Reporting System
Author: Souvik Dutta
"""

import json
import os
import hashlib
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass, field, asdict

QUARANTINE_FILE = "quarantine_log.json"
REPORT_FILE = "phishshield_report.json"


@dataclass
class QuarantineEntry:
    entry_id: str
    target: str
    target_type: str
    risk_score: float
    risk_level: str
    flags: List[str]
    quarantined_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "quarantined"  # quarantined | reviewed | released | deleted

    def to_dict(self):
        return asdict(self)


class QuarantineSystem:
    """Stores and manages flagged phishing targets."""

    def __init__(self, storage_path: str = "."):
        self.storage_path = storage_path
        self.quarantine_file = os.path.join(storage_path, QUARANTINE_FILE)
        self._entries: List[QuarantineEntry] = []
        self._load()

    def _load(self):
        if os.path.exists(self.quarantine_file):
            try:
                with open(self.quarantine_file, "r") as f:
                    raw = json.load(f)
                    self._entries = [QuarantineEntry(**e) for e in raw]
            except Exception:
                self._entries = []

    def _save(self):
        with open(self.quarantine_file, "w") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2)

    def _generate_id(self, target: str) -> str:
        return hashlib.md5((target + datetime.now().isoformat()).encode()).hexdigest()[:10]

    def quarantine(self, target: str, target_type: str, risk_score: float,
                   risk_level: str, flags: List[str]) -> QuarantineEntry:
        """Add a detected threat to quarantine."""
        entry = QuarantineEntry(
            entry_id=self._generate_id(target),
            target=target,
            target_type=target_type,
            risk_score=risk_score,
            risk_level=risk_level,
            flags=flags
        )
        self._entries.append(entry)
        self._save()
        return entry

    def list_quarantined(self, status: Optional[str] = None) -> List[QuarantineEntry]:
        if status:
            return [e for e in self._entries if e.status == status]
        return self._entries

    def update_status(self, entry_id: str, new_status: str) -> bool:
        for entry in self._entries:
            if entry.entry_id == entry_id:
                entry.status = new_status
                self._save()
                return True
        return False

    def clear_all(self):
        self._entries = []
        self._save()

    def get_stats(self) -> dict:
        total = len(self._entries)
        by_level = {}
        by_type = {}
        for e in self._entries:
            by_level[e.risk_level] = by_level.get(e.risk_level, 0) + 1
            by_type[e.target_type] = by_type.get(e.target_type, 0) + 1
        return {
            "total_quarantined": total,
            "by_risk_level": by_level,
            "by_type": by_type,
            "statuses": {
                s: sum(1 for e in self._entries if e.status == s)
                for s in ["quarantined", "reviewed", "released", "deleted"]
            }
        }

    def export_report(self, output_path: Optional[str] = None) -> str:
        """Export full report as JSON."""
        path = output_path or os.path.join(self.storage_path, REPORT_FILE)
        report = {
            "generated_at": datetime.now().isoformat(),
            "tool": "PhishShield Pro",
            "author": "Souvik Dutta",
            "summary": self.get_stats(),
            "entries": [e.to_dict() for e in self._entries]
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        return path
