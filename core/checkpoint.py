"""
Checkpoint system — menyimpan progress recon per target.
Kalau script crash atau dihentikan, jalankan ulang dan
fase yang sudah selesai akan dilewati otomatis.
"""

import json
import os
from datetime import datetime


class Checkpoint:
    def __init__(self, target_dir: str, target: str):
        self.path = os.path.join(target_dir, ".checkpoint.json")
        self.target = target
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "target": self.target,
            "started": datetime.now().isoformat(),
            "completed_phases": [],
            "failed_phases": [],
        }

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self._data, f, indent=2)

    def is_done(self, fase: str) -> bool:
        return fase in self._data.get("completed_phases", [])

    def mark_done(self, fase: str):
        if fase not in self._data["completed_phases"]:
            self._data["completed_phases"].append(fase)
        self._data["last_completed"] = fase
        self._data["last_updated"] = datetime.now().isoformat()
        self._save()

    def mark_failed(self, fase: str, reason: str = ""):
        entry = {"fase": fase, "reason": reason}
        self._data.setdefault("failed_phases", []).append(entry)
        self._save()

    def completed(self) -> list:
        return self._data.get("completed_phases", [])

    def summary(self) -> dict:
        return self._data
