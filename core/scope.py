"""
Scope matcher — menentukan apakah sebuah host boleh (in-scope) dites.

Aturan pola (satu per baris / item):
  example.com            → exact, hanya host itu
  *.example.com          → apex + semua subdomain (a.example.com, a.b.example.com, example.com)
  example.*.google.com   → middle wildcard (example.us.google.com, example.eu.google.com)
  example.*              → TLD wildcard (example.com, example.co.id, example.de)
  !blog.example.com      → DIKECUALIKAN (out of scope), menang atas pola allow
  !*.dev.example.com     → kecualikan seluruh cabang dev

Default-deny: host yang tidak cocok pola allow mana pun = out of scope.
Bila scope KOSONG (tak ada pola allow), check() mengembalikan (True, "scope tidak diset")
— caller yang memutuskan apakah mau memperingatkan.

Bukan kontrol keamanan: ini pagar etis & penangkap scope, bukan penegak otorisasi.
"""

from __future__ import annotations

import csv
import fnmatch as _fnmatch

# Tipe aset yang didukung recon.io (web/domain). Sisanya dilewati.
_WEB_TYPES = {"url", "wildcard", "domain", "web", ""}

# Kandidat nama kolom CSV (urut prioritas), dicocokkan case-insensitive.
_IDENT_KEYS = ["identifier", "asset_identifier", "url", "domain", "host", "target", "asset", "name"]
_TYPE_KEYS  = ["asset_type", "type", "category"]
_ELIG_KEYS  = ["eligible_for_submission", "in_scope", "eligible_for_bounty", "eligible"]


def _norm(host: str) -> str:
    """Bersihkan host: buang skema, path, port, spasi, dan turunkan ke lowercase."""
    h = (host or "").strip().lower()
    h = h.replace("http://", "").replace("https://", "")
    h = h.split("/")[0].split("?")[0]
    if ":" in h:
        h = h.split(":")[0]
    return h.rstrip(".")


def _match(pattern: str, host: str) -> bool:
    p = pattern.strip().lower().rstrip(".")
    if not p or not host:
        return False
    if "*" not in p:
        return host == p
    if p.startswith("*."):
        base = p[2:]
        # apex sendiri + semua subdomain (berapapun kedalamannya)
        return host == base or _fnmatch.fnmatch(host, p)
    # middle wildcard (example.*.google.com) atau TLD wildcard (example.*)
    return _fnmatch.fnmatch(host, p)


def _find_col(fieldnames, candidates) -> str | None:
    lower = {fn.strip().lower(): fn for fn in fieldnames if fn}
    for c in candidates:
        if c in lower:
            return lower[c]
    return None


class Scope:
    def __init__(self, allow: list[str] | None = None, deny: list[str] | None = None,
                 skipped: list[str] | None = None):
        self.allow   = [a for a in (allow or []) if a.strip()]
        self.deny    = [d for d in (deny or []) if d.strip()]
        self.skipped = list(skipped or [])

    # ── konstruksi ───────────────────────────────────────────────
    @classmethod
    def from_lines(cls, lines) -> "Scope":
        allow, deny = [], []
        for raw in lines:
            item = raw.strip()
            if not item or item.startswith("#"):
                continue
            # buang komentar inline
            item = item.split("#", 1)[0].strip()
            if not item:
                continue
            if item.startswith("!"):
                deny.append(item[1:].strip())
            else:
                allow.append(item)
        return cls(allow, deny)

    @classmethod
    def from_text(cls, text: str) -> "Scope":
        # terima pemisah koma, titik koma, spasi, atau newline
        normalized = text.replace(",", "\n").replace(";", "\n")
        return cls.from_lines(normalized.splitlines())

    @classmethod
    def from_csv(cls, path: str) -> "Scope":
        """Parse CSV scope (gaya HackerOne/Bugcrowd). Non-web di-skip & dicatat."""
        allow, deny, skipped = [], [], []
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            ident_col = _find_col(reader.fieldnames or [], _IDENT_KEYS)

            if not ident_col:
                # header tak dikenal → anggap kolom pertama = identifier
                f.seek(0)
                for row in csv.reader(f):
                    if not row:
                        continue
                    cell = row[0].strip()
                    if cell.lower() in _IDENT_KEYS:   # lewati baris header
                        continue
                    pat = _norm(cell)
                    if pat:
                        allow.append(pat)
                return cls(allow, deny, skipped)

            type_col = _find_col(reader.fieldnames, _TYPE_KEYS)
            elig_col = _find_col(reader.fieldnames, _ELIG_KEYS)

            for row in reader:
                ident = (row.get(ident_col) or "").strip()
                if not ident:
                    continue
                atype = (row.get(type_col) or "").strip().lower() if type_col else ""
                if type_col and atype not in _WEB_TYPES:
                    skipped.append(f"{ident} [{atype or '?'}]")
                    continue
                pat = _norm(ident)
                if not pat:
                    continue
                eligible = True
                if elig_col:
                    v = (row.get(elig_col) or "").strip().lower()
                    eligible = v in {"true", "1", "yes", "y", "t"}
                (allow if eligible else deny).append(pat)

        return cls(allow, deny, skipped)

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        """Auto-deteksi: .csv → parser CSV, selain itu → satu pola per baris."""
        if path.lower().endswith(".csv"):
            return cls.from_csv(path)
        with open(path) as f:
            return cls.from_lines(f)

    # ── query ────────────────────────────────────────────────────
    def is_empty(self) -> bool:
        return not self.allow and not self.deny

    def check(self, host: str) -> tuple[bool, str]:
        """Return (in_scope, alasan)."""
        h = _norm(host)
        if not h:
            return False, "host kosong"

        for d in self.deny:
            if _match(d, h):
                return False, f"dikecualikan oleh '!{d}'"

        if not self.allow:
            return True, "scope tidak diset"

        for a in self.allow:
            if _match(a, h):
                return True, f"cocok '{a}'"

        return False, "tidak cocok pola in-scope mana pun"

    def is_wildcard_match(self, host: str) -> bool:
        """True bila host in-scope LEWAT pola wildcard → enumerasi subdomain sah.
        Mencakup: *.example.com, example.*.google.com, example.*
        False bila hanya cocok pola exact atau di luar scope."""
        h = _norm(host)
        for d in self.deny:
            if _match(d, h):
                return False
        for a in self.allow:
            if "*" in a and _match(a, h):
                return True
        return False

    def filter(self, hosts) -> list[str]:
        """Kembalikan hanya host yang in-scope (jaga urutan, dedupe)."""
        out, seen = [], set()
        for host in hosts:
            h = _norm(host)
            if h and h not in seen and self.check(host)[0]:
                seen.add(h)
                out.append(host)
        return out

    def summary(self) -> str:
        parts = []
        if self.allow:
            parts.append("in: " + ", ".join(self.allow))
        if self.deny:
            parts.append("out: " + ", ".join("!" + d for d in self.deny))
        return "  |  ".join(parts) if parts else "(scope tidak diset)"

    def describe(self) -> str:
        """Ringkasan deterministik (dipakai kode & diberikan ke AI untuk diperhalus)."""
        lines = [f"in-scope ({len(self.allow)}):"]
        lines += [f"  + {a}" for a in self.allow] or ["  (kosong)"]
        if self.deny:
            lines.append(f"dikecualikan ({len(self.deny)}):")
            lines += [f"  - !{d}" for d in self.deny]
        if self.skipped:
            lines.append(f"dilewati / non-web ({len(self.skipped)}):")
            lines += [f"  ~ {s}" for s in self.skipped[:15]]
            if len(self.skipped) > 15:
                lines.append(f"  ~ ... (+{len(self.skipped) - 15} lagi)")
        return "\n".join(lines)
