"""
Fase 8: Google Dork Generator
Generate daftar query dork siap copy-paste ke Google.
"""

import os
from core.utils import info


DORK_TEMPLATES = [
    'site:{target} filetype:pdf',
    'site:{target} filetype:xls OR filetype:xlsx',
    'site:{target} filetype:doc OR filetype:docx',
    'site:{target} filetype:sql',
    'site:{target} filetype:env',
    'site:{target} filetype:log',
    'site:{target} filetype:bak OR filetype:backup',
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} inurl:upload',
    'site:{target} inurl:api',
    'site:{target} inurl:config',
    'site:{target} inurl:debug',
    'site:{target} inurl:test',
    'site:{target} inurl:dev',
    'site:{target} inurl:staging',
    'site:{target} inurl:internal',
    'site:{target} inurl:dashboard',
    'site:{target} inurl:panel',
    'site:{target} inurl:phpinfo',
    'site:{target} intitle:"index of"',
    'site:{target} intitle:"admin panel"',
    'site:{target} intitle:"login"',
    'site:{target} "error" OR "exception" OR "stack trace"',
    'site:{target} "password" OR "passwd" OR "secret"',
    'site:{target} "api_key" OR "apikey" OR "access_token"',
    'site:{target} "BEGIN RSA PRIVATE KEY"',
    'site:{target} ext:php inurl:?',
    'site:{target} ext:asp inurl:?',
    'site:{target} ext:aspx inurl:?',
    'site:{target} inurl:".git"',
    'site:{target} inurl:".svn"',
    'site:{target} inurl:".env"',
    'site:{target} inurl:wp-admin',
    'site:{target} inurl:phpmyadmin',
    'site:{target} "powered by" inurl:admin',
    '"@{target}" email',
    'site:{target} -www',
]

SHODAN_TEMPLATES = [
    'hostname:{target}',
    'ssl.cert.subject.cn:{target}',
    'http.title:{target}',
]

CENSYS_TEMPLATES = [
    'parsed.names: {target}',
    'parsed.subject_dn: {target}',
]


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "dork")

    # ── google dorks ─────────────────────────────────────────────
    google_dorks = [t.replace("{target}", target) for t in DORK_TEMPLATES]
    dork_file = os.path.join(out, "dork_queries.txt")
    with open(dork_file, "w") as f:
        f.write("# Google Dork Queries\n")
        f.write(f"# Target: {target}\n\n")
        for i, d in enumerate(google_dorks, 1):
            f.write(f"{i:02d}. {d}\n")

    # ── shodan ───────────────────────────────────────────────────
    shodan_file = os.path.join(out, "shodan_queries.txt")
    with open(shodan_file, "w") as f:
        f.write("# Shodan Queries\n")
        f.write(f"# Target: {target}\n\n")
        for q in SHODAN_TEMPLATES:
            f.write(q.replace("{target}", target) + "\n")

    # ── censys ───────────────────────────────────────────────────
    censys_file = os.path.join(out, "censys_queries.txt")
    with open(censys_file, "w") as f:
        f.write("# Censys Queries\n")
        f.write(f"# Target: {target}\n\n")
        for q in CENSYS_TEMPLATES:
            f.write(q.replace("{target}", target) + "\n")

    info(f"dork queries dibuat: {len(google_dorks)} google, "
         f"{len(SHODAN_TEMPLATES)} shodan, {len(CENSYS_TEMPLATES)} censys")
