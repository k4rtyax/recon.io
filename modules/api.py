"""
Fase: Recon API Modern
Discovery endpoint GraphQL (introspeksi + fingerprint engine) dan
dokumen OpenAPI/Swagger beserta daftar route-nya.
"""

import os
import ssl
import json
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import info, warn, read_lines, write_lines, get_working_url, cancelled
from config import DEFAULT_USER_AGENT, TIMEOUTS


_GQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/gql",
    "/api/gql", "/query", "/api/query", "/graphiql", "/graphql/console",
    "/index.php?graphql",
]

_DOC_PATHS = [
    "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/swagger/v1/swagger.json", "/swagger-ui.html",
    "/redoc", "/api/swagger.json", "/.well-known/openapi.json",
]

_INTROSPECT = "{__schema{queryType{name} types{name kind}}}"

# urutan penting: pola paling khas didahulukan
_ENGINES = [
    ("Hasura",        ["query_root", "not found in type"]),
    ("WPGraphQL",     ["graphql_error"]),
    ("GraphQL Yoga",  ["graphql-yoga"]),
    ("Ariadne",       ["the query contains an unknown field"]),
    ("Apollo Server", ["graphql_validation_failed"]),
    ("graphql-ruby",  ["doesn't exist on type"]),
    ("Sangria",       ["(line 1, column"]),
    ("Graphene",      ["cannot query field", "' on type '"]),
    ("graphql-js",    ['cannot query field "', '" on type "']),
]

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


_CTX = _ssl_context()


def _fetch(url: str, payload: dict | None = None, timeout: int = 8) -> tuple[int, str]:
    data = None
    headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(200_000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def _is_graphql(url: str, deadline: float) -> bool:
    if time.monotonic() > deadline or cancelled():
        return False
    _, body = _fetch(url, payload={"query": "{__typename}"})
    if not body:
        return False
    try:
        data = json.loads(body)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False

    payload_data = data.get("data")
    if isinstance(payload_data, dict) and "__typename" in payload_data:
        return True
    errors = data.get("errors")
    return (
        isinstance(errors, list)
        and bool(errors)
        and isinstance(errors[0], dict)
        and "message" in errors[0]
    )


def _introspect(url: str) -> tuple[bool, dict | None]:
    _, body = _fetch(url, payload={"query": _INTROSPECT})
    if not body:
        return False, None
    try:
        data = json.loads(body)
    except ValueError:
        return False, None
    if not isinstance(data, dict):
        return False, None
    schema = (data.get("data") or {}).get("__schema") if isinstance(data.get("data"), dict) else None
    if isinstance(schema, dict) and schema.get("types"):
        return True, data
    return False, None


def _error_text(body: str) -> str:
    """Pesan error hasil parse + body mentah, kutip di dalam JSON ter-escape."""
    try:
        data = json.loads(body)
    except ValueError:
        return body
    if not isinstance(data, dict) or not isinstance(data.get("errors"), list):
        return body

    parts = []
    for e in data["errors"]:
        if isinstance(e, dict):
            parts.append(str(e.get("message", "")))
            if isinstance(e.get("extensions"), dict):
                parts.append(json.dumps(e["extensions"]))
        else:
            parts.append(str(e))
    return " ".join(parts) + " " + body


def _fingerprint(url: str) -> str:
    _, body = _fetch(url, payload={"query": "{zzzreconprobe}"})
    if not body:
        return "unknown"
    low = _error_text(body).lower()
    for engine, markers in _ENGINES:
        if all(m in low for m in markers):
            return engine
    return "unknown"


def _openapi_doc(url: str, deadline: float) -> tuple[str, list[str]]:
    if time.monotonic() > deadline or cancelled():
        return "", []
    code, body = _fetch(url)
    if code != 200 or not body:
        return "", []

    try:
        data = json.loads(body)
    except ValueError:
        low = body.lower()
        return ("ui", []) if ("swagger-ui" in low or "redoc" in low) else ("", [])

    if not isinstance(data, dict):
        return "", []
    version = data.get("openapi") or data.get("swagger")
    if not version:
        return "", []

    routes = []
    paths = data.get("paths")
    if isinstance(paths, dict):
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in methods:
                if isinstance(method, str) and method.lower() in _HTTP_METHODS:
                    routes.append(f"{method.upper():<7} {path}")
    return f"spec {version}", routes


def _from_urls_file(target_dir: str) -> tuple[list[str], list[str]]:
    path = os.path.join(target_dir, "urls", "all_urls.txt")
    if not os.path.exists(path):
        return [], []

    gql, docs = set(), set()
    for line in read_lines(path):
        low = line.lower()
        if not low.startswith("http"):
            continue
        if "graphql" in low or "/gql" in low:
            gql.add(line)
        elif "swagger" in low or "openapi" in low or "api-docs" in low:
            docs.add(line)
    return sorted(gql)[:25], sorted(docs)[:25]


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "api")
    os.makedirs(out, exist_ok=True)

    base = get_working_url(target).rstrip("/")
    deadline = time.monotonic() + TIMEOUTS["api"]

    gql_extra, doc_extra = _from_urls_file(target_dir)
    gql_cands = list(dict.fromkeys([base + p for p in _GQL_PATHS] + gql_extra))
    doc_cands = list(dict.fromkeys([base + p for p in _DOC_PATHS] + doc_extra))

    # ── GraphQL discovery ─────────────────────────────────────────
    endpoints = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_is_graphql, u, deadline): u for u in gql_cands}
        for fut in as_completed(futures):
            try:
                if fut.result():
                    endpoints.append(futures[fut])
            except Exception:
                continue
    endpoints.sort()

    # ── introspeksi & fingerprint engine ──────────────────────────
    gql_lines, fp_lines, raw = [], [], {}
    for url in endpoints:
        enabled, data = _introspect(url)
        if enabled:
            raw[url] = data
            types = len(data["data"]["__schema"].get("types") or [])
            gql_lines.append(f"{url} [introspeksi: aktif] [tipe: {types}]")
        else:
            gql_lines.append(f"{url} [introspeksi: nonaktif]")
        fp_lines.append(f"{url} [{_fingerprint(url)}]")

    write_lines(os.path.join(out, "graphql_endpoints.txt"), gql_lines)
    write_lines(os.path.join(out, "graphql_fingerprint.txt"), fp_lines)
    if raw:
        with open(os.path.join(out, "graphql_introspection.json"), "w") as f:
            json.dump(raw, f, indent=2)

    info(f"endpoint GraphQL: {len(endpoints)}")
    for line in gql_lines:
        if "aktif" in line:
            warn(f"introspeksi GraphQL terbuka: {line}")

    # ── OpenAPI / Swagger ─────────────────────────────────────────
    docs, routes = [], []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_openapi_doc, u, deadline): u for u in doc_cands}
        for fut in as_completed(futures):
            try:
                kind, found_routes = fut.result()
            except Exception:
                continue
            if kind:
                docs.append(f"{futures[fut]} [{kind}]")
                routes += found_routes

    docs.sort()
    routes = sorted(set(routes))
    write_lines(os.path.join(out, "api_docs.txt"), docs)
    write_lines(os.path.join(out, "api_endpoints.txt"), routes)

    info(f"dokumen API ditemukan: {len(docs)}, route: {len(routes)}")
    if time.monotonic() > deadline:
        warn("timeout fase api tercapai, sebagian kandidat tidak dicek")
