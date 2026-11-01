#!/usr/bin/env python3
r"""
shapecheck — C2 profile validator for TornadoC2.

Usage:
    shapecheck                              # scans ./profiles/c2/
    shapecheck profiles/c2/                 # scans ./profiles/c2/
    shapecheck profiles/c2/apple.json       # one file
    shapecheck profiles/c2/ backup/         # multiple paths
    shapecheck --build-config build.json    # enable cross-file checks
    shapecheck --explain EXT002
    shapecheck --list-checks
    shapecheck --ignore XPR001,DNS005 profiles/c2/

Exit: 0 clean, 1 errors, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

VERSION = "1.1.0"
DEFAULT_DIR = "profiles/c2"

# --- Optional: the handler's shaping module ---
def _import_shaping():
    try:
        from shaping import wrap, unwrap
        return wrap, unwrap
    except ImportError:
        pass
    here = Path(__file__).resolve().parent
    for candidate in (
        here / "shaping.py",
        here / "features" / "shaping.py",
        here.parent / "shaping.py",
        here.parent / "features" / "shaping.py",
    ):
        if candidate.is_file():
            sys.path.insert(0, str(candidate.parent))
            try:
                from shaping import wrap, unwrap
                return wrap, unwrap
            except ImportError:
                continue
    return None, None

wrap, unwrap = _import_shaping()
HAVE_SHAPING = wrap is not None

# ---------------------------------------------------------------------------
# Constants — must mirror shaping.py and shaping.go
# ---------------------------------------------------------------------------

VALID_SHAPES = ("checkin_response", "tasks_response", "results_request")
VALID_ENCODINGS = {"", "base64", "base64url", "hex", "netbios"}
VALID_PLACEMENT_KINDS = {"body", "header", "cookie"}
VALID_STATUS_ROLES = {"beacon", "tasks", "results", "error"}

PLACEHOLDER_FULL = re.compile(r"^\{\{(\w+)\}\}$")
PATH_SEG_PY = re.compile(r"^(\w+)(?:\[(\d+)\])?$")
PATH_SEG_GO = re.compile(r"^([0-9A-Za-z_]+)(?:\[(\d+)\])?$")
NON_ASCII = re.compile(r"[^\x00-\x7F]")
HEADER_INJECTION = re.compile(r"[\r\n\0]")
PLACEMENT_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
COOKIE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
DNS_VERB = re.compile(r"^[a-z0-9]$")

# RFC 7230 header token: alphanumerics plus a fixed punctuation set.
PLACEMENT_TOKEN = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")

# URL-encoded characters (%XX) never match request.path after Flask
# decodes it.
URL_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")

# :<digits> — plausible when copy-pasted from a URL that carried a port.
PORT_IN_PATH = re.compile(r":[0-9]+")

# Framework routes registered on the BEACON listener before any
# profile's routes. A profile declaring one is shadowing or shadowed.
FRAMEWORK_PATHS = re.compile(
    r"^/(stage/|beacon/?$|tasks/?$|results/?$)"
)

# Headers the framework sets itself on every response.
FRAMEWORK_HEADERS = {
    "content-type", "content-length", "set-cookie",
    "x-beacon-sleep", "x-beacon-jitter", "x-beacon-kill",
    "x-beacon-workstart", "x-beacon-workend",
    "x-beacon-spawnto", "x-payload-sig",
}

# XML/SOAP top-level names that only an XML-shaped body carries.
XML_ROOTS = {"ListBucketResult", "EnumerationResults",
             "AccessControlPolicy", "Envelope", "PutObjectRequest"}

PROBES: list[Any] = [
    {"__probe__": "ok", "n": 1},
    {"empty": {}},
    {"list": [1, 2, 3]},
    {"nested": {"a": {"b": {"c": "deep"}}}},
    {"bool": True, "null": None, "num": 3.14},
    {"unicode": "日本語テスト"},
    {"long": "x" * 500},
]

# ---------------------------------------------------------------------------
# Realism tables
# ---------------------------------------------------------------------------

# UA version floors — bump these each release. A profile below the
# floor is claiming a browser version no real client sends any more.
UA_FLOOR = {
    "chrome":  120,
    "firefox": 120,
    "safari":  17,
}

# Per-profile path hints. The key is the profile filename stem; the
# value is a list of regexes a real service of that name would
# plausibly expose. A profile whose beacon_path does not match any
# pattern is flagged as RT011.
#
# Patterns are anchored (^/) and match against the path only, not
# the host. A profile served on a path-style URL (S3, Azure) is
# validated against the first path segment, which is the bucket or
# container name.
PATH_HINTS = {
    # Amazon storefront uses /gp/ for account pages and /dp/ for
    # products; MWS API is under /gp/mws/. Sellers' SP-API is /.
    "amazon":           [r"^/gp/", r"^/(dp|api)/"],

    # iCloud web services are under /ws/ (setup.icloud.com/setup/ws/1/)
    # and per-service hosts under /ws/ as well.
    "apple-icloud":     [r"^/(ws|setup/ws)/"],

    # S3 path-style: https://s3.amazonaws.com/{bucket}/{key}
    # The first path segment is the bucket name.
    "aws-s3":           [r"^/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/"],

    # Azure Blob path-style: https://{account}.blob.core.windows.net/{container}
    "azure-blob":       [r"^/[a-z0-9][a-z0-9-]{1,61}[a-z0-9]/"],

    # Cloudflare stable base is /client/v4/ (api.cloudflare.com).
    # /cdn-cgi/ is the trace endpoint the dashboard hits.
    "cloudflare":       [r"^/(client/v4/|cdn-cgi/)"],

    # Discord HTTP API is /api/v{version}/, current default v10.
    "discord":          [r"^/api/v[0-9]+/", r"^/api/"],

    # Dropbox API v2 endpoints all start with /2/.
    "dropbox":          [r"^/2/"],

    # GitHub REST API is /repos/, /user/, /users/, /orgs/ on api.github.com;
    # GitHub Enterprise prefixes /api/v3/.
    "github":           [r"^/(repos|user|users|orgs)/", r"^/api/v3/"],

    # GitLab REST API is always /api/v4/.
    "gitlab":           [r"^/api/v4/"],

    # GA4 Data API is /v1beta/properties/{id}:runReport on
    # analyticsdata.googleapis.com. Universal Analytics /collect/ is
    # the legacy endpoint; some profiles still use it.
    "google-analytics": [r"^/(v1beta/properties/|v1/properties/|collect)"],

    # Google Drive API is /drive/v3/; uploads are /upload/drive/v3/.
    "google-drive":     [r"^/(drive/v3/|upload/drive/v3/)"],

    # Instagram private API (i.instagram.com) is /api/v1/; the
    # web client also hits /graphql/.
    "instagram":        [r"^/(api/v1/|graphql/)"],

    # Jira Cloud/Server REST is /rest/api/3/ (Cloud) or /rest/api/2/ (Server).
    # The OAuth path is /rest/oauth/.
    "jira":             [r"^/rest/(api|oauth)/"],

    # LinkedIn public API is /v2/; the internal Voyager API is /voyager/api/.
    "linkedin":         [r"^/(v2|voyager/api)/"],

    # Notion API base is https://api.notion.com/v1/.
    "notion":           [r"^/v1/"],

    # Office 365 is Microsoft Graph: /v1.0/ or /beta/. The older
    # Outlook REST surface is /api/v2.0/.
    "o365":             [r"^/(v1\.0|beta|api/v[0-9.]+)/"],

    # Okta core API is /api/v1/ on {subdomain}.okta.com.
    "okta":             [r"^/api/v1/"],

    # OneDrive is the Graph drive surface: /v1.0/me/drive/.
    "onedrive":         [r"^/v1\.0/(me|users|drives)/", r"^/me/"],

    # Salesforce REST is /services/data/vXX.X/.
    "salesforce":       [r"^/services/(data|oauth2)/"],

    # Shopify Admin API is /admin/api/{version}/.
    "shopify":          [r"^/admin/api/"],

    # Slack Web API is https://slack.com/api/{method}.
    "slack":            [r"^/api/"],

    # Spotify Web API base is https://api.spotify.com/v1/.
    "spotify":          [r"^/v1/"],

    # Stripe API base is https://api.stripe.com/v1/ (and /v2/ for the
    # newer Accounts API).
    "stripe":           [r"^/(v1|v2)/"],

    # Microsoft Teams is Microsoft Graph: /v1.0/ or /beta/.
    "teams":            [r"^/(v1\.0|beta)/"],

    # Telegram Bot API is /bot{token}/{method}; the token is digits
    # followed by a colon. Some clients also hit /bot/ and /api/.
    "telegram":         [r"^/bot[0-9]+:", r"^/(bot|api)/"],

    # Webex REST base is https://webexapis.com/v1/.
    "webex":            [r"^/v1/"],

    # YouTube Data API is /youtube/v3/ on www.googleapis.com; the
    # internal innertube API is /youtubei/.
    "youtube":          [r"^/(youtube/v3/|youtubei/)"],

    # Zoom REST API base is https://api.zoom.us/v2/.
    "zoom":             [r"^/v2/"],
}

# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckMeta:
    id: str
    severity: str          # error | warn | info | hint
    summary: str
    suggestion: str = ""
    doc: str = ""


CHECK_REGISTRY: dict[str, CheckMeta] = {}

def _reg(id: str, severity: str, summary: str,
         suggestion: str = "", doc: str = "") -> None:
    CHECK_REGISTRY[id] = CheckMeta(id, severity, summary, suggestion, doc)


# --- Routing ---
_reg("RT001", "error", "Path is not a string")
_reg("RT002", "info",  "Path is empty (framework default)")
_reg("RT003", "error", 'Path must start with "/"',
     "Prefix the path with /.")
_reg("RT004", "error", "Path contains a query string or fragment",
     "The listener matches request.path, which excludes ? and #. "
     "Two profiles declaring '/x' and '/x?y' collide.")
_reg("RT005", "error", "Path contains whitespace")
_reg("RT006", "error",
     "beacon_path / tasks_path / results_path are not distinct",
     "The handler refuses a profile whose three roles collide.")
_reg("RT007", "warn",  "All three paths are framework defaults",
     "Set explicit paths so the profile blends with the target network.")
_reg("RT008", "error", "stager.path is malformed",
     'stager.path must be a string starting with "/".')
_reg("RT009", "warn",  "stager.path collides with a role path",
     "The handler does not check stager.path in the collision rule; "
     "the earlier-registered route wins.")
_reg("RT010", "error", "Path contains a {{placeholder}}",
     "Placeholders are substituted only in template bodies. "
     "This is sent literally as part of the URL.")
_reg("RT011", "warn",  "Path does not match the profile's named application",
     "The beacon_path does not match the shape of the service the "
     "profile name claims to mimic. The path looks like the framework "
     "default or a different app's layout.")
_reg("RT012", "warn", "Path collides with a framework-reserved route",
     "The listener registers /stage/*, /identify, /api/v1/*, and "
     "/.well-known/* before any profile's routes. A profile declaring "
     "one of these is either shadowed or shadowing — either way, "
     "not what the operator intended.")
_reg("RT013", "error", "Path contains URL-encoded characters",
     "Flask's request.path is decoded. A literal %2E or %20 in a "
     "declared path will never match an incoming request.")
_reg("RT014", "warn",  "Path contains what looks like a port number",
     "Copy-paste from a URL often leaves :8080 in the path. The "
     "port belongs on the build config's url field, not the path.")

# --- Headers ---
_reg("HDR001", "error", "Header value contains CR/LF/NUL (header injection)",
     "Strip control characters from header keys and values.")
_reg("HDR002", "warn",  "Header contains a {{placeholder}} sent literally",
     "Placeholders are not substituted in headers, paths, or extra_headers. "
     "A static value is usually what you want; a real value must come from "
     "the build config, not the profile.")
_reg("HDR003", "error", "Header key or value is not a string")
_reg("HDR004", "warn",  "Accept header does not match the shaped body shape",
     "An XML-shaped template (S3 ListBucketResult, Azure "
     "EnumerationResults) served with Accept: application/json is a "
     "contradiction a defender can read.")
_reg("HDR005", "error", "Duplicate header name (case-insensitive)",
     "HTTP headers are case-insensitive. Content-Type and content-type "
     "in the same block means one silently wins at runtime, and which "
     "one is not predictable.")
_reg("HDR006", "warn",  "Content-Type contradicts the request body shape",
     "Sending Content-Type: application/json with an XML-shaped body "
     "is a two-signal mismatch a request inspector reads immediately.")
_reg("HDR007", "warn",  "Accept and Content-Type confuse JSON with XML",
     "Accept: application/json paired with Content-Type: "
     "application/xml on the same request is the shape of a client "
     "that confused the two protocols. Accept and Content-Type "
     "routinely differ on legitimate traffic (uploading binary, "
     "expecting JSON); only the JSON/XML inversion is flagged.")
_reg("HDR008", "warn",  "Header value exceeds the plausible length ceiling",
     "Headers over 8 KB are unusual. Even Authorization tokens and "
     "cookies rarely exceed 4 KB.")

# --- Status ---
_reg("STS001", "error", "status is not an object")
_reg("STS002", "warn",  "Unknown status role",
     f"Valid roles: {sorted(VALID_STATUS_ROLES)}")
_reg("STS003", "error", "Status code not in 100-599")
_reg("STS004", "error", "error status is a success code (2xx)",
     "The agent treats a response as a session failure if it matches "
     "the declared error code. A 2xx error code breaks the fallback path.")
_reg("STS005", "warn",  "beacon status is 204 (agent needs a body)",
     "204 No Content has no response body. The agent needs the body to "
     "extract the session info — a 204 check-in response loses the payload.")
_reg("STS006", "warn",  "tasks status is 204 (agent needs a body)",
     "Same as STS005 — the tasks response must carry the task payload.")

# --- Cookie ---
_reg("CKY001", "error", "cookie_name is empty or not a string")
_reg("CKY002", "error", "cookie_name contains invalid characters",
     "The listener falls back to 'sid' when the name fails "
     "[A-Za-z0-9._-]+.")

# --- Shaping structure ---
_reg("SHP001", "error", "shaping (or dns_label) is not an object")
_reg("SHP002", "warn",  "Unknown shape key in shaping",
     f"Valid shapes: {list(VALID_SHAPES)}")
_reg("SHP003", "error", "Shape value is not an object")
_reg("SHP004", "error", "template is not an object",
     "The renderer requires a JSON object at the top level.")
_reg("SHP005", "error", "extract is missing or not a string")
_reg("SHP006", "warn",  "Rendered body size exceeds the plausible ceiling",
     "Real SaaS check-in responses are small. A template that "
     "renders to >100 KB for a small probe payload is likely an "
     "authoring mistake.")
_reg("SHP007", "warn",  "Response shapes use different encodings",
     "A real service encodes the same way on every endpoint it "
     "serves. Mixed encodings are legal but implausible.")
_reg("SHP008", "warn",  "Body size varies by >20x across shapes",
     "Real services produce responses within an order of magnitude "
     "of one another. A drift this large suggests a template with "
     "an accidental bloat.")

# --- Payload placeholder ---
_reg("PLD001", "error", "No {{payload}} placeholder anywhere in the template",
     "The payload cannot ride in this shape without {{payload}}.")
_reg("PLD002", "error", "{{payload}} is embedded in a larger string",
     "The placeholder regex is ^\\{\\{(\\w+)\\}\\}$ (full match). "
     "Embedded placeholders are not substituted and the extract will "
     "base64-decode the literal string '{{payload}}'.")
_reg("PLD003", "warn",  "Multiple {{payload}} placeholders",
     "One is sufficient — the payload is duplicated on the wire.")
_reg("PLD004", "warn",  "{{ts}} is embedded in a larger string",
     "Full-match only; embedded {{ts}} is sent literally.")
_reg("PLD005", "warn",  "{{nonce}} is embedded in a larger string",
     "Full-match only; embedded {{nonce}} is sent literally.")

# --- Encoding ---
_reg("ENC001", "error", "Unknown encoding value (silent fallback to base64)",
     f"Valid encodings: {sorted(VALID_ENCODINGS - {''})}. "
     "Both sides silently fall back to base64 on an unknown value — "
     "the wire format is not what the profile says.")
_reg("ENC002", "warn",  "Encoding has surrounding whitespace",
     "Python strips; Go does not. Both fall back to base64 here, but "
     "the two sides take different paths to get there.")
_reg("ENC003", "info",  "Encoding is uppercase (harmless)")

# --- Placement ---
_reg("PLC001", "error", "placement is not an object")
_reg("PLC002", "error", "Unknown placement kind",
     f"Valid kinds: {sorted(VALID_PLACEMENT_KINDS)}")
_reg("PLC003", "error", "header/cookie placement missing a name")
_reg("PLC004", "error", "Placement name contains invalid characters",
     "The listener silently falls back to placement=body.")
_reg("PLC005", "warn",  "placement on results_request is ignored",
     "results_request is an HTTP request from the agent, not a response. "
     "Placement applies only to responses.")
_reg("PLC006", "error",
     "Placement header collides with a framework-set header",
     "The framework writes Content-Type, Set-Cookie, and X-Beacon-* "
     "on every response. A payload placed in one of those is either "
     "overwritten by the framework or overwrites a header the agent "
     "needs to parse.")
_reg("PLC007", "error", "Placement name is not a valid HTTP header token",
     "Header names are RFC 7230 tokens. A name containing : or space "
     "is a header line injection vector, not a header.")

# --- Extract path ---
_reg("EXT001", "error", "Extract path segment has invalid syntax",
     "A segment must match ^(\\w+)(\\[N\\])?$.")
_reg("EXT002", "error",
     "Segment matches Python's \\w but not Go's (ASCII-only)",
     "Python's \\w is Unicode-aware; Go's is ASCII-only. The handler "
     "accepts the profile but ValidateShapingSpec() on the agent build "
     "rejects it.")
_reg("EXT003", "error", "Segment contains non-ASCII characters",
     "The Go walker (pathSegRe) is ASCII-only and fails on the agent.")
_reg("EXT004", "error", "Round-trip failed (per-probe)",
     "wrap() then unwrap() produced a different payload. "
     "The template and extract do not agree on where the payload lives.")

# --- DNS ---
_reg("DNS001", "error",
     "DNS verb must be a single lowercase alphanumeric character")
_reg("DNS002", "error", "DNS verb collision resets all three to defaults",
     "Two verbs sharing a character is not partially recoverable: "
     "both sides reset verb_b/t/r to 'b'/'t'/'r' at once.")
_reg("DNS003", "error", "payload_chunk_size is not an integer")
_reg("DNS004", "error", "payload_chunk_size out of 1-63 range")
_reg("DNS005", "warn",  "payload_chunk_size < 16 amplifies query count",
     "Smaller chunks mean more queries per logical request — visible "
     "as traffic amplification on a monitor.")

# --- Cross-profile ---
_reg("XPR001", "error", "Path collision between profiles in the directory",
     "The handler refuses a profile whose paths collide with an "
     "already-loaded one.")
_reg("XPR002", "warn",  "Multiple profiles declare dns_label",
     "The handler reads only the alphabetically-first dns_label block. "
     "Run the listener with --beacon-profile <name> to pin the choice.")

# --- Transport ---
_reg("TRN001", "warn",  "Profile declares both shaping and dns_label",
     "Each build transport reads only one side. If you build "
     "--transport http, the dns_label block is ignored; if "
     "--transport dns, the shaping block is ignored.")
_reg("TRN002", "warn",  "Response Server header does not fit the UA family",
     "A Chrome UA served by AppleHttpServer, or a Safari UA served by "
     "Microsoft-HTTPAPI, is a two-signal mismatch a defender can read.")

# --- Profile root ---
_reg("PRF001", "error", "Profile root is not an object")
_reg("PRF002", "warn",  "user_agent is missing",
     "The built-in default is used; may not match a plausible target.")
_reg("PRF003", "warn",  "user_agent is empty")
_reg("PRF004", "warn",  "user_agent version is below the current floor",
     "A Chrome/100 or Firefox/90 UA is immediately stale — real "
     "clients update. Bump to a version within the current release "
     "window.")
_reg("PRF005", "warn",  "user_agent family and --tls-profile disagree",
     "A profile claiming Chrome with --tls-profile go sends a Go "
     "stdlib ClientHello that a JA3/JA4 lookup sees immediately. "
     "Pair a browser UA with the matching --tls-profile.")
_reg("PRF006", "warn",
     "Explicit paths declared without a shaping block",
     "A profile that changes the paths but not the bodies sends "
     "plain JSON in the framework's default structure. The paths "
     "blend; the bodies do not.")
_reg("PRF007", "warn", "Response headers do not include a Server header",
     "Every enterprise front-end sets Server. A response with only "
     "Content-Type is the shape of a hand-rolled API, not a real one.")

# ---------------------------------------------------------------------------
# User-Agent family detection
# ---------------------------------------------------------------------------

def _ua_family(ua: Any) -> Optional[str]:
    """Return 'chrome' | 'firefox' | 'safari' | None.

    Edge returns 'chrome' — Edge uses Chrome's TLS stack, so the
    uTLS profile that applies is the Chrome one.
    """
    if not isinstance(ua, str) or not ua:
        return None
    ua_lc = ua.lower()
    if "firefox/" in ua_lc:
        return "firefox"
    if "edg/" in ua_lc:
        return "chrome"
    if "chrome/" in ua_lc:
        return "chrome"
    if "safari/" in ua_lc:
        return "safari"
    return None


def _effective_encoding(enc: Any) -> str:
    """Return the encoding a shape will actually use.

    Empty, None, unrecognised, and 'base64' all resolve to base64 —
    the framework's fallback. Whitespace is stripped to match the
    Python handler's normalisation.
    """
    if not isinstance(enc, str):
        return "base64"
    stripped = enc.strip().lower()
    if stripped in VALID_ENCODINGS:
        return stripped or "base64"
    return "base64"


# ---------------------------------------------------------------------------
# Issues and per-profile results
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    id: str
    section: str
    message: str
    severity: str = "error"
    suggestion: str = ""


@dataclass
class ProfileResult:
    name: str
    path: Path
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warn")


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class Checker:
    def __init__(self, name: str, path: Path, profile: Any,
                 cfg: Optional[dict] = None):
        self.name = name
        self.path = path
        self.profile = profile
        self.cfg = cfg
        self.issues: list[Issue] = []

    def _add(self, id: str, section: str, message: str = "",
             suggestion: str = "") -> None:
        meta = CHECK_REGISTRY[id]
        self.issues.append(Issue(
            id=id,
            section=section,
            message=message or meta.summary,
            severity=meta.severity,
            suggestion=suggestion or meta.suggestion,
        ))

    # ------------------------------------------------------------------
    def run(self) -> ProfileResult:
        if not isinstance(self.profile, dict):
            self._add("PRF001", "<root>",
                      f"got {type(self.profile).__name__}, expected object")
            return ProfileResult(self.name, self.path, self.issues)

        self._check_paths()
        self._check_path_hint()
        self._check_user_agent()
        self._check_ua_freshness()
        self._check_ua_tls_consistency()
        self._check_headers()
        self._check_accept_consistency()
        self._check_content_type_consistency()
        self._check_accept_ct_consistency()
        self._check_server_consistency()
        self._check_status()
        self._check_cookie()
        self._check_shaping()
        self._check_encoding_consistency()
        self._check_size_drift()
        self._check_dns()
        self._check_stager()
        self._check_shaping_presence()
        self._check_server_presence()
        self._check_transport_hints()
        return ProfileResult(self.name, self.path, self.issues)

    # ------------------------------------------------------------------
    def _check_paths(self) -> None:
        beacon  = self.profile.get("beacon_path",  "/beacon")
        tasks   = self.profile.get("tasks_path",   "/tasks")
        results = self.profile.get("results_path", "/results")

        for role, val in (
            ("beacon_path", beacon),
            ("tasks_path", tasks),
            ("results_path", results),
        ):
            self._check_one_path(role, val)

        if len({beacon, tasks, results}) < 3:
            self._add("RT006", "paths",
                      f"beacon={beacon!r} tasks={tasks!r} "
                      f"results={results!r}")

        if (beacon, tasks, results) == ("/beacon", "/tasks", "/results"):
            self._add("RT007", "paths")

    def _check_one_path(self, section: str, path: Any) -> None:
        if not isinstance(path, str):
            self._add("RT001", section, f"got {type(path).__name__}")
            return
        if not path:
            self._add("RT002", section)
            return
        if not path.startswith("/"):
            self._add("RT003", section, f"got {path!r}")
        if "?" in path or "#" in path:
            self._add("RT004", section, f"got {path!r}")
        if " " in path:
            self._add("RT005", section, f"got {path!r}")
        if "{{" in path:
            self._add("RT010", section, f"got {path!r}")
        if FRAMEWORK_PATHS.search(path):
            self._add("RT012", section, f"got {path!r}")
        if URL_ENCODED.search(path):
            self._add("RT013", section, f"got {path!r}")
        if PORT_IN_PATH.search(path):
            self._add("RT014", section, f"got {path!r}")

    def _check_path_hint(self) -> None:
        stem = self.path.stem.split(".")[0]
        patterns = PATH_HINTS.get(stem)
        if not patterns:
            return
        # DNS-only profiles carry placeholder paths; the DNS wire
        # format has no path segment, so the check does not apply.
        if "dns_label" in self.profile and "shaping" not in self.profile:
            return
        beacon = self.profile.get("beacon_path", "")
        if not isinstance(beacon, str) or not beacon:
            return
        if not any(re.search(p, beacon) for p in patterns):
            self._add("RT011", "beacon_path",
                      f"{beacon!r} does not match {stem} shape "
                      f"({', '.join(patterns)})",
                      suggestion=(f"A profile named {stem!r} whose "
                                  f"beacon_path does not match any of "
                                  f"{patterns} is not carrying a "
                                  f"plausible {stem} shape. The path "
                                  f"looks like the framework default "
                                  f"or a different app's layout."))

    def _check_user_agent(self) -> None:
        if "user_agent" not in self.profile:
            self._add("PRF002", "user_agent")
            return
        ua = self.profile.get("user_agent")
        if not isinstance(ua, str):
            self._add("PRF003", "user_agent", f"got {type(ua).__name__}")
        elif not ua.strip():
            self._add("PRF003", "user_agent", "value is empty")

    def _check_ua_freshness(self) -> None:
        ua = self.profile.get("user_agent", "")
        if not isinstance(ua, str) or not ua:
            return
        m = re.search(r"chrome/(\d+)", ua, re.IGNORECASE)
        if m:
            v = int(m.group(1))
            if v < UA_FLOOR["chrome"]:
                self._add("PRF004", "user_agent",
                          f"Chrome/{v} below floor "
                          f"Chrome/{UA_FLOOR['chrome']}")
            return
        m = re.search(r"firefox/(\d+)", ua, re.IGNORECASE)
        if m:
            v = int(m.group(1))
            if v < UA_FLOOR["firefox"]:
                self._add("PRF004", "user_agent",
                          f"Firefox/{v} below floor "
                          f"Firefox/{UA_FLOOR['firefox']}")
            return
        if "safari/" in ua.lower():
            m = re.search(r"version/(\d+)", ua, re.IGNORECASE)
            if m:
                v = int(m.group(1))
                if v < UA_FLOOR["safari"]:
                    self._add("PRF004", "user_agent",
                              f"Safari Version/{v} below floor "
                              f"Safari/{UA_FLOOR['safari']}")

    def _check_ua_tls_consistency(self) -> None:
        if self.cfg is None:
            return
        transport = str(self.cfg.get("transport_mode", "") or "").lower()
        # QUIC and WireGuard ignore --tls-profile; the framework
        # cannot close the ClientHello gap there, so it is not a
        # lint.
        if "quic" in transport or "wireguard" in transport:
            return
        # DNS and ICMP carry no HTTP request; --tls-profile does not
        # apply. Only HTTP-shaped transports matter here.
        if not any(t in transport for t in ("http", "doh", "websocket")):
            return
        ua = self.profile.get("user_agent", "")
        tls = self.cfg.get("tls_profile", "go")
        if not isinstance(ua, str) or not isinstance(tls, str):
            return
        family = _ua_family(ua)
        if family is None:
            return
        if tls == "go":
            self._add("PRF005", "user_agent",
                      f"UA claims {family}, build uses --tls-profile go "
                      f"— a JA3/JA4 lookup sees the Go stdlib, not "
                      f"{family}")
        elif tls != family:
            self._add("PRF005", "user_agent",
                      f"UA claims {family}, build uses --tls-profile "
                      f"{tls} — the two fingerprints disagree")

    def _check_headers(self) -> None:
        for section in ("extra_headers", "request_headers",
                        "response_headers"):
            if section not in self.profile:
                continue
            headers = self.profile[section]
            if not isinstance(headers, dict):
                self._add("HDR003", section, f"got {type(headers).__name__}")
                continue
            seen_lc: dict[str, str] = {}
            for k, v in headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    self._add("HDR003", section,
                              f"header {k!r} has non-string key or value")
                    continue
                lc = k.lower()
                if lc in seen_lc:
                    self._add("HDR005", section,
                              f"header {k!r} duplicates "
                              f"{seen_lc[lc]!r} case-insensitively")
                else:
                    seen_lc[lc] = k
                if HEADER_INJECTION.search(k) or HEADER_INJECTION.search(v):
                    self._add("HDR001", section, f"header {k!r}")
                if "{{" in k or "{{" in v:
                    self._add("HDR002", section, f"header {k!r} = {v!r}")
                if len(v) > 8192:
                    self._add("HDR008", section,
                              f"header {k!r} value is {len(v)} bytes "
                              f"(>8 KB)")

    def _check_accept_consistency(self) -> None:
        """HDR004: Accept media type must not contradict an XML-shaped
        template the response carries."""
        accept = ""
        for section in ("extra_headers", "request_headers"):
            headers = self.profile.get(section)
            if isinstance(headers, dict):
                a = headers.get("Accept")
                if isinstance(a, str) and a:
                    accept = a.lower()
                    break
        if not accept:
            return
        accept_primary = accept.split(",")[0].split(";")[0].strip()
        if not accept_primary or "*/*" in accept_primary:
            return
        sh = self.profile.get("shaping")
        if not isinstance(sh, dict):
            return
        for shape_name in ("checkin_response", "tasks_response"):
            spec = sh.get(shape_name)
            if not isinstance(spec, dict):
                continue
            tmpl = spec.get("template")
            if not isinstance(tmpl, dict) or not tmpl:
                continue
            top = set(tmpl.keys())
            looks_xml = bool(top & XML_ROOTS)
            if looks_xml and "json" in accept_primary:
                self._add("HDR004", "extra_headers",
                          f"Accept={accept_primary!r} but "
                          f"{shape_name} template is XML-shaped "
                          f"(top-level {sorted(top & XML_ROOTS)})")
                return

    def _check_content_type_consistency(self) -> None:
        """HDR006: Content-Type on the request must not contradict
        the results_request template shape."""
        ct = ""
        for section in ("extra_headers", "request_headers"):
            headers = self.profile.get(section)
            if isinstance(headers, dict):
                v = headers.get("Content-Type")
                if isinstance(v, str) and v:
                    ct = v.lower()
                    break
        if not ct:
            return
        ct_primary = ct.split(",")[0].split(";")[0].strip()
        sh = self.profile.get("shaping")
        if not isinstance(sh, dict):
            return
        spec = sh.get("results_request")
        if not isinstance(spec, dict):
            return
        tmpl = spec.get("template")
        if not isinstance(tmpl, dict) or not tmpl:
            return
        top = set(tmpl.keys())
        looks_xml = bool(top & XML_ROOTS)
        if looks_xml and "json" in ct_primary:
            self._add("HDR006", "extra_headers",
                      f"Content-Type={ct_primary!r} but "
                      f"results_request template is XML-shaped "
                      f"(top-level {sorted(top & XML_ROOTS)})")

    def _check_accept_ct_consistency(self) -> None:
        """HDR007: Accept and Content-Type confuse JSON with XML.

        Accept describes response media types; Content-Type
        describes request body media types. They are independent
        headers and routinely differ on legitimate traffic
        (uploading octet-stream and expecting JSON back is normal).

        The one pattern that is almost always a mistake is a
        request that asks for JSON but claims to send XML, or the
        reverse — a client that has confused the two protocols. That
        is the only case this check fires on."""
        accept = ""
        ct = ""
        for section in ("extra_headers", "request_headers"):
            headers = self.profile.get(section)
            if not isinstance(headers, dict):
                continue
            a = headers.get("Accept")
            c = headers.get("Content-Type")
            if isinstance(a, str) and a and not accept:
                accept = a.lower()
            if isinstance(c, str) and c and not ct:
                ct = c.lower()
        if not accept or not ct:
            return
        accept_primary = accept.split(",")[0].split(";")[0].strip()
        ct_primary     = ct.split(",")[0].split(";")[0].strip()
        if not accept_primary or not ct_primary:
            return

        JSON_TYPES = {"application/json"}
        XML_TYPES  = {"application/xml", "text/xml"}
        is_json_xml_mismatch = (
            (accept_primary in JSON_TYPES and ct_primary in XML_TYPES)
            or
            (accept_primary in XML_TYPES and ct_primary in JSON_TYPES)
        )
        if is_json_xml_mismatch:
            self._add("HDR007", "extra_headers",
                      f"Accept={accept_primary!r} but "
                      f"Content-Type={ct_primary!r} — a client that "
                      f"asks for one of JSON/XML while sending the "
                      f"other has confused the two protocols")

    def _check_server_consistency(self) -> None:
        family = _ua_family(self.profile.get("user_agent", "") or "")
        if family is None:
            return
        sh = self.profile.get("response_headers")
        if not isinstance(sh, dict):
            return
        server = sh.get("Server", "")
        if not isinstance(server, str) or not server:
            return
        server_lc = server.lower()
        if family == "chrome" and "apple" in server_lc:
            self._add("TRN002", "response_headers",
                      f"Server={server!r} but UA claims Chrome — "
                      f"Apple front-ends do not typically serve "
                      f"Chrome clients as their primary audience")
        elif family == "safari" and any(
            s in server_lc for s in ("microsoft", "amazons3", "gws")
        ):
            self._add("TRN002", "response_headers",
                      f"Server={server!r} but UA claims Safari — "
                      f"Microsoft/AWS front-ends do not serve Safari "
                      f"clients as their primary audience")

    def _check_status(self) -> None:
        if "status" not in self.profile:
            return
        st = self.profile["status"]
        if not isinstance(st, dict):
            self._add("STS001", "status", f"got {type(st).__name__}")
            return
        for role, code in st.items():
            if role not in VALID_STATUS_ROLES:
                self._add("STS002", "status", f"role {role!r}")
                continue
            if not isinstance(code, int) or not (100 <= code <= 599):
                self._add("STS003", "status", f"{role}={code!r}")
        err = st.get("error")
        if isinstance(err, int) and 200 <= err < 300:
            self._add("STS004", "status", f"error={err}")
        if st.get("beacon") == 204:
            self._add("STS005", "status")
        if st.get("tasks") == 204:
            self._add("STS006", "status")

    def _check_cookie(self) -> None:
        if "cookie_name" not in self.profile:
            return
        name = self.profile["cookie_name"]
        if not isinstance(name, str) or not name:
            self._add("CKY001", "cookie_name", f"got {name!r}")
            return
        if not COOKIE_NAME.match(name):
            self._add("CKY002", "cookie_name", f"got {name!r}")

    def _check_shaping(self) -> None:
        if "shaping" not in self.profile:
            return
        sh = self.profile["shaping"]
        if not isinstance(sh, dict):
            self._add("SHP001", "shaping", f"got {type(sh).__name__}")
            return
        for key in sh:
            if key not in VALID_SHAPES:
                self._add("SHP002", f"shaping.{key}", f"got {key!r}")
        for shape in VALID_SHAPES:
            if shape in sh:
                self._check_one_shape(shape, sh[shape])

    def _check_one_shape(self, name: str, spec: Any) -> None:
        sec = f"shaping.{name}"
        if not isinstance(spec, dict):
            self._add("SHP003", sec, f"got {type(spec).__name__}")
            return

        tmpl      = spec.get("template")
        extract   = spec.get("extract")
        encoding  = spec.get("encoding", "")
        placement = spec.get("placement")

        if not isinstance(tmpl, dict):
            self._add("SHP004", f"{sec}.template",
                      f"got {type(tmpl).__name__}")
            return
        if not isinstance(extract, str) or not extract:
            self._add("SHP005", f"{sec}.extract", f"got {extract!r}")
            return

        if encoding not in (None, ""):
            if not isinstance(encoding, str):
                self._add("ENC001", f"{sec}.encoding",
                          f"got {type(encoding).__name__}")
            else:
                stripped = encoding.strip()
                lowered  = stripped.lower()
                if lowered not in VALID_ENCODINGS:
                    self._add("ENC001", f"{sec}.encoding",
                              f"got {encoding!r}")
                if encoding != stripped:
                    self._add("ENC002", f"{sec}.encoding",
                              f"got {encoding!r}")
                elif encoding != lowered:
                    self._add("ENC003", f"{sec}.encoding",
                              f"got {encoding!r}")

        if placement is not None:
            self._check_placement(f"{sec}.placement", placement, name)

        full, embedded = self._count_placeholders(tmpl, "payload")
        if full == 0 and embedded == 0:
            self._add("PLD001", f"{sec}.template")
        elif full == 0:
            self._add("PLD002", f"{sec}.template",
                      f"{embedded} embedded, 0 full-match")
        elif full > 1:
            self._add("PLD003", f"{sec}.template", f"{full} full-match")

        for ph, cid in (("ts", "PLD004"), ("nonce", "PLD005")):
            if self._has_embedded(tmpl, ph):
                self._add(cid, f"{sec}.template")

        self._check_extract(f"{sec}.extract", extract)

        if HAVE_SHAPING:
            self._check_roundtrip(sec, tmpl, extract, encoding)
            self._check_body_size(sec, tmpl, encoding)

    def _check_placement(self, section: str, placement: Any,
                         shape: str) -> None:
        if not isinstance(placement, dict):
            self._add("PLC001", section, f"got {type(placement).__name__}")
            return
        kind = placement.get("kind", "")
        name = placement.get("name", "")
        if kind and kind not in VALID_PLACEMENT_KINDS:
            self._add("PLC002", section, f"kind={kind!r}")
        if kind in ("header", "cookie"):
            if not name:
                self._add("PLC003", section, f"kind={kind!r} needs a name")
            elif not isinstance(name, str) or not PLACEMENT_NAME.match(name):
                self._add("PLC004", section, f"name={name!r}")
            elif not PLACEMENT_TOKEN.match(name):
                self._add("PLC007", section, f"name={name!r}")
            if (kind == "header"
                    and isinstance(name, str)
                    and name.lower() in FRAMEWORK_HEADERS):
                self._add("PLC006", section, f"name={name!r}")
        if shape == "results_request":
            self._add("PLC005", section)

    @staticmethod
    def _count_placeholders(node: Any, ph: str) -> tuple[int, int]:
        full = embedded = 0
        token = "{{" + ph + "}}"

        def walk(n: Any) -> None:
            nonlocal full, embedded
            if isinstance(n, dict):
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
            elif isinstance(n, str) and token in n:
                m = PLACEHOLDER_FULL.match(n)
                if m and m.group(1) == ph:
                    full += 1
                else:
                    embedded += 1

        walk(node)
        return full, embedded

    def _has_embedded(self, node: Any, ph: str) -> bool:
        _, embedded = self._count_placeholders(node, ph)
        return embedded > 0

    def _check_extract(self, section: str, extract: str) -> None:
        for part in extract.split("."):
            if not PATH_SEG_PY.match(part):
                self._add("EXT001", section, f"segment {part!r}")
                continue
            if not PATH_SEG_GO.match(part):
                self._add("EXT002", section, f"segment {part!r}")
                continue
            if NON_ASCII.search(part):
                self._add("EXT003", section, f"segment {part!r}")

    def _check_roundtrip(self, section: str, tmpl: Any, extract: str,
                         encoding: Any) -> None:
        eff = _effective_encoding(encoding)
        for probe in PROBES:
            try:
                rendered  = wrap(tmpl, probe, eff)
                recovered = unwrap(rendered, extract, eff)
                if recovered != probe:
                    self._add("EXT004", section,
                              f"probe={self._brief(probe)}: "
                              f"got {self._brief(recovered)}")
                    return
            except Exception as exc:
                self._add("EXT004", section,
                          f"probe={self._brief(probe)}: {exc}")
                return

    def _check_body_size(self, section: str, tmpl: Any,
                         encoding: Any) -> None:
        probe = {"__probe__": "ok", "n": 1}
        try:
            rendered = wrap(tmpl, probe, _effective_encoding(encoding))
            body = json.dumps(rendered, separators=(",", ":"))
        except Exception:
            return
        if len(body) > 100_000:
            self._add("SHP006", section,
                      f"renders to {len(body)} bytes for a small probe "
                      f"— real SaaS check-in responses are typically "
                      f"under 100 KB")

    @staticmethod
    def _brief(x: Any, maxlen: int = 60) -> str:
        s = repr(x)
        return s if len(s) <= maxlen else s[:maxlen - 3] + "..."

    def _check_encoding_consistency(self) -> None:
        """SHP007: checkin_response and tasks_response should use
        the same effective encoding."""
        sh = self.profile.get("shaping")
        if not isinstance(sh, dict):
            return
        encodings: dict[str, str] = {}
        for shape in ("checkin_response", "tasks_response"):
            spec = sh.get(shape)
            if not isinstance(spec, dict):
                continue
            encodings[shape] = _effective_encoding(spec.get("encoding"))
        if len(set(encodings.values())) > 1:
            self._add("SHP007", "shaping", f"{encodings}")

    def _check_size_drift(self) -> None:
        """SHP008: two response shapes rendering to wildly different
        sizes for the same probe payload is a template bug."""
        if not HAVE_SHAPING:
            return
        sh = self.profile.get("shaping")
        if not isinstance(sh, dict):
            return
        sizes: dict[str, int] = {}
        probe = {"__probe__": "ok", "n": 1}
        for shape in ("checkin_response", "tasks_response"):
            spec = sh.get(shape)
            if not isinstance(spec, dict):
                continue
            tmpl = spec.get("template")
            if not isinstance(tmpl, dict):
                continue
            try:
                rendered = wrap(tmpl, probe,
                                _effective_encoding(spec.get("encoding")))
                sizes[shape] = len(json.dumps(rendered,
                                              separators=(",", ":")))
            except Exception:
                continue
        if len(sizes) < 2:
            return
        mn, mx = min(sizes.values()), max(sizes.values())
        if mn > 0 and mx / mn > 20:
            self._add("SHP008", "shaping", f"{sorted(sizes.items())}")

    def _check_dns(self) -> None:
        if "dns_label" not in self.profile:
            return
        dns = self.profile["dns_label"]
        if not isinstance(dns, dict):
            self._add("SHP001", "dns_label", f"got {type(dns).__name__}")
            return
        defaults = {"verb_b": "b", "verb_t": "t", "verb_r": "r"}
        seen: dict[str, str] = {}
        for key in ("verb_b", "verb_t", "verb_r"):
            v = dns.get(key, defaults[key])
            if not isinstance(v, str) or not DNS_VERB.match(v):
                self._add("DNS001", f"dns_label.{key}", f"got {v!r}")
                continue
            if v in seen:
                self._add("DNS002", f"dns_label.{key}",
                          f"verb {v!r} collides with {seen[v]}")
            seen[v] = key

        chunk = dns.get("payload_chunk_size", 63)
        if not isinstance(chunk, int):
            self._add("DNS003", "dns_label.payload_chunk_size",
                      f"got {chunk!r}")
            return
        if not (1 <= chunk <= 63):
            self._add("DNS004", "dns_label.payload_chunk_size",
                      f"got {chunk}")
        elif chunk < 16:
            self._add("DNS005", "dns_label.payload_chunk_size",
                      f"got {chunk}")

    def _check_stager(self) -> None:
        stager = self.profile.get("stager")
        if stager is None:
            return
        if not isinstance(stager, dict):
            self._add("RT008", "stager", f"got {type(stager).__name__}")
            return
        sp = stager.get("path")
        if sp is None:
            return
        if not isinstance(sp, str) or not sp.startswith("/"):
            self._add("RT008", "stager.path", f"got {sp!r}")
            return
        beacon  = self.profile.get("beacon_path",  "/beacon")
        tasks   = self.profile.get("tasks_path",   "/tasks")
        results = self.profile.get("results_path", "/results")
        if sp in (beacon, tasks, results):
            self._add("RT009", "stager.path", f"{sp!r} collides")

    def _check_shaping_presence(self) -> None:
        """PRF006: explicit paths but no shaping — bodies stay in the
        framework's plain-JSON default shape."""
        if "dns_label" in self.profile and "shaping" not in self.profile:
            return
        beacon = self.profile.get("beacon_path", "")
        if not beacon or beacon == "/beacon":
            return
        if "shaping" not in self.profile:
            self._add("PRF006", "shaping",
                      "explicit HTTP paths but no shaping block — "
                      "bodies are plain JSON in the framework's "
                      "default structure")

    def _check_server_presence(self) -> None:
        """PRF007: no Server header on an HTTP-shaped profile."""
        if "dns_label" in self.profile and "shaping" not in self.profile:
            return
        beacon = self.profile.get("beacon_path", "")
        if not beacon or beacon == "/beacon":
            return
        sh = self.profile.get("response_headers")
        if not isinstance(sh, dict):
            self._add("PRF007", "response_headers",
                      "no response_headers block — real servers send "
                      "Server, Cache-Control, and at least one X-* header")
            return
        if "Server" not in sh and "server" not in sh:
            self._add("PRF007", "response_headers",
                      "response_headers has no Server header — real "
                      "enterprise front-ends always set one")

    def _check_transport_hints(self) -> None:
        if "shaping" in self.profile and "dns_label" in self.profile:
            self._add("TRN001", "profile")


# ---------------------------------------------------------------------------
# Cross-profile checks
# ---------------------------------------------------------------------------

def check_directory(profiles: dict[str, tuple[Path, Any]]) -> list[Issue]:
    issues: list[Issue] = []
    role_owners: dict[str, dict[str, str]] = {
        "beacon_path":  {},
        "tasks_path":   {},
        "results_path": {},
    }
    dns_owners: list[str] = []

    for name, (_, profile) in profiles.items():
        if not isinstance(profile, dict):
            continue
        for role in role_owners:
            p = profile.get(role)
            if isinstance(p, str) and p:
                if p in role_owners[role]:
                    issues.append(Issue(
                        id="XPR001",
                        section=role,
                        message=f"path {p!r} already used by "
                                f"{role_owners[role][p]!r}",
                        severity="error",
                    ))
                else:
                    role_owners[role][p] = name
        if "dns_label" in profile:
            dns_owners.append(name)

    if len(dns_owners) > 1:
        first = sorted(dns_owners)[0]
        issues.append(Issue(
            id="XPR002",
            section="dns_label",
            message=f"multiple profiles declare dns_label: "
                    f"{sorted(dns_owners)}; only alphabetically-first "
                    f"({first!r}) is used by the handler",
            severity="warn",
        ))

    return issues


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

class Color:
    RESET  = "\033[0m"
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    GRAY   = "\033[90m"
    GREEN  = "\033[32m"
    BOLD   = "\033[1m"
    enabled = True

    @classmethod
    def c(cls, color: str, text: str) -> str:
        return text if not cls.enabled else f"{color}{text}{cls.RESET}"


SEV_COLOR  = {"error": Color.RED, "warn": Color.YELLOW,
              "info": Color.CYAN, "hint": Color.GRAY}
SEV_MARKER = {"error": "✗", "warn": "!", "info": "·", "hint": "?"}


def print_results(results: list[ProfileResult]) -> None:
    total_errors = total_warnings = 0
    for r in results:
        e = r.errors
        w = r.warnings
        total_errors += e
        total_warnings += w
        marker = "✗" if e else ("!" if w else "✓")
        color  = Color.RED if e else (Color.YELLOW if w else Color.GREEN)
        print(Color.c(color + Color.BOLD, f"{marker} {r.name}"))
        for issue in r.issues:
            sev_color  = SEV_COLOR.get(issue.severity, Color.GRAY)
            sev_marker = SEV_MARKER.get(issue.severity, "?")
            sev_padded = f"{issue.severity:<5}"
            print(f"  {Color.c(sev_color, sev_marker)} "
                  f"{Color.c(Color.GRAY, issue.id)}  "
                  f"{Color.c(sev_color, sev_padded)}  "
                  f"{issue.section}: {issue.message}")
            if issue.suggestion and issue.severity in ("error", "warn"):
                print(f"          "
                      f"{Color.c(Color.GRAY, '↳ ' + issue.suggestion)}")
        print()

    print(Color.c(Color.GRAY, "─" * 60))
    print(f"  {total_errors} error(s)  {total_warnings} warning(s)  "
          f"{len(results)} profile(s)")


# ---------------------------------------------------------------------------
# Explain / list
# ---------------------------------------------------------------------------

def explain_check(cid: str) -> int:
    m = CHECK_REGISTRY.get(cid)
    if not m:
        print(f"unknown check id {cid!r}", file=sys.stderr)
        print("run --list-checks to see all available checks",
              file=sys.stderr)
        return 2
    print(f"{m.id}  [{m.severity}]")
    print(f"  {m.summary}")
    if m.suggestion:
        print(f"  suggestion: {m.suggestion}")
    if m.doc:
        print(f"  doc: {m.doc}")
    return 0


def list_checks() -> int:
    print(f"shapecheck v{VERSION} — {len(CHECK_REGISTRY)} checks\n")
    print(f"{'id':<10}{'severity':<10}summary")
    print("-" * 80)
    for cid in sorted(CHECK_REGISTRY):
        m = CHECK_REGISTRY[cid]
        print(f"{m.id:<10}{m.severity:<10}{m.summary}")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="shapecheck",
        description="C2 profile validator for TornadoC2.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'shapecheck --list-checks' for the full check catalogue.",
    )
    ap.add_argument("paths", nargs="*",
                    help=f"profile files or directories "
                         f"(default: ./{DEFAULT_DIR}/)")
    ap.add_argument("--build-config", metavar="FILE",
                    help="build config to cross-check against "
                         "(enables PRF005, the UA/TLS mismatch check)")
    ap.add_argument("--explain", metavar="ID",
                    help="show documentation for a check ID")
    ap.add_argument("--list-checks", action="store_true",
                    help="list every check ID with its severity and summary")
    ap.add_argument("--ignore", default="",
                    help="comma-separated check IDs to suppress")
    args = ap.parse_args(argv)

    Color.enabled = sys.stdout.isatty()

    if args.list_checks:
        return list_checks()

    if args.explain:
        return explain_check(args.explain)

    cfg: Optional[dict] = None
    if args.build_config:
        try:
            cfg = json.loads(Path(args.build_config).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: --build-config: {exc}", file=sys.stderr)
            return 2
        if not isinstance(cfg, dict):
            print(f"error: --build-config: root is "
                  f"{type(cfg).__name__}, expected object", file=sys.stderr)
            return 2

    if not HAVE_SHAPING:
        print("note: shaping.py not importable — round-trip checks "
              "(EXT004), body-size checks (SHP006), and size-drift "
              "(SHP008) are skipped", file=sys.stderr)
    if cfg is None:
        print("note: --build-config not given — PRF005 "
              "(UA/TLS mismatch) is skipped", file=sys.stderr)

    ignored = {s.strip() for s in args.ignore.split(",") if s.strip()}

    paths = args.paths or [DEFAULT_DIR]
    profiles: dict[str, tuple[Path, Any]] = {}
    for p in paths:
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.glob("*.json")):
                try:
                    profiles[f.name] = (f, json.loads(f.read_text()))
                except json.JSONDecodeError as exc:
                    profiles[f.name] = (f, exc)
        elif path.is_file():
            try:
                profiles[path.name] = (path, json.loads(path.read_text()))
            except json.JSONDecodeError as exc:
                profiles[path.name] = (path, exc)
        else:
            print(f"error: no such file or directory: {path}",
                  file=sys.stderr)
            return 2

    if not profiles:
        print(f"error: no .json files found in {paths}", file=sys.stderr)
        return 2

    results: list[ProfileResult] = []
    for name, (path, profile) in profiles.items():
        if isinstance(profile, Exception):
            r = ProfileResult(name, path)
            r.issues.append(Issue(
                id="PRF001",
                section="<json>",
                message=str(profile),
                severity="error",
            ))
            results.append(r)
            continue
        results.append(Checker(name, path, profile, cfg=cfg).run())

    if len(profiles) > 1:
        cross = check_directory(profiles)
        if cross:
            results.append(ProfileResult("<directory>", Path("."), cross))

    if ignored:
        for r in results:
            r.issues = [i for i in r.issues if i.id not in ignored]
        results = [r for r in results
                   if r.name != "<directory>" or r.issues]

    print(f"shapecheck v{VERSION} — scanning "
          f"{', '.join(str(p) for p in paths)}\n")
    print_results(results)

    return 1 if any(r.errors for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())