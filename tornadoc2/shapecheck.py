#!/usr/bin/env python3
r"""
shapecheck — C2 profile validator for TornadoC2.

Cross-checks a profile against both the Python handler (validate())
and the Go agent (ValidateShapingSpec()). Where the two implementations
diverge — Python's Unicode \w vs Go's ASCII \w, Python's permissive
base64 vs Go's strict decoder — the profile passes on one side and
fails on the other. Those cases are errors here, because they break
on deployment.

Usage:
    shapecheck                              # scans ./profiles/c2/
    shapecheck profiles/c2/                 # scans ./profiles/c2/
    shapecheck profiles/c2/apple.json       # one file
    shapecheck profiles/c2/ backup/         # multiple paths
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

VERSION = "1.0.0"
DEFAULT_DIR = "profiles/c2"

# --- Optional: the handler's shaping module ---
try:
    from shaping import wrap, unwrap
    HAVE_SHAPING = True
except ImportError:
    HAVE_SHAPING = False

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
_reg("RT006", "error", "beacon_path / tasks_path / results_path are not distinct",
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

# --- Headers ---
_reg("HDR001", "error", "Header value contains CR/LF/NUL (header injection)",
     "Strip control characters from header keys and values.")
_reg("HDR002", "warn",  "Header contains a {{placeholder}} sent literally",
     "Placeholders are not substituted in headers, paths, or extra_headers. "
     "A static value is usually what you want; a real value must come from "
     "the build config, not the profile.")
_reg("HDR003", "error", "Header key or value is not a string")

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

# --- Extract path ---
_reg("EXT001", "error", "Extract path segment has invalid syntax",
     "A segment must match ^(\\w+)(\\[N\\])?$.")
_reg("EXT002", "error", "Segment matches Python's \\w but not Go's (ASCII-only)",
     "Python's \\w is Unicode-aware; Go's is ASCII-only. The handler "
     "accepts the profile but ValidateShapingSpec() on the agent build "
     "rejects it.")
_reg("EXT003", "error", "Segment contains non-ASCII characters",
     "The Go walker (pathSegRe) is ASCII-only and fails on the agent.")
_reg("EXT004", "error", "Round-trip failed (per-probe)",
     "wrap() then unwrap() produced a different payload. "
     "The template and extract do not agree on where the payload lives.")

# --- DNS ---
_reg("DNS001", "error", "DNS verb must be a single lowercase alphanumeric character")
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

# --- Profile root ---
_reg("PRF001", "error", "Profile root is not an object")
_reg("PRF002", "warn",  "user_agent is missing",
     "The built-in default is used; may not match a plausible target.")
_reg("PRF003", "warn",  "user_agent is empty")

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
    def __init__(self, name: str, path: Path, profile: Any):
        self.name = name
        self.path = path
        self.profile = profile
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
        self._check_user_agent()
        self._check_headers()
        self._check_status()
        self._check_cookie()
        self._check_shaping()
        self._check_dns()
        self._check_stager()
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
                      f"beacon={beacon!r} tasks={tasks!r} results={results!r}")

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

    def _check_user_agent(self) -> None:
        if "user_agent" not in self.profile:
            self._add("PRF002", "user_agent")
            return
        ua = self.profile.get("user_agent")
        if not isinstance(ua, str):
            self._add("PRF003", "user_agent", f"got {type(ua).__name__}")
        elif not ua.strip():
            self._add("PRF003", "user_agent", "value is empty")

    def _check_headers(self) -> None:
        for section in ("extra_headers", "request_headers", "response_headers"):
            if section not in self.profile:
                continue
            headers = self.profile[section]
            if not isinstance(headers, dict):
                self._add("HDR003", section, f"got {type(headers).__name__}")
                continue
            for k, v in headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    self._add("HDR003", section,
                              f"header {k!r} has non-string key or value")
                    continue
                if HEADER_INJECTION.search(k) or HEADER_INJECTION.search(v):
                    self._add("HDR001", section, f"header {k!r}")
                if "{{" in k or "{{" in v:
                    self._add("HDR002", section, f"header {k!r} = {v!r}")

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
                    self._add("ENC001", f"{sec}.encoding", f"got {encoding!r}")
                if encoding != stripped:
                    self._add("ENC002", f"{sec}.encoding", f"got {encoding!r}")
                elif encoding != lowered:
                    self._add("ENC003", f"{sec}.encoding", f"got {encoding!r}")

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
        eff = (encoding.strip().lower()
               if isinstance(encoding, str)
                  and encoding.strip().lower() in VALID_ENCODINGS
               else "base64")
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

    @staticmethod
    def _brief(x: Any, maxlen: int = 60) -> str:
        s = repr(x)
        return s if len(s) <= maxlen else s[:maxlen - 3] + "..."

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

    if not HAVE_SHAPING:
        print("note: shaping.py not importable — round-trip checks are "
              "skipped (add the handler package to PYTHONPATH)",
              file=sys.stderr)

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
        results.append(Checker(name, path, profile).run())

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