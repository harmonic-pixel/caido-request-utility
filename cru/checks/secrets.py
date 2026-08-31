"""Check 2: secrets (TruffleHog-style)"""

from __future__ import annotations

import re

from cru.checks.base import (
    _B64_TOKEN,
    Finding,
    _dedupe,
    iter_fields,
    jwt_identity,
    shannon_entropy,
)

# High-precision detectors: (name, regex, severity)
_SECRET_DETECTORS = [
    (
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b"),
        "high",
    ),
    ("github-pat", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), "high"),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b"), "high"),
    ("gitlab-pat", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b"), "high"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,64}\b"), "high"),
    (
        "slack-webhook",
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
        "medium",
    ),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "high"),
    ("stripe-test-key", re.compile(r"\b[sr]k_test_[0-9A-Za-z]{20,}\b"), "low"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("google-oauth-token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"), "medium"),
    (
        "openai-key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"),
        "high",
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b"), "high"),
    (
        "sendgrid-key",
        re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
        "high",
    ),
    ("npm-token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"), "high"),
    ("twilio-api-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "medium"),
    ("mailgun-key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "medium"),
    (
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "high",
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
        "medium",
    ),
    (
        "basic-auth-header",
        re.compile(r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}"),
        "medium",
    ),
    # Generic assignment — noisy, so it's reported at review tier.
    (
        "generic-secret-assignment",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key)"
            r"[\"'\s:=]{1,4}[\"']?([^\s\"'&;]{6,})"
        ),
        "review",
    ),
]

# entropy config
_ENTROPY_B64_MIN = 4.5
_ENTROPY_HEX_MIN = 3.0
_ENTROPY_MIN_LEN = 20
_HEXish = re.compile(r"^[0-9a-fA-F]+$")
# Skip contexts/values that entropy loves but that aren't secrets.
_ENTROPY_SKIP = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-",
)  # UUID prefix


class SecretScanner:
    name = "secrets"

    def __init__(self, entropy=True):
        self.entropy = entropy

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in iter_fields(r):
                # 1) high-precision detectors
                for name, rx, sev in _SECRET_DETECTORS:
                    for m in rx.finditer(text):
                        hit = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
                        # Same token, re-issued, is the same leaked credential:
                        # group it on the decoded claims as the jwt check does.
                        group = jwt_identity(hit) if name == "jwt" else None
                        out.append(
                            Finding(
                                self.name,
                                sev,
                                name,
                                r["host"],
                                r["method"],
                                r["path"],
                                label,
                                hit.strip(),
                                "matched detector pattern",
                                group=group,
                            )
                        )
                # 2) entropy pass for unlabelled high-entropy tokens
                if self.entropy:
                    out.extend(self._entropy(r, label, text))
        return _dedupe(out)

    def _entropy(self, r, label, text):
        found = []
        for m in _B64_TOKEN.finditer(text):
            tok = m.group(0)
            if len(tok) < _ENTROPY_MIN_LEN or _ENTROPY_SKIP.match(tok):
                continue
            is_hex = bool(_HEXish.match(tok))
            ent = shannon_entropy(tok)
            thresh = _ENTROPY_HEX_MIN if is_hex else _ENTROPY_B64_MIN
            if ent >= thresh:
                # 24/32/40/64 hex are usually hashes or resource IDs, not
                # secrets -> skip. 24 is a Mongo ObjectId; those are worth
                # keeping as *enumeration* candidates rather than secrets, and
                # idor_finder already classifies them (`_OBJECTID_RE`, id_type
                # "objectid") for exactly that.
                if is_hex and len(tok) in (24, 32, 40, 64):
                    continue
                found.append(
                    Finding(
                        self.name,
                        "review",
                        "high-entropy-string",
                        r["host"],
                        r["method"],
                        r["path"],
                        label,
                        tok,
                        f"entropy={ent:.2f} len={len(tok)} — unlabelled, verify by hand",
                    )
                )
        return found
