"""Check 2: secrets (TruffleHog-style)"""

from __future__ import annotations

import base64
import binascii
import re

from cru.checks.base import (
    _B64_TOKEN,
    JWT_DECODED_RE,
    JWT_RE,
    Finding,
    _dedupe,
    gate,
    iter_fields,
    jwt_claims,
    jwt_identity,
    shannon_entropy,
    value_identity,
)

# High-precision detectors: (name, regex, severity)
_SECRET_DETECTORS = [
    (
        "aws-access-key-id",
        gate(
            r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b", "akia", "asia", "agpa", "aida"
        ),
        "high",
    ),
    ("github-pat", gate(r"\bgh[pousr]_[0-9A-Za-z]{36}\b", "gh"), "high"),
    (
        "github-fine-grained-pat",
        gate(r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "github_pat_"),
        "high",
    ),
    ("gitlab-pat", gate(r"\bglpat-[0-9A-Za-z_\-]{20}\b", "glpat-"), "high"),
    ("slack-token", gate(r"\bxox[baprs]-[0-9A-Za-z-]{10,64}\b", "xox"), "high"),
    (
        "slack-webhook",
        gate(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "hooks.slack.com"),
        "medium",
    ),
    ("stripe-live-key", gate(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b", "k_live_"), "high"),
    ("stripe-test-key", gate(r"\b[sr]k_test_[0-9A-Za-z]{20,}\b", "k_test_"), "low"),
    ("google-api-key", gate(r"\bAIza[0-9A-Za-z_\-]{35}\b", "aiza"), "high"),
    ("google-oauth-token", gate(r"\bya29\.[0-9A-Za-z_\-]{20,}", "ya29."), "medium"),
    (
        "openai-key",
        gate(
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b",
            "t3blbkfj",
        ),
        "high",
    ),
    ("anthropic-key", gate(r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b", "sk-ant-"), "high"),
    (
        "sendgrid-key",
        gate(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b", "sg."),
        "high",
    ),
    ("npm-token", gate(r"\bnpm_[0-9A-Za-z]{36}\b", "npm_"), "high"),
    ("twilio-api-key", gate(r"\bSK[0-9a-fA-F]{32}\b", "sk"), "medium"),
    ("mailgun-key", gate(r"\bkey-[0-9a-f]{32}\b", "key-"), "medium"),
    (
        "private-key-block",
        # The whole block, not just the opening marker: the evidence is what
        # gets masked, so matching the marker alone hid the label and left the
        # key material itself in plain sight. Falls back to the marker when the
        # end is missing (a truncated field), which is better than no finding.
        gate(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]{0,20000}?-----END [A-Z ]{0,40}PRIVATE KEY-----"
            r"|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            "private key-----",
        ),
        "high",
    ),
    (
        "jwt",
        gate(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "eyj",
        ),
        "medium",
    ),
    (
        "basic-auth-header",
        # Capture only the credential. The evidence is what gets redacted in the
        # output and masked in the report's message, and `Authorization: Basic`
        # is not the secret — blanking it just makes the request unreadable.
        gate(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})", "basic"),
        "medium",
    ),
    # Generic assignment — noisy, so it's reported at review tier.
    (
        "generic-secret-assignment",
        gate(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
            r"auth[_-]?token|client[_-]?secret|private[_-]?key)"
            r"[\"'\s:=]{1,4}[\"']?([^\s\"'&;]{6,})",
            "password",
            "passwd",
            "pwd",
            "secret",
            "key",
            "token",
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


def _basic_credential(hit):
    """What an `Authorization: Basic` credential decodes to, or ""."""
    token = hit.rsplit(None, 1)[-1]
    try:
        return base64.b64decode(token + "=" * (-len(token) % 4)).decode(
            "utf-8", "replace"
        )
    except (ValueError, binascii.Error):
        return ""


def _side(label):
    """Which half of the exchange a field belongs to.

    Grouping keeps the two apart: a key you send and the same key coming back
    in a response are different facts, and merging them would lose the leak.
    The views of one field (`#decoded`, `#json`) are the same fact, and merge.
    """
    return "response" if label.startswith("response") else "request"


class SecretScanner:
    name = "secrets"

    def __init__(self, entropy=True):
        self.entropy = entropy

    def run(self, rows):
        return _dedupe(self.scan(rows))

    def scan(self, rows):
        """Every occurrence, before dedup — what the report's masking needs.

        `run` collapses the occurrences that share a group: a session token
        re-issued through a browsing session becomes one finding carrying one
        representative's text. The report embeds whole bodies, so it has to
        hide every sibling sitting in a pane too, not just that one.
        """
        out = []
        for r in rows:
            # What a Basic credential on this request decodes to. Some apps put
            # a JWT in the username, and then the token and the header are one
            # credential wearing two encodings — worth saying once, not twice.
            basic = []
            for label, text in iter_fields(r):
                # 1) high-precision detectors
                claimed = []
                for name, rx, sev in _SECRET_DETECTORS:
                    for m in rx.finditer(text):
                        hit = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
                        if name == "jwt" and any(hit in b for b in basic):
                            continue  # already reported as the Basic credential
                        # This text now has a name. The entropy sweep exists
                        # for the *unlabelled*, so it must not report the same
                        # bytes again — the credential in an Authorization:
                        # Basic header is high-entropy by nature, and it is
                        # already a basic-auth-header finding.
                        claimed.append(m.span())
                        detail = "matched detector pattern"
                        if name == "jwt":
                            claims = jwt_claims(hit)
                            if claims:
                                detail = f"matched detector pattern [{claims}]"
                        if name == "basic-auth-header":
                            credential = _basic_credential(m.group(0))
                            if JWT_RE.search(credential):
                                basic.append(credential)
                                detail = (
                                    "Basic credential is a JWT used as the "
                                    "username — one credential, and the token "
                                    "travels in a header that gets logged"
                                )
                        # One finding per secret, not per request it appeared
                        # in: a credential sprayed across a browsing session is
                        # one thing to rotate, and the requests are listed on
                        # it. A JWT groups on its decoded claims, so a re-issued
                        # token counts once; everything else on its own value.
                        ident = (
                            jwt_identity(hit) if name == "jwt" else value_identity(hit)
                        )
                        group = f"{_side(label)}:{ident}"
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
                                detail,
                                group=group,
                            )
                        )
                # 2) entropy pass for unlabelled high-entropy tokens
                if self.entropy:
                    out.extend(self._entropy(r, label, text, claimed))
        return out

    def _entropy(self, r, label, text, claimed=()):
        found = []
        # Anything a detector already named, plus the JWTs. A JWT is
        # high-entropy by construction, and so is every claim value and
        # signature inside it — including in the expanded view `field_decode`
        # writes, which no detector matches.
        skip = list(claimed) + [
            m.span() for rx in (JWT_RE, JWT_DECODED_RE) for m in rx.finditer(text)
        ]
        for m in _B64_TOKEN.finditer(text):
            tok = m.group(0)
            if len(tok) < _ENTROPY_MIN_LEN or _ENTROPY_SKIP.match(tok):
                continue
            start, end = m.span()
            if any(s <= start and end <= e for s, e in skip):
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
                        group=f"{_side(label)}:{value_identity(tok)}",
                    )
                )
        return found
