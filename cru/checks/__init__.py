"""The check registry.

One module per check. `CHECKS` is the single source of truth: `build_checks`
and the `--check` CLI choices both read it, so registering a check here is the
only wiring a new check needs.
"""

from __future__ import annotations

from cru.checks.cleartext import CleartextScanner
from cru.checks.code import CodeScanner
from cru.checks.cookies import CookieScanner
from cru.checks.cors import CorsScanner
from cru.checks.crlf import CrlfScanner
from cru.checks.csrf import CsrfScanner
from cru.checks.deser import DeserializationScanner
from cru.checks.fingerprint import FingerprintScanner
from cru.checks.headers import SecurityHeadersScanner
from cru.checks.infoleak import InfoLeakScanner
from cru.checks.jwt import JwtScanner
from cru.checks.methods import MethodScanner
from cru.checks.mixedcontent import MixedContentScanner
from cru.checks.nosqli import NoSqliScanner
from cru.checks.redirect import OpenRedirectScanner
from cru.checks.secrets import SecretScanner
from cru.checks.sqli import SqliScanner
from cru.checks.srcleak import SourceLeakScanner
from cru.checks.ssrf import SsrfScanner
from cru.checks.ssti import SstiScanner
from cru.checks.traversal import TraversalScanner
from cru.checks.upload import UploadScanner
from cru.checks.xss import XssScanner
from cru.checks.xxe import XxeScanner

CHECKS = {
    "deser": DeserializationScanner,
    "secrets": SecretScanner,
    "sqli": SqliScanner,
    "ssti": SstiScanner,
    "code": CodeScanner,
    "srcleak": SourceLeakScanner,
    "xss": XssScanner,
    "xxe": XxeScanner,
    "ssrf": SsrfScanner,
    "redirect": OpenRedirectScanner,
    "traversal": TraversalScanner,
    "crlf": CrlfScanner,
    "nosqli": NoSqliScanner,
    "upload": UploadScanner,
    "headers": SecurityHeadersScanner,
    "cors": CorsScanner,
    "cookies": CookieScanner,
    "jwt": JwtScanner,
    "infoleak": InfoLeakScanner,
    "fingerprint": FingerprintScanner,
    "methods": MethodScanner,
    "mixedcontent": MixedContentScanner,
    "cleartext": CleartextScanner,
    "csrf": CsrfScanner,
}

__all__ = ["CHECKS"]
