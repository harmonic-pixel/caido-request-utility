"""Check 13: NoSQL injection operators"""

from __future__ import annotations

import re

from cru.checks.base import _dedupe, _emit, request_inputs

_NOSQL_PARAM = re.compile(
    r"\[\$(?:ne|gt|gte|lt|lte|regex|in|nin|or|and|where|"
    r"exists|expr|elemMatch|not|all)\]"
)
_NOSQL_JSON = re.compile(
    r'"\$(?:ne|gt|gte|lt|lte|regex|where|expr|function|or|'
    r'and|in|nin|exists|elemMatch)"\s*:'
)
_NOSQL_WHERE = re.compile(
    r"\$where\b|sleep\s*\(\s*\d|this\.\w+\s*==|\|\|\s*'1'\s*==\s*'1"
)


class NoSqliScanner:
    name = "nosqli"

    def run(self, rows):
        out = []
        for r in rows:
            for label, text in request_inputs(r):
                m = _NOSQL_JSON.search(text) or _NOSQL_WHERE.search(text)
                if m is not None:
                    _emit(
                        out,
                        self.name,
                        "high",
                        "nosql-operator",
                        r,
                        label,
                        m.group(0),
                        "MongoDB operator/$where in input — NoSQL " "injection",
                    )
                else:
                    m = _NOSQL_PARAM.search(text)
                    if m is None:
                        continue
                    _emit(
                        out,
                        self.name,
                        "medium",
                        "nosql-param-operator",
                        r,
                        label,
                        m.group(0),
                        "bracketed Mongo operator in param — NoSQL injection",
                    )
        return _dedupe(out)
