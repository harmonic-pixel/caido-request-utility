"""The IDOR finder's job is a short list worth acting on.

Its review tier — a bare integer on a parameter nobody named — is where false
positives collect, so these pin what it must refuse: quantities, positions and
indices by name, and anything seen only once.
"""

import json

from cru import idor_finder as idor


def _pairs(body):
    return idor.body_candidates(json.dumps(body), "Content-Type: application/json")


def test_quantities_and_positions_are_not_identifiers():
    """`offset`, a canvas `y`, an array `_key` — an int there is never a ref."""
    candidates = _pairs(
        {
            "offset": 0,
            "per_page": 30,
            "node": {"x": 420, "y": 179, "inputs": [{"min_count": 1, "_key": 0}]},
        }
    )

    assert candidates == [], [c.location for c in candidates]


def test_an_unnamed_integer_is_still_worth_a_look():
    """The tier exists for a reason; only the obvious non-refs are dropped."""
    assert [c.location for c in _pairs({"thing": 4021})] == ["body:thing"]


def test_the_leaf_name_is_what_counts():
    """Six levels down a document does not turn a `y` into an identifier."""
    assert idor._leaf_name("node.parameters[0].value.value[0].y") == "y"
    assert idor._leaf_name("user_id") == "user_id"


def test_a_jwt_is_a_credential_not_a_reference():
    """It reaches the finder on the parameter name — `token` is an id hint.

    Enumerating one is not a thing you can do: it is signed and it expires, and
    what is interesting about it belongs to the `jwt` check.
    """
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = f"{seg({'alg': 'RS256'})}.{seg({'sub': '42'})}.aaaaaaaabbbbbbbb"

    assert _pairs({"token": token}) == []
    # and the same value under a name that is not a hint at all
    assert _pairs({"whatever": token}) == []


def _rows(values, key="thing"):
    """One request per value, shaped like the requests table."""
    return [
        {
            "host": "app.test",
            "method": "GET",
            "path": "/a",
            "query": "",
            "cookies": "",
            "headers": "Authorization: Bearer x",
            "body": json.dumps({key: v}),
            "response_status_code": 200,
            "response_length": 500,
        }
        for v in values
    ]


def test_a_single_sighting_is_not_worth_testing():
    """One observed ID is not a lead, whatever shape it is.

    There is nothing to enumerate and nothing to compare — it says only that
    the endpoint takes an identifier, which its shape already said.
    """
    assert idor.analyse(_rows([4021])) == []
    assert idor.analyse(_rows(["6a951f7f1af62e63c9e34025"], key="user_id")) == []

    seen_twice = idor.analyse(_rows([4021, 4022]))
    assert [f.location for f in seen_twice] == ["body:thing"]
    assert seen_twice[0].distinct_ids == 2


def test_the_floor_is_the_flag():
    """One knob, not a hidden rule plus a flag that cannot reach past it."""
    findings = idor.analyse(_rows(["6a951f7f1af62e63c9e34025"]), min_distinct=1)

    assert [f.id_type for f in findings] == ["objectid"]
    assert findings[0].distinct_ids == 1
