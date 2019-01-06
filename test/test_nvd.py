
from datetime import datetime, timezone
from io import StringIO

from tracker.nvd import parse_meta, is_old

meta = """lastModifiedDate:2019-01-06T08:00:46-05:00
size:3963616
zipSize:211211
gzSize:211067
sha256:4355FCD5C59858C9C41C3213BAE2CEF8F4D42D1AA0FBC6D31B5571BF7EEDF925
""".replace("\n", "\r\n")

def test_parse_meta():
    m = parse_meta(StringIO(meta))
    stamp = datetime(2019, 1, 6, 13, 0, 46,
        tzinfo=timezone.utc)
    want = {
        "lastModifiedDate": stamp,
        "size": 3963616,
        "gzSize": 211067,
        "sha256": "4355FCD5C59858C9C41C3213BAE2CEF8F4D42D1AA0FBC6D31B5571BF7EEDF925",
    }
    for key in want:
        assert want[key] == m[key]

def test_is_old():
    m = parse_meta(StringIO(meta))
    assert is_old("2019", m,
        now=datetime.fromisoformat("2019-01-15T00:00:00+00:00"))
    assert not is_old("2019", m,
        now=datetime.fromisoformat("2019-01-10T00:00:00+00:00"))
    assert is_old("modified", m,
        now=datetime.fromisoformat("2019-01-08T00:00:00+00:00"))
    assert not is_old("modified", m,
        now=datetime.fromisoformat("2019-01-07T00:00:00+00:00"))
