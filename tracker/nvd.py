"""
Download and mirror NIST's National Vulnerability Database
data feeds.

The JSON 1.0 format is used for simplicity.

The main functions in this module are:
- sync(): downloads updates from NIST website
- all_cves(): an iterator over all NVD entries
- get_cve(): an accessor for a single CVE entry
"""

from datetime import datetime, timedelta, timezone
import gzip
from hashlib import sha256
import io
import json
import os
import requests

from config import basedir

FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-"
LAST_YEAR = 2019

def sync(force=False):
    """ Synchronize copy of NVD database. """
    session = requests.Session()
    for feed, meta in metadata().items():
        print("{:<8} ".format(feed), end="")
        dest = os.path.join(datadir(), feed+".json.gz")
        if force or not meta or is_old(feed, meta) or not _check(meta, dest):
            fetch(feed, session)
        else:
            print("up-to-date")

def all_cves():
    """ An iterator over all NVD CVE entries. """
    for _, entry in _all_nvd_items():
        yield _nvd_to_model(entry)

def get_cve(cve_id):
    """ Returns a single CVE from the NVD database. """
    return _nvd_to_model(_get_nvd_item(cve_id))

def datadir():
    return os.path.join(basedir, "nvd")

def feeds():
    """
    Available NVD feeds.

    The 2002 feed contains also entries prior to 2002.
    The 'recent' feed is not used as the yearly feeds and
    the 'modified' feed are enough to rebuild the full database.
    """
    return [str(y) for y in range(2002, LAST_YEAR+1)] + ["modified"]

def metadata():
    db = {}
    for feed in feeds():
        db[feed] = None
        fp = os.path.join(datadir(), feed+".meta")
        if os.path.exists(fp):
            with open(fp) as f:
                db[feed] = _parse_meta(f)
    return db

def _parse_meta(f):
    d = {}
    for line in f:
        if line.isspace():
            continue
        key, _, value = line.strip().partition(':')
        if key == "lastModifiedDate":
            value = datetime.fromisoformat(value)
        elif key.lower().endswith("size"):
            value = int(value)
        d[key] = value
    return d

def fetch(feed, session):
    outdir = datadir()
    resp = session.get(FEED_ROOT + feed + ".meta")
    with open(os.path.join(outdir, feed+".meta"), "w") as w:
        w.write(resp.text)
    meta = _parse_meta(io.StringIO(resp.text))
    dest = os.path.join(outdir, feed+".json.gz")
    if _check(meta, dest):
        print("not modified")
    else:
        _download(session, FEED_ROOT + feed + ".json.gz", dest)
        if _check(meta, dest):
            print("OK ({} bytes)".format(meta["gzSize"]))
        else:
            print("checksum failed")

def _check(meta, filepath):
    sz = meta["gzSize"]
    sha = meta["sha256"]
    if not os.path.exists(filepath):
        return False
    if os.stat(filepath).st_size != sz:
        return False
    with gzip.open(filepath, 'rb') as f:
        buf = bytearray(32768)
        h = sha256()
        while True:
            n = f.readinto(buf)
            if n == 0:
                break
            h.update(buf[:n])
    return h.hexdigest() == sha.lower()

def _download(session, url, dest):
    """ A helper method to download a file. """
    with open(dest, 'wb') as w:
        resp = session.get(url, stream=True)
        for buf in resp.iter_content(32768):
            w.write(buf)

def is_old(feed, meta, now=None):
    # Update yearly feeds every week, "modified" feed
    # every day.
    stamp = meta["lastModifiedDate"]
    if now is None:
        now = datetime.now(tz=timezone.utc)
    if feed == "modified":
        return now - stamp > timedelta(days=1)
    else:
        return now - stamp > timedelta(days=7)

def _all_nvd_items():
    d = datadir()
    with gzip.open(os.path.join(d, "modified.json.gz")) as f:
        data = json.load(f)
        modified = {}
        for item in data["CVE_Items"]:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            modified[cve_id] = item

    seen = set()
    for year in range(2002, LAST_YEAR+1):
        with gzip.open(os.path.join(d, "{}.json.gz".format(year))) as f:
            data = json.load(f)
            for item in data["CVE_Items"]:
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                if cve_id in modified:
                    seen.add(cve_id)
                    yield cve_id, modified[cve_id]
                else:
                    yield cve_id, item

    for cve_id, item in modified.items():
        if cve_id not in seen:
            yield cve_id, item

def _get_nvd_item(cve_id):
    if cve_id.count('-') != 2:
        raise ValueError("invalid CVE id {}".format(cve_id))

    _, year, _ = cve_id.split('-')
    if not year.isdigit():
        raise ValueError("invalid CVE id {}".format(cve_id))

    d = datadir()
    with gzip.open(os.path.join(d, "modified.json.gz")) as f:
        data = json.load(f)
        for item in data["CVE_Items"]:
            if item["cve"]["CVE_data_meta"]["ID"] == cve_id:
                return item

    with gzip.open(os.path.join(d, year+".json.gz")) as f:
        data = json.load(f)
        for item in data["CVE_Items"]:
            if item["cve"]["CVE_data_meta"]["ID"] == cve_id:
                return item

    return None

def _nvd_to_model(doc):
    """ Parses a CVE from a JSON object. """
    from tracker.model.enum import Remote, Severity

    cve_id = doc["cve"]["CVE_data_meta"]["ID"]
    # Description
    desc = doc["cve"]["description"]["description_data"][0]
    for item in doc["cve"]["description"]["description_data"]:
        if item["lang"] == "en":
            desc = item
    # References
    refs = doc["cve"]["references"]["reference_data"]

    # Severity
    cvss3 = (doc
             .get("impact", {})
             .get("baseMetricV3", {})
             .get("cvssV3", {}))
    severity = cvss3.get("baseSeverity", "").lower()
    # Attack vector
    vector = cvss3.get("attackVector")
    if vector in ("LOCAL", "PHYSICAL"):
        remote = Remote.local
    elif vector in ("NETWORK", "ADJACENT_NETWORK"):
        remote = Remote.remote
    else:
        remote = Remote.unknown

    # Extra information
    products = []
    vendor_data = doc["cve"]["affects"]["vendor"]["vendor_data"]
    for vendor in vendor_data:
        for product in vendor["product"]["product_data"]:
            for version in product["version"]["version_data"]:
                products.append("{} {} {} {}".format(
                    vendor["vendor_name"], product["product_name"],
                    version["version_affected"], version["version_value"]))

    return {
        "id": cve_id,
        "description": desc["value"],
        "severity": Severity.fromstring(severity),
        "remote": remote,
        "reference": [ref["url"] for ref in refs],
        "products": products,
    }

