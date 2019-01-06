"""
Download and mirror NIST's National Vulnerability Database
data feeds.

The JSON 1.0 format is used for simplicity.
"""

from datetime import datetime, timedelta, timezone
import gzip
from hashlib import sha256
import io
import os
import requests

from config import basedir

FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-"

def datadir():
    return os.path.join(basedir, "nvd")

def feeds():
    return [str(y) for y in range(2002, 2020)] + ["modified"]

def metadata():
    db = {}
    for feed in feeds():
        db[feed] = None
        fp = os.path.join(datadir(), feed+".meta")
        if os.path.exists(fp):
            with open(fp) as f:
                db[feed] = parse_meta(f)
    return db

def parse_meta(f):
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

def sync(force=False):
    session = requests.Session()
    for feed, meta in metadata().items():
        print("{:<8} ".format(feed), end="")
        dest = os.path.join(datadir(), feed+".json.gz")
        if not meta or is_old(feed, meta) or not check(meta, dest):
            fetch(feed, session)
        else:
            print("up-to-date")

def fetch(feed, session):
    outdir = datadir()
    resp = session.get(FEED_ROOT + feed + ".meta")
    with open(os.path.join(outdir, feed+".meta"), "w") as w:
        w.write(resp.text)
    meta = parse_meta(io.StringIO(resp.text))
    dest = os.path.join(outdir, feed+".json.gz")
    if check(meta, dest):
        print("not modified")
    else:
        download(session, FEED_ROOT + feed + ".json.gz", dest)
        if check(meta, dest):
            print("OK ({} bytes)".format(meta["gzSize"]))
        else:
            print("checksum failed")

def check(meta, filepath):
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

def download(session, url, dest):
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
