"""
Utility commands to import data from security.archlinux.org
"""

from click import echo
import requests
import time
import datetime

from .util import cli

from tracker import db
from tracker.advisory import advisory_extend_model_from_advisory_text
from tracker.model.advisory import Advisory
from tracker.model.cve import CVE
from tracker.model.cvegroup import CVEGroup
from tracker.model.cvegroupentry import CVEGroupEntry
from tracker.model.cvegrouppackage import CVEGroupPackage
from tracker.model.enum import Remote, Severity, Status

@cli.group()
def sync():
    """Synchronize with official Arch tracker.
    
    This can be used to initialize a development environment."""
    pass

@sync.command()
def cves():
    """Download CVEs from Arch tracker."""
    # CVEs are either orphan (not in a CVEGroup)
    # or in a CVEGroup (AVG).
    sess = requests.session()
    todo = get_orphans(sess)
    groups = get_groups(sess)

    all_cves = set(cve["name"] for cve in todo["issues"]["orphan"])
    for g in groups:
        all_cves.update(g["issues"])

    echo("{} CVEs in Arch tracker".format(len(all_cves)))

    our_cves = set(cve.id for cve in CVE.query.all())
    echo("{} CVEs to import".format(len(all_cves - our_cves)))
    t0 = time.time()
    objs = []
    imported = 0
    for cve in sorted(all_cves - our_cves):
        info = get_cve(sess, cve)
        obj = {
            "id": info["name"],
            "issue_type": info["type"],
            "description": info["description"],
            "severity": Severity.from_label(info["severity"]),
            "remote": Remote.from_label(info["vector"]),
            "reference": "\n".join(info["references"]),
            "notes": info["notes"], # nullable
        }
        objs.append(obj)
        if len(objs) % 50 == 0:
            db.session.bulk_insert_mappings(CVE, objs)
            db.session.commit()
            imported += len(objs)
            echo("imported {} new CVEs in {:.3f}s".format(imported, time.time()-t0))
            objs = []
    # remaining objects
    if objs:
        db.session.bulk_insert_mappings(CVE, objs)
        db.session.commit()
        imported += len(objs)
        echo("imported {} new CVEs in {:.3f}s".format(imported, time.time()-t0))

@sync.command()
def avgs():
    """Download AVGs from Arch tracker"""
    sess = requests.session()
    groups = get_groups(sess)

    all_groups = set(g["name"] for g in groups)

    echo("{} AVGs in Arch tracker".format(len(all_groups)))

    our_avgs = set(avg.name for avg in CVEGroup.query.all())
    echo("{} AVGs to import".format(len(all_groups - our_avgs)))
    t0 = time.time()
    objs = []
    for g in sorted(all_groups - our_avgs):
        info = get_avg(sess, g)
        if info["name"].startswith("AVG-"):
            pk = int(info["name"][4:])
        else:
            echo("invalid AVG id {}".format(info["name"]))
            continue
        obj = {
            "id": pk,
            "status": Status.from_label(info["status"]),
            "severity": Severity.from_label(info["severity"]),
            "affected": info["affected"],
            "fixed": info["fixed"], # nullable
            "bug_ticket": info["ticket"], # nullable
            "reference": "\n".join(info["references"]),
            "notes": info["notes"], # nullable
            # created, not exported
            # advisory_qualified not exported
        }
        group = db.create(CVEGroup, **obj)
        db.session.commit()

        for cve in info["issues"]:
            db.create(CVEGroupEntry, group=group, cve_id=cve)
        for pkgname in info["packages"]:
            db.create(CVEGroupPackage, pkgname=pkgname, group=group)
        db.session.commit()

        echo("processed {} ({} packages, {} issues)".format(g,
            len(group.packages), len(group.issues)))

@sync.command()
def advisories():
    """Download advisories from the Arch tracker"""
    sess = requests.session()
    advs = get_advisories(sess)

    echo("{} advisories in Arch tracker".format(len(advs)))
    theirs = set(adv["name"] for adv in advs)
    ours = set(x.id for x in Advisory.query.all())
    echo("{} AVGs to import".format(len(theirs - ours)))

    for info in advs:
        if info["name"] in ours:
            continue
        body = get_advisory(sess, info["name"])
        gpkg = CVEGroupPackage.query.filter_by(
            group_id=int(info["group"][len("ASA-"):]),
            pkgname=info["package"]).first()
        if gpkg is None:
            echo("{name}: cannot find {group}/{package} in database, ignoring".format(**info))
            continue
        obj = {
            "id": info["name"],
            "group_package": gpkg,
            "advisory_type": info["type"],
            "publication": None, # FIXME
            # workaround, computed from content
            # impact, computed from content
            "content": body,
            "created": datetime.datetime.strptime(info["date"], "%Y-%m-%d"),
            "reference": info["reference"],
        }
        adv = db.create(Advisory, **obj)
        advisory_extend_model_from_advisory_text(adv)
        db.session.commit()
        echo("imported {name} ({group}/{package})".format(**info))

ARCH_TRACKER = "https://security.archlinux.org/"

def get_orphans(session):
    return session.get(ARCH_TRACKER + "todo.json").json()

def get_groups(session):
    return session.get(ARCH_TRACKER + "all.json").json()

def get_advisories(session):
    return session.get(ARCH_TRACKER + "advisories.json").json()

def get_cve(session, cve_id):
    return session.get(ARCH_TRACKER + "cve/{}.json".format(cve_id)).json()

def get_avg(session, id):
    return session.get(ARCH_TRACKER + "avg/{}.json".format(id)).json()

def get_advisory(session, adv):
    return session.get(ARCH_TRACKER + "{}/raw".format(adv)).text
