#!/usr/bin/env python3
#
# Copyright (c) 2018 by Cisco Systems, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

""" CVERT library: set of functions for CVE reports
"""


import os
import re
import sys
import json
import gzip
import pickle
import logging
import hashlib
import datetime
import textwrap
import urllib.request
import distutils.version


logging.getLogger(__name__).addHandler(logging.NullHandler())


def generate_report(manifest, cve_struct):
    """Generate CVE report"""

    report = []

    for cve in cve_struct:
        affected = set()

        for conf in cve_struct[cve]["nodes"]:
            affected = affected.union(process_configuration(manifest, conf))

        for key in affected:
            product, version = key.split(",")
            patched = manifest[product][version]

            if cve in patched:
                cve_item = {"status": "patched"}
            else:
                cve_item = {"status": "unpatched"}

            cve_item["CVSS"] = "{0:.1f}".format(cve_struct[cve]["score"])
            cve_item["CVE"] = cve
            cve_item["product"] = product
            cve_item["version"] = version
            cve_item["description"] = cve_struct[cve]["description"]
            cve_item["reference"] = [x["url"] for x in cve_struct[cve]["reference"]]

            logging.debug("%9s %s %s,%s",
                          cve_item["status"], cve_item["CVE"],
                          cve_item["product"], cve_item["version"])

            report.append(cve_item)

    return sorted(report, key=lambda x: (x["status"], x["product"], x["CVSS"], x["CVE"]))


def process_configuration(manifest, conf):
    """Recursive call to process all CVE configurations"""

    operator = conf["operator"]

    if operator not in ["OR", "AND"]:
        raise ValueError("operator {} is not supported".format(operator))

    operator = True if operator == "AND" else False
    match = False
    affected = set()

    if "cpe" in conf:
        match = process_cpe(manifest, conf["cpe"][0], affected)

        for cpe in conf["cpe"][1:]:
            package_match = process_cpe(manifest, cpe, affected)

            # match = match <operator> package_match
            match = operator ^ ((operator ^ match) or (operator ^ package_match))
    elif "children" in conf:
        product_set = process_configuration(manifest, conf["children"][0])

        if product_set:
            match = True
            affected = affected.union(product_set)

        for child in conf["children"][1:]:
            product_set = process_configuration(manifest, child)
            package_match = True if product_set else False

            # match = match OP package_match
            match = operator ^ ((operator ^ match) or (operator ^ package_match))

            if package_match:
                affected = affected.union(product_set)

    if match:
        return affected

    return ()


def process_cpe(manifest, cpe, affected):
    """Match CPE with all manifest packages"""

    if not cpe["vulnerable"]:
        # ignore non vulnerable part
        return False

    version_range = {}

    for flag in ["versionStartIncluding",
                 "versionStartExcluding",
                 "versionEndIncluding",
                 "versionEndExcluding"]:
        if flag in cpe:
            version_range[flag] = cpe[flag]

    # take only "product" and "version"
    product, version = cpe["cpe23Uri"].split(":")[4:6]

    if product not in manifest:
        return False

    if not version_range:
        if version == "*":
            # ignore CVEs that touches all versions of package,
            # can not fix it anyway
            logging.debug('ignore "*" in %s', cpe["cpe23Uri"])
            return False
        elif version == "-":
            # "-" means NA
            #
            # NA (i.e. "not applicable/not used"). The logical value NA
            # SHOULD be assigned when there is no legal or meaningful
            # value for that attribute, or when that attribute is not
            # used as part of the description.
            # This includes the situation in which an attribute has
            # an obtainable value that is null
            #
            # Ignores CVEs if version is not set
            logging.debug('ignore "-" in %s', cpe["cpe23Uri"])
            return False
        else:
            version_range["versionExactMatch"] = version

    result = False

    for version in manifest[product]:
        try:
            if match_version(version,
                             version_range):
                logging.debug("match %s %s: %s", product, version, cpe["cpe23Uri"])
                affected.add("{},{}".format(product, version))

                result = True
        except TypeError:
            # version comparison is a very tricky
            # sometimes provider changes product version in a strange manner
            # and the above comparison just failed
            # so here we try to make version string "more standard"

            if match_version(twik_version(version),
                             [twik_version(v) for v in version_range]):
                logging.debug("match %s %s (twiked): %s", product, twik_version(version),
                              cpe["cpe23Uri"])
                affected.add("{},{}".format(product, version))

                result = True

    return result


def match_version(version, vrange):
    """Match version with the version range"""

    result = False
    version = util_version(version)

    if "versionExactMatch" in vrange:
        if version == util_version(vrange["versionExactMatch"]):
            result = True
    else:
        result = True

        if "versionStartIncluding" in vrange:
            result = result and version >= util_version(vrange["versionStartIncluding"])

        if "versionStartExcluding" in vrange:
            result = result and version > util_version(vrange["versionStartExcluding"])

        if "versionEndIncluding" in vrange:
            result = result and version <= util_version(vrange["versionEndIncluding"])

        if "versionEndExcluding" in vrange:
            result = result and version < util_version(vrange["versionEndExcluding"])

    return result


def util_version(version):
    """Simplify package version"""
    return distutils.version.LooseVersion(version.split("+git")[0])


def twik_version(version):
    """Return "standard" version for complex cases"""
    return "v1" + re.sub(r"^[a-zA-Z]+", "", version)


def print_report(report, width=70, show_description=False, show_reference=False, output=sys.stdout):
    """Print out final report"""

    for cve in report:
        print("{0:>9s} | {1:>4s} | {2:18s} | {3} | {4}".format(cve["status"], cve["CVSS"],
                                                               cve["CVE"], cve["product"],
                                                               cve["version"]),
              file=output)

        if show_description:
            print("{0:>9s} + {1}".format(" ", "Description"), file=output)

            for lin in textwrap.wrap(cve["description"], width=width):
                print("{0:>9s}   {1}".format(" ", lin), file=output)

        if show_reference:
            print("{0:>9s} + {1}".format(" ", "Reference"), file=output)

            for url in cve["reference"]:
                print("{0:>9s}   {1}".format(" ", url), file=output)


def update_feeds(feed_dir, offline=False, start=2002):
    """Update all JSON feeds"""

    feed_dir = os.path.realpath(feed_dir)
    year_now = datetime.datetime.now().year
    cve_struct = {}

    for year in range(start, year_now + 1):
        update_year(cve_struct, year, feed_dir, offline)

    return cve_struct


def update_year(cve_struct, year, feed_dir, offline):
    """Update one JSON feed for the particular year"""

    url_prefix = "https://static.nvd.nist.gov/feeds/json/cve/1.0"
    file_prefix = "nvdcve-1.0-{0}".format(year)

    meta = {
        "url": "{0}/{1}.meta".format(url_prefix, file_prefix),
        "file": os.path.join(feed_dir, "{0}.meta".format(file_prefix))
    }

    feed = {
        "url": "{0}/{1}.json.gz".format(url_prefix, file_prefix),
        "file": os.path.join(feed_dir, "{0}.json.gz".format(file_prefix))
    }

    ctx = {}

    if not offline:
        ctx = download_feed(meta, feed)

        if not "meta" in ctx or not "feed" in ctx:
            return

    if not os.path.isfile(meta["file"]):
        return

    if not os.path.isfile(feed["file"]):
        return

    if not "meta" in ctx:
        ctx["meta"] = ctx_meta(meta["file"])

    if not "sha256" in ctx["meta"]:
        return

    if not "feed" in ctx:
        ctx["feed"] = ctx_gzip(feed["file"], ctx["meta"]["sha256"])

    if not ctx["feed"]:
        return

    logging.debug("parsing year %s", year)

    for cve_item in ctx["feed"]["CVE_Items"]:
        iden, cve = parse_item(cve_item)

        if not iden:
            continue

        if not cve:
            logging.error("%s parse error", iden)
            break

        if iden in cve_struct:
            logging.error("%s duplicated", iden)
            break

        cve_struct[iden] = cve

    logging.debug("cve records: %d", len(cve_struct))


def ctx_meta(filename):
    """Parse feed meta file"""

    if not os.path.isfile(filename):
        return {}

    ctx = {}

    with open(filename) as fil:
        for lin in fil:
            pair = lin.split(":", maxsplit=1)
            ctx[pair[0]] = pair[1].rstrip()

    return ctx


def ctx_gzip(filename, checksum=""):
    """Parse feed archive file"""

    if not os.path.isfile(filename):
        return {}

    with gzip.open(filename) as fil:
        try:
            ctx = fil.read()
        except (EOFError, OSError):
            logging.error("failed to process gz archive %s", filename, exc_info=True)
            return {}

    if checksum and checksum.upper() != hashlib.sha256(ctx).hexdigest().upper():
        return {}

    return json.loads(ctx.decode())


def parse_item(cve_item):
    """Parse one JSON CVE entry"""

    cve_id = cve_item["cve"]["CVE_data_meta"]["ID"][:]
    impact = cve_item["impact"]

    if not impact:
        # REJECTed CVE
        return None, None

    if "baseMetricV3" in impact:
        score = impact["baseMetricV3"]["cvssV3"]["baseScore"]
    elif "baseMetricV2" in impact:
        score = impact["baseMetricV2"]["cvssV2"]["baseScore"]
    else:
        return cve_id, None

    return cve_id, {
        "score": score,
        "nodes": cve_item["configurations"]["nodes"][:],
        "reference": cve_item["cve"]["references"]["reference_data"][:],
        "description": cve_item["cve"]["description"]["description_data"][0]["value"]
    }


def download_feed(meta, feed):
    """Download and parse feed"""

    ctx = {}

    if not retrieve_url(meta["url"], meta["file"]):
        return {}

    ctx["meta"] = ctx_meta(meta["file"])

    if not "sha256" in ctx["meta"]:
        return {}

    ctx["feed"] = ctx_gzip(feed["file"], ctx["meta"]["sha256"])

    if not ctx["feed"]:
        if not retrieve_url(feed["url"], feed["file"]):
            return {}

        ctx["feed"] = ctx_gzip(feed["file"], ctx["meta"]["sha256"])

    return ctx


def retrieve_url(url, filename=None):
    """Download file by URL"""

    if filename:
        os.makedirs(os.path.dirname(filename), exist_ok=True)

    logging.debug("downloading %s", url)

    try:
        urllib.request.urlretrieve(url, filename=filename)
    except urllib.error.HTTPError:
        logging.error("failed to download URL %s", url, exc_info=True)
        return False

    return True


def logconfig(debug_flag=False):
    """Return default log config"""

    return {
        "version": 1,
        "formatters": {
            "f": {
                "format": "# %(asctime)s %% CVERT %% %(levelname)-8s %% %(message)s"
            }
        },
        "handlers": {
            "h": {
                "class": "logging.StreamHandler",
                "formatter": "f",
                "level": logging.DEBUG if debug_flag else logging.INFO
            }
        },
        "root": {
            "handlers": ["h"],
            "level": logging.DEBUG if debug_flag else logging.INFO
        },
    }


def save_cve(filename, cve_struct):
    """Save CVE structure in the file"""

    filename = os.path.realpath(filename)

    logging.debug("saving %d CVE records to %s", len(cve_struct), filename)

    with open(filename, "wb") as fil:
        pickle.dump(cve_struct, fil)


def load_cve(filename):
    """Load CVE structure from the file"""

    filename = os.path.realpath(filename)

    logging.debug("loading from %s", filename)

    with open(filename, "rb") as fil:
        cve_struct = pickle.load(fil)

    logging.debug("cve records: %d", len(cve_struct))

    return cve_struct
