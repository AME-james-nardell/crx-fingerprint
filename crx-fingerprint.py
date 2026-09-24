#!/usr/bin/env python3
"""
crx-fingerprint.py: inspect a Chrome extension without installing it.

A .crx file is a signed zip. This downloads one from Google's public update
endpoint, unpacks it into a fresh temp directory, and reports what is inside.
No code is executed and nothing touches your browser profile.

Usage:
    python crx-fingerprint.py <extension-id> [<extension-id> ...]
    python crx-fingerprint.py -f ids.txt
    python crx-fingerprint.py --show-filtered <extension-id>

Reports:

  - the manifest permission set, optional permissions and host permissions
  - every content script entry, with its match patterns and run_at
  - every external host that appears in a literal URL, and the file it is in
  - whether it matches the bundled fingerprint, and why

Exit status is non-zero if any extension failed to download, failed to unpack,
or could only be analysed incompletely.

The fingerprint is tuned to a pattern found in two extensions that redirect
typed URLs through affiliate links. A STRONG MATCH means the package resembles
that pattern. It is not an accusation. Edit INFRA, MERCHANTS and
FINGERPRINT_PERMS below to fingerprint something else.
"""

import argparse
import io
import json
import re
import sys
import tempfile
import zipfile
import urllib.request
from urllib.parse import urlsplit

CRX_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=120&acceptformat=crx2,crx3&x=id%3D{}%26uc"
)

EXT_ID_RE = re.compile(r"^[a-p]{32}$")

# Resource limits. These packages are downloaded from the internet and are
# controlled by whoever published them, so nothing is read or written without
# a ceiling. Limits are enforced before the manifest is read, during scanning,
# and again during extraction.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024     # 64 MiB compressed
MAX_ENTRIES = 5000                        # archive members
MAX_MEMBER_BYTES = 16 * 1024 * 1024       # 16 MiB per expanded file
MAX_TOTAL_BYTES = 256 * 1024 * 1024       # 256 MiB expanded in total

# Infrastructure seen in the Cashback Ninja redirect chain and the
# Cashback Master telemetry call.
INFRA = [
    "cashbackninja.top",
    "cbmaster.pro",
    "n-tab.pro",
    "monetoad.com",
    "pickalink.com",
    "retagro.com",
    "rewardany.com",
    "showmelinks.com",
]

# Merchants seen in the extensions' stored lists.
MERCHANTS = [
    "tidio.com", "coohom.com", "hover.com", "onetravel.com", "airalo.com",
    "voghion.com", "tvcmall.com", "strawberrynet.com", "wowangel.com",
    "luonkos.com", "gamivo.com", "kiwi.com", "trip.com", "thetrainline.com",
]

# Permission set declared by both known extensions.
FINGERPRINT_PERMS = {
    "webRequest", "declarativeNetRequestWithHostAccess",
    "cookies", "storage", "tabs", "alarms",
}

# Libraries, schemas and platform plumbing. Matched as domains, never as
# substrings, so google.com.attacker.example is NOT filtered out.
BORING_DOMAINS = {
    "w3.org", "reactjs.org", "react.dev", "schema.org", "google.com",
    "googleapis.com", "gstatic.com", "github.com", "github.io", "mozilla.org",
    "jquery.com", "npmjs.com", "npms.io", "vuejs.org", "angular.dev",
    "chromium.org", "ecma-international.org", "opensource.org",
    "wikipedia.org", "stackoverflow.com",
}

TEXTISH = re.compile(r"\.(js|mjs|json|html|htm|css|txt|map)$", re.I)

# Candidate URL strings. These are parsed properly rather than pattern
# matched, so userinfo, ports and internationalised hosts are handled by the
# standard library instead of by a regex that has to guess. A bracketed IPv6
# literal is matched first, because the closing bracket would otherwise end
# the candidate and leave urlsplit a malformed URL.
URL_CANDIDATE = re.compile(
    r"""https?://(?:\[[0-9A-Fa-f:.]+\])?[^\s"'<>\\)\]},;]*""", re.I)

# Any dotted token that looks like a hostname, Unicode labels included. Used
# ONLY to test whether a known fingerprint domain appears without a scheme.
# Never reported directly, because ordinary JavaScript such as document.body
# has this shape. The closing boundary refuses to stop before another label,
# so cbmaster.pro.рф is captured whole rather than truncated to cbmaster.pro.
BARE_TOKEN = re.compile(
    r"(?<![\w.\-])((?:[\w\-]+\.)+(?:xn--[\w\-]+|[^\W\d_]{2,}))(?![\w\-]|\.[\w])"
)


def _split_host(candidate):
    """(hostname, is_partial) for a URL string, or (None, False)."""
    try:
        parts = urlsplit(candidate)
        h = parts.hostname
    except ValueError:
        return None, False
    if not h:
        return None, False
    raw = h.strip().lower()
    # A literal that stops at a dot with nothing after it is a URL whose last
    # label is concatenated at runtime, e.g. "https://www.google." + tld. What
    # is in the file is a fragment, not a host, and reporting it as a host is
    # misleading. A trailing dot followed by a path is just a fully qualified
    # name and is fine.
    partial = raw.endswith(".") and not (parts.path or parts.query or parts.fragment)
    h = raw.rstrip(".")
    # A dot means a domain name or an IPv4 address. A colon means an IPv6
    # literal, whose brackets urlsplit has already stripped. Anything with
    # neither is not a host worth reporting.
    if not ("." in h or ":" in h):
        return None, False
    return h, partial


def url_hostname(candidate):
    """Hostname of a URL string, or None. Strips userinfo, port and case."""
    h, partial = _split_host(candidate)
    return None if partial else h


def partial_hostname(candidate):
    """Host fragment from a URL whose last label is built at runtime, or None."""
    h, partial = _split_host(candidate)
    return h if partial else None


# Host permission pattern: scheme://host/path. Chrome ignores the path for
# host permissions, so only scheme and host matter here.
HOST_PERM = re.compile(r"^(\*|https?|file|ftp)://([^/]*)(/.*)?$")

# Content script match pattern. Unlike host permissions, the path matters.
CS_MATCH = re.compile(r"^(\*|https?|file|ftp)://([^/]*)(/.*)$")


def host_matches(host, domain):
    """True for the domain itself or any subdomain of it. Never a substring."""
    host = host.lower().rstrip(".")
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def is_broad_host_permission(pattern):
    """Does this host permission grant access to every host?"""
    if pattern == "<all_urls>":
        return True
    m = HOST_PERM.match(pattern)
    return bool(m) and m.group(2) == "*"


def is_broad_content_match(pattern):
    """Does this content script match pattern cover every host and every path?"""
    if pattern == "<all_urls>":
        return True
    m = CS_MATCH.match(pattern)
    return bool(m) and m.group(2) == "*" and m.group(3) == "/*"


def fetch_crx(ext_id):
    req = urllib.request.Request(
        CRX_URL.format(ext_id),
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    buf = bytearray()
    with urllib.request.urlopen(req, timeout=60) as r:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_DOWNLOAD_BYTES:
                raise ValueError(
                    f"download exceeds {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MiB limit")
    return bytes(buf)


def crx_to_zip(data):
    """CRX2 and CRX3 both wrap a plain zip. Slice from the zip magic."""
    i = data.find(b"PK\x03\x04")
    if i < 0:
        raise ValueError("no zip payload found (not a CRX?)")
    return zipfile.ZipFile(io.BytesIO(data[i:]))


def resolve_localised_name(z, infos, man):
    """A manifest name of __MSG_key__ lives in _locales. Resolve it, or keep it.

    Read by ZipInfo and size checked, like every other read here.
    """
    name = man.get("name")
    if not (isinstance(name, str) and name.startswith("__MSG_")):
        return name
    key = name[6:].rstrip("_").lower()
    by_name = {i.filename: i for i in infos}
    for loc in (man.get("default_locale"), "en_US", "en", "en_GB"):
        if not loc:
            continue
        info = by_name.get(f"_locales/{loc}/messages.json")
        if info is None or info.file_size > MAX_MEMBER_BYTES:
            continue
        try:
            msgs = json.loads(z.read(info).decode("utf-8-sig"))
        except Exception:
            continue
        for k, v in msgs.items():
            if k.lower() == key and isinstance(v, dict) and v.get("message"):
                return v["message"]
    return name


def check_archive_limits(infos):
    """Return a list of limit breaches. Non-empty means do not process."""
    problems = []
    if len(infos) > MAX_ENTRIES:
        problems.append(f"{len(infos)} entries, over the {MAX_ENTRIES} limit")
    total = sum(i.file_size for i in infos)
    if total > MAX_TOTAL_BYTES:
        problems.append(
            f"expands to {total // (1024 * 1024)} MiB, over the "
            f"{MAX_TOTAL_BYTES // (1024 * 1024)} MiB limit")
    return problems


def analyse(ext_id, show_filtered=False):
    """Return 0 if the analysis completed, 1 if it failed or was incomplete."""
    print(f"\n{'=' * 72}\n{ext_id}\n{'=' * 72}")

    try:
        raw = fetch_crx(ext_id)
    except Exception as e:
        print(f"  download failed: {e}")
        return 1
    try:
        z = crx_to_zip(raw)
    except Exception as e:
        print(f"  unpack failed: {e}")
        return 1

    infos = z.infolist()

    # Limits are checked before anything inside the archive is read.
    breaches = check_archive_limits(infos)
    if breaches:
        for b in breaches:
            print(f"  refused: archive {b}")
        print("  nothing was read or extracted")
        return 1

    incomplete = []

    # Duplicate names make a size check on one entry meaningless if the read
    # resolves to another, so every read below is by ZipInfo, not by name.
    seen = {}
    dups = set()
    for i in infos:
        if i.filename in seen:
            dups.add(i.filename)
        seen[i.filename] = i
    if dups:
        incomplete.append(f"{len(dups)} duplicate filename(s) in the archive")

    manifest_info = next((i for i in infos if i.filename == "manifest.json"), None)
    if manifest_info is None:
        print("  no manifest.json in the archive")
        return 1
    if manifest_info.file_size > MAX_MEMBER_BYTES:
        print(f"  refused: manifest.json is {manifest_info.file_size} bytes, "
              f"over the {MAX_MEMBER_BYTES} byte member limit")
        return 1
    try:
        man = json.loads(z.read(manifest_info).decode("utf-8-sig"))
    except Exception as e:
        print(f"  no readable manifest: {e}")
        return 1

    perms = set(man.get("permissions", []))
    optional = set(man.get("optional_permissions", []))
    hosts = man.get("host_permissions", [])
    optional_hosts = man.get("optional_host_permissions", [])
    version = str(man.get("version", "unknown"))

    print(f"  name in manifest : {resolve_localised_name(z, infos, man)}")
    print(f"  version          : {version}")
    print(f"  manifest_version : {man.get('manifest_version')}")
    print(f"  permissions      : {sorted(perms)}")
    if optional:
        print(f"  optional perms   : {sorted(optional)}")
    print(f"  host_permissions : {hosts}")
    if optional_hosts:
        print(f"  optional hosts   : {optional_hosts}")

    scripts = man.get("content_scripts", []) or []
    print(f"  content_scripts  : {len(scripts)} entry(s)")
    broad_early_script = False
    for i, cs in enumerate(scripts):
        matches = cs.get("matches", [])
        run_at = cs.get("run_at", "document_idle")
        print(f"     [{i}] matches={matches} run_at={run_at} "
              f"all_frames={cs.get('all_frames', False)}")
        if run_at == "document_start" and any(is_broad_content_match(m) for m in matches):
            broad_early_script = True

    # url_hosts are reported. bare_hits are only used to notice a known
    # fingerprint domain written without a scheme.
    url_hosts = {}    # host -> first file it appeared in
    partial_hosts = {}  # incomplete host -> first file it appeared in
    bare_hits = {}    # host -> first file it appeared in
    unreadable = []
    skipped = []

    known = INFRA + MERCHANTS

    for info in infos:
        name = info.filename
        if name.endswith("/") or not TEXTISH.search(name):
            continue
        if info.file_size > MAX_MEMBER_BYTES:
            skipped.append(f"{name} ({info.file_size // (1024 * 1024)} MiB)")
            continue
        try:
            text = z.read(info).decode("utf-8", "ignore")
        except Exception as e:
            unreadable.append(f"{name} ({e.__class__.__name__})")
            continue
        for m in URL_CANDIDATE.finditer(text):
            host = url_hostname(m.group(0))
            if host:
                url_hosts.setdefault(host, name)
            else:
                frag = partial_hostname(m.group(0))
                if frag:
                    partial_hosts.setdefault(frag, name)
        for m in BARE_TOKEN.finditer(text):
            host = m.group(1).rstrip(".").lower()
            if host in url_hosts or host in bare_hits:
                continue
            if any(host_matches(host, d) for d in known):
                bare_hits[host] = name

    if unreadable:
        incomplete.append(f"{len(unreadable)} file(s) could not be read")
    if skipped:
        incomplete.append(f"{len(skipped)} file(s) skipped as oversized")

    interesting = {h: f for h, f in url_hosts.items()
                   if not any(host_matches(h, b) for b in BORING_DOMAINS)}
    filtered = {h: f for h, f in url_hosts.items() if h not in interesting}

    # fingerprint matching considers URL hosts and bare references to known domains
    candidates = dict(interesting)
    candidates.update(bare_hits)

    infra_hits = {d: (h, f) for d in INFRA
                  for h, f in candidates.items() if host_matches(h, d)}
    merch_hits = {d: (h, f) for d in MERCHANTS
                  for h, f in candidates.items() if host_matches(h, d)}

    tp_hosts = sorted(h for h in candidates if h.startswith("tp."))
    tp_exact_parent = [h for h in tp_hosts if h[3:] in candidates]
    tp_sibling = [h for h in tp_hosts if h not in tp_exact_parent
                  and any(host_matches(o, h[3:]) and o != h for o in candidates)]

    broad_access = any(is_broad_host_permission(h) for h in hosts)

    print()
    if interesting:
        print("  HOSTS IN URLS    :")
        for h in sorted(interesting):
            print(f"     {h:44} {interesting[h]}")
    else:
        print("  HOSTS IN URLS    : none")
    if partial_hosts:
        print("  PARTIAL HOSTS    :  (last label built at runtime, not in the source)")
        for h in sorted(partial_hosts):
            print(f"     {h + '.*':44} {partial_hosts[h]}")
    if bare_hits:
        print("  BARE REFERENCES  :  (known domains written without a scheme)")
        for h in sorted(bare_hits):
            print(f"     {h:44} {bare_hits[h]}")
    if show_filtered and filtered:
        print("  (filtered)       :")
        for h in sorted(filtered):
            print(f"     {h:44} {filtered[h]}")

    if infra_hits:
        print("  INFRA DOMAINS    :")
        for d in sorted(infra_hits):
            h, f = infra_hits[d]
            print(f"     {d:28} seen as {h:30} {f}")
    else:
        print("  INFRA DOMAINS    : none")

    print(f"  MERCHANT LIST    : {len(merch_hits)}/{len(MERCHANTS)}")
    for d in sorted(merch_hits):
        h, f = merch_hits[d]
        print(f"     {d:28} seen as {h:30} {f}")

    if tp_exact_parent:
        print(f"  'tp.' SUBDOMAIN  : {tp_hosts}  (parent domain also present)")
    elif tp_sibling:
        print(f"  'tp.' SUBDOMAIN  : {tp_hosts}  "
              f"(another host under the same parent domain is present)")
    elif tp_hosts:
        print(f"  'tp.' SUBDOMAIN  : {tp_hosts}")
    else:
        print("  'tp.' SUBDOMAIN  : no")

    for note in incomplete:
        print(f"  INCOMPLETE       : {note}")
    for u in (unreadable + skipped)[:5]:
        print(f"     {u}")

    # Extraction runs before the verdict so that any problem it finds is
    # reflected in the INCOMPLETE flag rather than appearing after it.
    out = tempfile.mkdtemp(prefix=f"crx-{ext_id}-{version}-")
    too_big = 0
    failed = 0
    for info in infos:
        if info.file_size > MAX_MEMBER_BYTES:
            too_big += 1
            continue
        try:
            z.extract(info, out)
        except Exception:
            failed += 1
    if too_big:
        incomplete.append(f"{too_big} file(s) not extracted, over the member limit")
    if failed:
        incomplete.append(f"{failed} file(s) failed to extract")

    score = 0
    reasons = []
    if perms == FINGERPRINT_PERMS:
        score += 2
        reasons.append("+2 exact fingerprint permission set")
    elif perms & FINGERPRINT_PERMS == FINGERPRINT_PERMS:
        score += 1
        reasons.append("+1 superset of fingerprint permissions")
    if broad_access:
        score += 1
        reasons.append("+1 host access to all sites")
    if broad_early_script:
        score += 1
        reasons.append("+1 content script at document_start on all sites")
    if infra_hits:
        score += 3
        reasons.append(f"+3 known infrastructure domain ({sorted(infra_hits)[0]})")
    if tp_exact_parent:
        score += 2
        reasons.append(f"+2 tp. subdomain alongside its parent domain ({tp_exact_parent[0]})")
    elif tp_sibling:
        score += 1
        reasons.append(f"+1 tp. subdomain with a sibling host ({tp_sibling[0]})")
    elif tp_hosts:
        score += 1
        reasons.append("+1 tp. subdomain, parent domain not referenced")
    if len(merch_hits) >= 5:
        score += 3
        reasons.append(f"+3 {len(merch_hits)} merchants from the known list")
    elif merch_hits:
        score += 1
        reasons.append(f"+1 {len(merch_hits)} merchant(s) from the known list")

    verdict = ("STRONG MATCH" if score >= 5 else
               "POSSIBLE MATCH" if score >= 2 else
               "no fingerprint match")
    flag = "  [INCOMPLETE ANALYSIS]" if incomplete else ""
    print()
    print(f"  VERDICT          : {verdict} (score {score}){flag}")
    for r in reasons:
        print(f"     {r}")
    if not reasons:
        print("     no fingerprint components present")

    print()
    print(f"  unpacked to      : {out}")
    if too_big or failed:
        print(f"  (not extracted   : {too_big} oversized, {failed} failed)")

    return 1 if incomplete else 0


def main():
    ap = argparse.ArgumentParser(
        description="Inspect Chrome extensions without installing them.")
    ap.add_argument("ids", nargs="*", help="32-character extension IDs")
    ap.add_argument("-f", "--file", metavar="PATH",
                    help="file containing one extension ID per line")
    ap.add_argument("--show-filtered", action="store_true",
                    help="also list hosts filtered out as libraries or plumbing")
    args = ap.parse_args()

    ids = list(args.ids)
    if args.file:
        try:
            with open(args.file) as fh:
                ids += [l.strip() for l in fh
                        if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(f"cannot read {args.file}: {e}", file=sys.stderr)
            return 2
    if not ids:
        ap.print_help()
        return 2

    failures = 0
    valid = []
    for i in ids:
        if EXT_ID_RE.match(i):
            valid.append(i)
        else:
            print(f"not a valid extension ID, skipping: {i}", file=sys.stderr)
            failures += 1
    if not valid:
        return 2

    for ext_id in valid:
        try:
            failures += analyse(ext_id, show_filtered=args.show_filtered)
        except Exception as e:
            print(f"  unexpected error on {ext_id}: {e}")
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
