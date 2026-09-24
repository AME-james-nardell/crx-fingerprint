# crx-fingerprint

[![tests](https://github.com/AME-james-nardell/crx-fingerprint/actions/workflows/tests.yml/badge.svg)](https://github.com/AME-james-nardell/crx-fingerprint/actions/workflows/tests.yml)

Inspect any Chrome extension's permissions, hardcoded endpoints and code, **without installing it**.

A `.crx` file is a signed zip. This downloads one from Google's own public update endpoint, unpacks it in a temp directory, and reports what's inside. No code is executed and nothing touches your browser profile.

Written while investigating browser extensions that redirect affiliate traffic. It's general purpose, but it ships with the fingerprint from that investigation as a worked example.

## Requirements

Python 3.9 or newer. **No dependencies.** Standard library only.

Tested on 3.9, 3.12 and 3.14 on every push.

## Usage

```bash
python crx-fingerprint.py <extension-id> [<extension-id> ...]
python crx-fingerprint.py -f ids.txt
python crx-fingerprint.py --show-filtered <extension-id>
```

The extension ID is the 32-character string in a Chrome Web Store URL:

```
https://chromewebstore.google.com/detail/some-extension/dbjlkjnlhjgnabhmibofkhfgcnkgloig
                                                         └────────── this ──────────┘
```

## What it reports

For each extension:

- **Name, version, manifest version** — a localised name stored as `__MSG_appName__` is resolved from `_locales`, so you see what the extension is actually called
- **Permissions, optional permissions and host permissions** — what it's allowed to do, and where
- **Every content script entry** — which pages it injects into, and when
- **Hosts in URLs** — every external host that appears in a literal `http://` or `https://` URL, with the file it appears in. Libraries and platform plumbing are filtered out by domain, not by substring, so `google.com.attacker.example` is not hidden. Pass `--show-filtered` to see what was excluded.
- **Partial hosts** — a URL literal that stops at a dot because its last label is concatenated at runtime, such as `"https://www.google." + countryCode`. Listed separately and never scored, because the host in the file is a fragment rather than a host.
- **Bare references** — a known fingerprint domain written without a scheme. Reported separately, because ordinary JavaScript such as `document.body` has the same shape as a hostname and should never be presented as an external host.
- **Fingerprint match, with the reason for every point awarded**

Files are scanned individually rather than concatenated, so a match cannot be manufactured by a string spanning two files. If any file in the package cannot be read, the report says so and marks the analysis incomplete.

Everything is also unpacked to a fresh temp directory, named for the extension and version, so nothing from a previous run survives. The path is printed at the end.

Hosts in URLs are found by locating candidate URL strings and then parsing them with `urllib.parse.urlsplit`, rather than by pattern matching. That means userinfo, ports, IPv4 and IPv6 literals and internationalised hosts are handled by the standard library: `https://cbmaster.pro@collector.example/` reports `collector.example`, not `cbmaster.pro`, and `https://[2001:db8::1]/collect` reports `2001:db8::1`.

Bare tokens are extracted as complete hostnames, punycode and Unicode labels included, and then compared as domains. `cbmaster.pro.123.attacker.example` and `cbmaster.pro.xn--p1ai` are not counted as `cbmaster.pro`. Host permissions are parsed rather than string-matched, because Chrome ignores the path component of a host permission: `https://*/` grants the same access as `https://*/*`. Content script match patterns are parsed separately, because there the path does matter.

## Resource limits

These packages come from the internet and are controlled by whoever published them, so nothing is read or written without a ceiling:

| Limit | Default |
|---|---|
| Download size | 64 MiB |
| Archive entries | 5,000 |
| Single expanded file | 16 MiB |
| Total expanded size | 256 MiB |

Limits are checked against the archive's metadata **before anything inside it is read**, including the manifest. An archive over the entry or total limit is refused outright: nothing is read and nothing is extracted. Oversized individual files are skipped during scanning and again during extraction, and both are reported.

Every read is performed against a specific archive entry rather than a filename, because a zip may contain two entries with the same name, and a size check on one would otherwise be meaningless. Duplicate filenames are flagged.

Edit the constants at the top of the file to change the limits.

## Tests

```bash
python test_crx_fingerprint.py
```

Thirty-five tests, no network access.

Most are regression tests: every case is one that previously gave a wrong answer. Substring domain matches, userinfo spoofing, punycode truncation, IPv6 literals dropped, JavaScript properties reported as hosts, `<all_urls>` not recognised, archive limits, duplicate archive entries.

The rest drive `analyse()` end to end against archives built in memory, with the download replaced, so the whole path from package to verdict is covered: a matching extension scores, a benign one doesn't, a domain split across two files doesn't, an oversized member produces an incomplete verdict, and an archive over the entry limit is refused before anything is read.

## Exit status

`0` if every extension was analysed completely. `1` if any download, unpack or extraction failed, if any file could not be read, or if any ID was invalid. `2` for a usage error. Incomplete analyses are also flagged next to the verdict, so a partial result is never mistaken for a clean one.

## Example

```
$ python crx-fingerprint.py ejcfngdpgojodfjcajnglnhppglcfedg

  name in manifest : Cashback Master
  version          : 1.0.0.2
  manifest_version : 3
  permissions      : ['alarms', 'cookies', 'declarativeNetRequestWithHostAccess',
                      'storage', 'tabs', 'webRequest']
  host_permissions : ['http://*/*', 'https://*/*']
  content_scripts  : 1 entry(s)
     [0] matches=['http://*/*', 'https://*/*'] run_at=document_start all_frames=False

  HOSTS IN URLS    :
     cbmaster.pro                                 background.js
     static.cbmaster.pro                          content.js
     tp.cbmaster.pro                              background.js
  INFRA DOMAINS    :
     cbmaster.pro                 seen as static.cbmaster.pro            content.js
  MERCHANT LIST    : 0/14
  'tp.' SUBDOMAIN  : ['tp.cbmaster.pro']  (parent domain also present)

  VERDICT          : STRONG MATCH (score 9)
     +2 exact fingerprint permission set
     +1 host access to all sites
     +1 content script at document_start on all sites
     +3 known infrastructure domain (cbmaster.pro)
     +2 tp. subdomain alongside its parent domain (tp.cbmaster.pro)
```

## The permission worth looking for

`declarativeNetRequestWithHostAccess` lets an extension **rewrite and redirect network requests**. Combined with broad host access, that is the ability to intercept a navigation to any site before the browser contacts it.

**Be careful how much weight you put on the permission string.** Chrome's plain `declarativeNetRequest` permission, combined with host permissions, provides the same redirect capability; the two differ in how host access is granted rather than in what they allow. The string is useful for identifying a particular pattern. Its absence does not establish that an extension cannot redirect.

Plenty of legitimate extensions need broad permissions. Ad blockers use declarative rules for exactly what they say on the tin. The question this tool helps you ask is whether the permissions an extension requests match what it claims to do.

For reference, I checked sixteen mainstream cashback and coupon extensions. Two of them request `declarativeNetRequestWithHostAccess`: Troywell, and Cashback Assistant, which turns out to be Opera's. The other fourteen do the job with `scripting`, `webNavigation` and `webRequest`. None of the sixteen matches the full fingerprint below.

## The bundled fingerprint

The scoring is tuned to a specific pattern found in two extensions that redirect typed URLs through affiliate links:

| Component | Points |
|---|---|
| Exact fingerprint permission set | +2 |
| Superset of those permissions | +1 |
| Host access to all sites | +1 |
| Content script at `document_start` on all sites | +1 |
| A known infrastructure domain | +3 |
| A `tp.` subdomain alongside its parent domain | +2 |
| A `tp.` subdomain with a sibling host under the same parent | +1 |
| A `tp.` subdomain with neither | +1 |
| Five or more merchants from the known list | +3 |
| One to four merchants | +1 |

`STRONG MATCH` at 5 or more, `POSSIBLE MATCH` at 2 to 4, otherwise `no fingerprint match`. Every point awarded is printed with its reason, so you can judge the verdict rather than trust it.

Edit the `INFRA`, `MERCHANTS` and `FINGERPRINT_PERMS` constants at the top of the file to fingerprint something else.

A `STRONG MATCH` means the package resembles that pattern. **It is not an accusation and not a finding of wrongdoing.** It means look more closely.

## Limitations

- Removed or unpublished extensions can't be downloaded from the update endpoint. Only the Chrome Web Store is queried, so an extension published solely to the Edge or Firefox stores will not resolve.
- URLs assembled at runtime appear as fragments, because the tool reports the strings that are actually in the file. `"https://www.google." + tld` is caught and listed separately under `PARTIAL HOSTS`. `"https://app.ahrefs" + ".com"` cannot be told apart from a real host and is reported as `app.ahrefs`. Read the host list with that in mind.
- Domains fetched at runtime rather than hardcoded won't appear. Several extensions pull their configuration after install, so an empty host list doesn't mean the extension talks to nobody.
- Packaged `declarative_net_request` rulesets are not yet parsed. A rule file can contain thousands of redirect rules that this tool does not currently read.
- Only text-like members are scanned: `.js`, `.mjs`, `.json`, `.html`, `.htm`, `.css`, `.txt`, `.map`. A host hardcoded in a WebAssembly module or any other extension is not seen.
- Reading the package tells you what the code *can* do, not what it *does*. For that you need `chrome://net-export` and a clean profile.

## Background

This came out of two investigations into browser extensions that rewrite navigations to insert affiliate tracking:

- [I Typed a Train Company's Address. Six Intermediaries Later, Someone Had Earned a Commission.](https://affiliatemanager.expert/2026/09/21/browser-extension-affiliate-hijacking/)
- I Typed a Travel Site's Address and Never Got There. *(link to follow)*

## Licence

MIT. See [LICENSE](LICENSE).

## Author

James Nardell, [Affiliate Manager Expert](https://affiliatemanager.expert). I manage affiliate programs and write about attribution, fraud and leakage.

Issues and pull requests welcome, particularly additional fingerprints.
