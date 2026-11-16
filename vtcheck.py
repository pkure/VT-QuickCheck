"""VirusTotal Check: highlight text anywhere on the Mac, right-click > Services > VirusTotal Check.

Reads the selected text on stdin, un-defangs it (hxxps://evil[.]com -> https://evil.com), finds URLs, domains,
IPs and file hashes, and opens each one's VirusTotal page in Chrome (up to 5 tabs). Look-ups only: nothing is
uploaded or submitted for scanning (VirusTotal does see what you look up, so the tool refuses to send links that
carry an email address or a personal token and looks up the bare domain instead).
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import urllib.parse

VT = "https://www.virustotal.com/gui"
MAX_TABS = 5
FILE_EXT = {"exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "js", "html", "htm", "png",
            "jpg", "jpeg", "gif", "svg", "txt", "csv", "json", "xml", "eml", "msg", "lnk", "iso", "img", "ps1", "py",
            "sh", "bat", "vbs", "hta", "md", "log", "tmp", "dat", "bin", "jar", "msi", "rtf", "one", "cab", "rar", "7z",
            "gz", "tar", "ics", "pfbin", "local", "internal", "lan", "test", "example", "invalid", "localhost"}
URL = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.I)
HASH = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])", re.I)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])", re.I)
PERSONAL = re.compile(r"(?i)[\w.+-]+(?:@|%40)[\w-]+\.[\w.-]+|[?&](?:e|email|user|token|t|id|uid)=[^&]{12,}")


def refang(t: str) -> str:
    t = re.sub(r"(?i)\bh(?:xx|\*\*|XX)p(s?)", r"http\1", t)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"),
                 ("[://]", "://"), ("[at]", "@"), ("(at)", "@"), ("[/]", "/")):
        t = t.replace(a, b).replace(a.upper(), b)
    return t


def indicators(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """[(kind, value)] in order of appearance, deduplicated; plus notes for the user."""
    t = refang(text[:16384])
    found, notes, seen = [], [], set()

    def add(kind, value):
        if value.lower() not in seen:
            seen.add(value.lower())
            found.append((kind, value))

    spans = []
    for m in URL.finditer(t):
        u = m.group(0).rstrip(".,;:)]}>'\"")
        spans.append(m.span())
        host = (urllib.parse.urlsplit(u).hostname or "").lower()
        if PERSONAL.search(u):
            notes.append(f"{host}: the link carries an email address or personal token, so only the domain was looked up")
            add("ip" if IPV4.fullmatch(host) else "domain", host)
        else:
            add("url", u)
    rest = "".join(" " if any(a <= i < b for a, b in spans) else ch for i, ch in enumerate(t))
    for m in HASH.finditer(rest):
        add("hash", m.group(0).lower())
    for m in IPV4.finditer(rest):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            notes.append(f"{ip}: private/internal address, skipped (VirusTotal knows nothing about it)")
            continue
        add("ip", str(ip))
    for m in DOMAIN.finditer(re.sub(r"[\w.+-]+@", " ", rest)):   # an email's domain still counts, not its user
        d, tld = m.group(1).lower(), m.group(2).lower()
        if tld in FILE_EXT or IPV4.fullmatch(d) or re.fullmatch(r"[0-9a-f]+(\.[0-9a-f]+)*", d):
            continue
        add("domain", d)
    return found, notes


def vt_url(kind: str, value: str) -> str:
    if kind == "hash":
        return f"{VT}/file/{value}"
    if kind == "ip":
        return f"{VT}/ip-address/{value}"
    if kind == "domain":
        return f"{VT}/domain/{value}"
    return f"{VT}/search/{urllib.parse.quote(value, safe='')}"   # search = look up an existing report, no submit


def notify(msg: str) -> None:
    subprocess.run(["osascript", "-e", f'display notification {quote_as(msg)} with title "VirusTotal Check"'],
                   check=False)


def quote_as(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"')[:220] + '"'


def main() -> None:
    found, notes = indicators(sys.stdin.read())
    if not found:
        notify("No URL, domain, IP address or file hash found in the selection. Nothing was sent.")
        return
    urls = [vt_url(k, v) for k, v in found[:MAX_TABS]]
    r = subprocess.run(["open", "-a", "Google Chrome", *urls], check=False)
    if r.returncode != 0:
        subprocess.run(["open", *urls], check=False)
    extra = len(found) - MAX_TABS
    msg = "; ".join(notes[:2] + ([f"{extra} more not opened (max {MAX_TABS} tabs)"] if extra > 0 else []))
    if msg:
        notify(msg)


if __name__ == "__main__":
    main()
