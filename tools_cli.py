#!/usr/bin/env python3
"""
SyncHunt - helper CLI (`synchunt-tools`)

Offline equivalents of the small Unix-style helpers in the standard recon
toolchain, so the workflow does not depend on extra binaries:

    synchunt-tools dedupe   urls.txt              # anew
    synchunt-tools unfurl   urls.txt --part keys  # unfurl
    synchunt-tools gf       ssrf urls.txt         # gf + gf-patterns
    synchunt-tools meg-urls --hosts h.txt --paths p.txt   # meg (URL matrix)
    synchunt-tools postman  collection.json       # Postman collection -> URLs
    synchunt-tools hash-id  hashes.txt            # hashcat/john preflight

Every command reads files listed as arguments, or stdin when none are given.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Dict, Iterable, List, Optional, Sequence

from core.hashid import suggest_commands
from core.patterns import GF_PATTERNS, pattern_names

UNFURL_PARTS = ("schemes", "hosts", "domains", "ports", "paths", "keys", "values", "extensions")


# ----------------------------------------------------------------------
# IO helpers
# ----------------------------------------------------------------------
def read_inputs(paths) -> List[str]:
    """Read every path (and/or stdin) into a list of non-empty lines."""
    if isinstance(paths, str):
        paths = [paths]
    lines: List[str] = []
    sources = [p for p in (paths or []) if p]
    if not sources:
        sources = ["-"]
    for path in sources:
        if path == "-":
            data = sys.stdin.read()
            lines.extend(data.splitlines())
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines.extend(handle.read().splitlines())
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def emit(lines: Iterable[str], output: Optional[str] = None) -> int:
    materialised = list(lines)
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            for line in materialised:
                handle.write(f"{line}\n")
    else:
        for line in materialised:
            print(line)
    return len(materialised)


def _split_url(url: str) -> Dict[str, str]:
    match = re.match(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<rest>[^/?#]*)(?P<path>[^?#]*)(?P<query>\?[^#]*)?", url)
    if not match:
        return {}
    parts = match.groupdict()
    rest = parts.get("rest") or ""
    host, _, port = rest.partition(":")
    query = parts.get("query") or ""
    path = parts.get("path") or ""
    keys, values = [], []
    if query.startswith("?"):
        for chunk in query[1:].split("&"):
            if not chunk:
                continue
            key, _, value = chunk.partition("=")
            keys.append(key)
            if value:
                values.append(value)
    extension = ""
    if "." in path.rsplit("/", 1)[-1]:
        extension = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    return {
        "scheme": parts.get("scheme") or "",
        "host": host or "",
        "domain": ".".join(host.split(".")[-2:]) if host and not host.replace(".", "").isdigit() else host,
        "port": port or "",
        "path": path or "",
        "keys": "\n".join(keys),
        "values": "\n".join(values),
        "extensions": extension,
    }


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_dedupe(args) -> int:
    seen, unique = set(), []
    for line in read_inputs(args.files):
        if line in seen:
            continue
        seen.add(line)
        unique.append(line)
    if args.sort:
        unique.sort()
    count = emit(unique, args.output)
    if args.count and not args.output:
        print(f"# {count} unique line(s)", file=sys.stderr)
    return 0


def cmd_unfurl(args) -> int:
    wanted = UNFURL_PARTS if args.part == "all" else (args.part,)
    buckets: Dict[str, set] = {part: set() for part in wanted}
    for url in read_inputs(args.files):
        parts = _split_url(url)
        for part in wanted:
            value = parts.get(part.rstrip("s") if part in ("schemes", "hosts", "domains", "ports", "paths", "keys", "values", "extensions") else part, "")
            if not value:
                value = parts.get(part, "")
            for item in str(value).splitlines():
                if item:
                    buckets[part].add(item)
    lines: List[str] = []
    for part in wanted:
        for item in sorted(buckets[part]):
            lines.append(f"{part}\t{item}" if args.with_labels else item)
    count = emit(lines, args.output)
    if args.count and not args.output:
        print(f"# {count} value(s)", file=sys.stderr)
    return 0


def cmd_gf(args) -> int:
    if args.list or not args.pattern:
        print("available patterns (gf-patterns equivalent):")
        for name in pattern_names():
            print(f"  {name:<18} {GF_PATTERNS[name]['description']}")
        return 0
    if args.pattern not in GF_PATTERNS:
        print(f"unknown pattern '{args.pattern}' - use --list", file=sys.stderr)
        return 2
    patterns = [re.compile(p) for p in GF_PATTERNS[args.pattern]["patterns"]]  # type: ignore[index]
    matched = [line for line in read_inputs(args.files) if any(p.search(line) for p in patterns)]
    count = emit(matched, args.output)
    if args.count and not args.output:
        print(f"# {count} match(es) for '{args.pattern}'", file=sys.stderr)
    return 0


def cmd_meg_urls(args) -> int:
    hosts = read_inputs(args.hosts) if args.hosts else []
    paths = read_inputs(args.paths) if args.paths else []
    if not hosts or not paths:
        print("meg-urls needs --hosts and --paths files", file=sys.stderr)
        return 2
    urls: List[str] = []
    for host in hosts:
        base = host if "://" in host else f"{args.scheme}://{host}".rstrip("/")
        for path in paths:
            urls.append(f"{base}/{path.lstrip('/')}")
    count = emit(urls, args.output)
    if args.count and not args.output:
        print(f"# {count} URL(s)", file=sys.stderr)
    return 0


def _postman_urls(node: object) -> List[str]:
    """Walk a Postman v2 collection and pull out request URLs."""
    urls: List[str] = []

    def walk(item: object) -> None:
        if isinstance(item, dict):
            request = item.get("request")
            if isinstance(request, dict):
                url = request.get("url")
                if isinstance(url, str):
                    urls.append(url)
                elif isinstance(url, dict):
                    if url.get("raw"):
                        urls.append(str(url["raw"]))
                    else:
                        host = ".".join(url.get("host", []) or [])
                        path = "/".join(url.get("path", []) or [])
                        if host:
                            urls.append(f"{url.get('protocol', 'https')}://{host}/{path}".rstrip("/"))
            for child in item.get("item", []) or []:
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(node)
    return urls


def cmd_postman(args) -> int:
    with open(args.file, "r", encoding="utf-8", errors="replace") as handle:
        collection = json.load(handle)
    variables = {}
    for var in (collection.get("variable") or []):
        if isinstance(var, dict) and var.get("key"):
            variables[str(var["key"])] = str(var.get("value", ""))
    urls = []
    for url in _postman_urls(collection):
        for key, value in variables.items():
            url = url.replace("{{" + key + "}}", value)
        urls.append(url)
    count = emit(sorted(set(urls)), args.output)
    if args.count and not args.output:
        print(f"# {count} request URL(s)", file=sys.stderr)
    return 0


def cmd_hash_id(args) -> int:
    values = read_inputs(args.files)
    if not values:
        return 0
    if args.json:
        print(json.dumps([suggest_commands(v) for v in values], indent=2))
        return 0
    for value in values:
        result = suggest_commands(value)
        if not result["identified"]:
            print(f"{value}\tunknown")
            continue
        for candidate in result["candidates"]:  # type: ignore[union-attr]
            print(f"{value}\t{candidate['name']}\thashcat -m {candidate['hashcat_mode']}\tjohn --format={candidate['john_format']}")
    return 0


def cmd_identify(args) -> int:
    """Identify hashes buried in free text (a JS bundle, a leak dump)."""
    text = sys.stdin.read()
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    from core.hashid import find_hashes_in_text

    for hit in find_hashes_in_text(text, limit=args.limit):
        names = ", ".join(str(c["name"]) for c in hit["candidates"])  # type: ignore[index]
        print(f"{hit['value']}\t{names}")
    return 0


# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="synchunt-tools",
        description="Offline helpers: dedupe (anew), unfurl, gf-patterns, meg URL matrix, "
                    "Postman collections, hashcat/john preflight.",
    )
    sub = parser.add_subparsers(dest="command")

    dedupe = sub.add_parser("dedupe", help="unique lines, order preserved (anew)")
    dedupe.add_argument("files", nargs="*")
    dedupe.add_argument("-o", "--output")
    dedupe.add_argument("--sort", action="store_true")
    dedupe.add_argument("--count", action="store_true")
    dedupe.set_defaults(func=cmd_dedupe)

    unfurl = sub.add_parser("unfurl", help="pull one part out of URLs (unfurl)")
    unfurl.add_argument("files", nargs="*")
    unfurl.add_argument("--part", default="domains",
                        choices=list(UNFURL_PARTS) + ["all"])
    unfurl.add_argument("--with-labels", action="store_true")
    unfurl.add_argument("-o", "--output")
    unfurl.add_argument("--count", action="store_true")
    unfurl.set_defaults(func=cmd_unfurl)

    gf = sub.add_parser("gf", help="pattern-match URLs (gf + gf-patterns)")
    gf.add_argument("pattern", nargs="?")
    gf.add_argument("files", nargs="*")
    gf.add_argument("--list", action="store_true", help="list the built-in patterns")
    gf.add_argument("-o", "--output")
    gf.add_argument("--count", action="store_true")
    gf.set_defaults(func=cmd_gf)

    meg = sub.add_parser("meg-urls", help="host x path URL matrix (meg)")
    meg.add_argument("--hosts")
    meg.add_argument("--paths")
    meg.add_argument("--scheme", default="https", choices=["http", "https"])
    meg.add_argument("-o", "--output")
    meg.add_argument("--count", action="store_true")
    meg.set_defaults(func=cmd_meg_urls)

    postman = sub.add_parser("postman", help="Postman collection -> request URLs")
    postman.add_argument("file")
    postman.add_argument("-o", "--output")
    postman.add_argument("--count", action="store_true")
    postman.set_defaults(func=cmd_postman)

    hash_id = sub.add_parser("hash-id", help="identify hashes + hashcat/john commands")
    hash_id.add_argument("files", nargs="*")
    hash_id.add_argument("--json", action="store_true")
    hash_id.set_defaults(func=cmd_hash_id)

    identify_cmd = sub.add_parser("identify", help="find hashes inside free text")
    identify_cmd.add_argument("file", nargs="?")
    identify_cmd.add_argument("--limit", type=int, default=25)
    identify_cmd.set_defaults(func=cmd_identify)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
