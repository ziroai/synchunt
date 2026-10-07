"""
SyncHunt - URL classification patterns (gf + gf-patterns equivalent)

The `gf` tool and its pattern collections are pure convenience: a curated list
of regular expressions that splits a URL corpus into bug classes
?(ssrf/xss/sqli/...)? so the right scanner sees the right URLs. SyncHunt ships
the same idea built-in (no binary, no shell) and writes one file per class into
`content_discovery/patterns/`.

`synchunt-tools gf <pattern>` exposes the same library on the command line.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

GF_PATTERNS: Dict[str, Dict[str, object]] = {
    "ssrf": {
        "description": "parameters that fetch remote resources (SSRF)",
        "patterns": [r"[?&](url|uri|dest|redirect|next|target|rurl|link|src|source|callback|feed|host|port|path|proxy|fetch|resource|domain|site|fetch_url|open|load|file|return)="],
    },
    "xss": {
        "description": "reflected parameters worth an XSS pass",
        "patterns": [r"[?&](q|s|search|query|keyword|lang|error|message|msg|name|comment|text|title|body|content|redirect|url|path|callback|jsonp|cb|return|ref|ref_url|data)="],
    },
    "sqli": {
        "description": "parameters commonly fed into SQL",
        "patterns": [r"[?&](id|select|report|role|update|query|sort|where|search|filter|order|by|dir|sort_by|column|table|from|limit|offset|page|cat|category|product|item|user|username|email|pass|password|login)="],
    },
    "lfi": {
        "description": "file/path parameters (LFI, path traversal)",
        "patterns": [r"[?&](file|filename|path|folder|dir|document|root|pg|page|template|include|require|view|img|image|download|upload|log|conf|cfg|config|doc|forward|filepath|url)="],
    },
    "redirect": {
        "description": "open-redirect candidates",
        "patterns": [r"[?&](redirect|redir|url|next|target|dest|destination|return|returnurl|return_url|continue|goto|out|link|to|r|u|forward|callback)=(?:https?|%2f|/|//|\\\\|%5c)"],
    },
    "rce": {
        "description": "command-injection flavoured parameters",
        "patterns": [r"[?&](cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|feature|exe|run|system|daemon|upload|log)="],
    },
    "ssti": {
        "description": "template-injection candidates",
        "patterns": [r"[?&](template|tpl|page|name|title|content|text|message|lang|theme|view|include|render|layout|preview)="],
    },
    "idor": {
        "description": "object references worth an authorisation check",
        "patterns": [r"[?&](id|user|account|account_id|uid|uuid|guid|pid|oid|order|order_id|invoice|doc|document|file|record|profile|number|no|key|ref)=[0-9]"],
    },
    "debug": {
        "description": "debug / admin / internal looking paths",
        "patterns": [r"/(debug|test|dev|staging|admin|internal|private|actuator|console|phpinfo|server-status|swagger|api-docs|graphiql|\.git|\.env|backup|old)(/|\.|$|\?)"],
    },
    "json-sec": {
        "description": "JSON endpoints and secrets-shaped parameters",
        "patterns": [r"\.json(\?|$)", r"[?&](token|key|secret|password|passwd|pwd|auth|apikey|api_key|access_token|session|jwt)="],
    },
    "takeovers": {
        "description": "hosts named like takeover-prone services",
        "patterns": [r"(^|//|\.)(s3|s3-website|storage\.googleapis|blob\.core\.windows|herokudns|herokuapp|cloudfront|github\.io|netlify|vercel|surge|azurewebsites|readthedocs|zendesk|shopify|fastly|fly\.dev|ghost\.io)"],
    },
    "params": {
        "description": "any URL carrying a parameter (not a fragment)",
        "patterns": [r"\?[^#]+="],
    },
    "interestingparams": {
        "description": "auth/identity parameters",
        "patterns": [r"[?&](email|user|username|login|pass|password|token|session|role|admin|isadmin|access|auth|permission|group|team|org|tenant|scope|client_id|grant_type)="],
    },
}


def pattern_names() -> List[str]:
    return sorted(GF_PATTERNS)


def compile_pattern(name: str) -> List["re.Pattern[str]"]:
    """Compile one named pattern set; raises KeyError for unknown names."""
    spec = GF_PATTERNS[name]
    return [re.compile(expr) for expr in spec["patterns"]]  # type: ignore[index]


def matches(name: str, line: str) -> bool:
    """Does one URL match a named pattern set?"""
    return any(regex.search(line) for regex in compile_pattern(name))


def classify_urls(
    urls: Iterable[str],
    names: Optional[Iterable[str]] = None,
) -> Dict[str, List[str]]:
    """
    Split a URL corpus by bug class.

    Returns {pattern_name: [matching urls]} with empty buckets omitted.
    """
    wanted = list(names) if names else pattern_names()
    corpus = [url for url in urls if url]
    buckets: Dict[str, List[str]] = {}
    for name in wanted:
        regexes = compile_pattern(name)
        hits = [url for url in corpus if any(regex.search(url) for regex in regexes)]
        if hits:
            buckets[name] = hits
    return buckets
