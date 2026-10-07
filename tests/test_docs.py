"""
Documentation guards: every local link in the README and docs/ must resolve,
and the advertised surfaces (docs index, badges, languages) must stay real.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)\s]+)\)")


def _markdown_files():
    yield os.path.join(ROOT, "README.md")
    yield os.path.join(ROOT, "CHANGELOG.md")
    docs = os.path.join(ROOT, "docs")
    for name in sorted(os.listdir(docs)):
        if name.endswith(".md"):
            yield os.path.join(docs, name)


def _local_targets(text):
    for target in LINK_RE.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        yield target


def test_every_local_markdown_link_resolves():
    missing = []
    for path in _markdown_files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for target in _local_targets(text):
            relative = target.split("#", 1)[0]
            if not relative:
                continue
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), relative))
            if not os.path.exists(resolved):
                missing.append(f"{os.path.relpath(path, ROOT)} -> {target}")
    assert not missing, f"broken local links: {missing}"


def test_readme_documents_the_shipped_surfaces():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
        readme = handle.read()

    for surface in (
        "synchunt --doctor",
        "synchunt-tools",
        "--lang",
        "--list-languages",
        "--cookie",
        "--proxy",
        "scripts/check.py",
        "docs/TOOL-COVERAGE.md",
        "docs/DEPLOYMENT.md",
        "CHANGELOG.md",
        "LICENSE",
    ):
        assert surface in readme, f"README no longer mentions {surface}"


def test_readme_languages_match_the_catalogues():
    from core import i18n

    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
        readme = handle.read()

    for code in i18n.available_languages():
        assert code in readme, f"README does not mention language '{code}'"


def test_banner_asset_exists_and_is_svg():
    banner = os.path.join(ROOT, "docs", "assets", "banner.svg")
    assert os.path.exists(banner)
    with open(banner, encoding="utf-8") as handle:
        content = handle.read()
    assert content.lstrip().startswith("<svg")
    assert "SyncHunt" in content


def test_docs_index_lists_every_document():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
        readme = handle.read()
    for name in os.listdir(os.path.join(ROOT, "docs")):
        if name.endswith(".md") and name != "ROADMAP.md":
            assert f"docs/{name}" in readme, f"{name} is not linked from the README"
