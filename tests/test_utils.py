import os

from core.utils import (
    extract_js_urls,
    extract_params_from_urls,
    fenced_block,
    filter_urls_by_extension,
    format_duration,
    get_file_count,
    get_root_domain,
    host_from_url,
    host_matches_domain,
    is_cidr,
    is_in_scope,
    is_ip,
    is_valid_domain,
    is_valid_target,
    merge_files,
    normalize_security_headers,
    normalize_severity,
    quote_args,
    read_file_lines,
    read_json_lines,
    sanitize_filename,
    severity_rank,
    short_hash,
    strip_scheme,
    truncate,
    write_file_lines,
)


def test_domain_validation():
    assert is_valid_domain("example.com")
    assert is_valid_domain("deep.sub.example.co.uk")
    assert not is_valid_domain("example")
    assert not is_valid_domain("ex ample.com")
    assert not is_valid_domain("")
    assert not is_valid_domain("-bad.com")


def test_ip_and_cidr_detection():
    assert is_ip("127.0.0.1")
    assert is_ip("::1")
    assert not is_ip("example.com")
    assert is_cidr("10.0.0.0/24")
    assert not is_cidr("10.0.0.1")


def test_valid_target_accepts_domain_ip_and_cidr():
    assert is_valid_target("example.com")
    assert is_valid_target("192.168.1.10")
    assert is_valid_target("10.0.0.0/24")
    assert not is_valid_target("not a target")


def test_root_domain_handles_multi_label_suffixes():
    assert get_root_domain("shop.example.com") == "example.com"
    assert get_root_domain("deep.shop.example.co.uk") == "example.co.uk"
    assert get_root_domain("api.example.com.au") == "example.com.au"
    assert get_root_domain("127.0.0.1") == "127.0.0.1"


def test_host_helpers():
    assert host_from_url("https://api.example.com:8443/path?x=1") == "api.example.com"
    assert host_from_url("example.com:8080") == "example.com"
    assert strip_scheme("https://example.com/x") == "example.com"


def test_scope_matching_is_boundary_correct():
    # The classic bypass: suffix matching without a dot boundary.
    assert not host_matches_domain("notexample.com", "example.com")
    assert not host_matches_domain("example.com.evil.net", "example.com")
    assert host_matches_domain("api.example.com", "example.com")
    assert host_matches_domain("example.com", "example.com")

    assert is_in_scope("api.example.com", ["example.com"])
    assert not is_in_scope("notexample.com", ["example.com"])
    assert not is_in_scope("example.com.evil.net", ["example.com"])
    assert is_in_scope("10.0.0.5", ["10.0.0.0/24"])
    assert not is_in_scope("10.0.1.5", ["10.0.0.0/24"])
    assert is_in_scope("anything.com", [])  # empty scope = no restriction


def test_file_helpers_roundtrip(tmp_path):
    path = str(tmp_path / "list.txt")
    count = write_file_lines(path, ["a", "b", "a"])
    assert count == 2
    assert read_file_lines(path) == ["a", "b"]
    assert get_file_count(path) == 2

    other = str(tmp_path / "other.txt")
    write_file_lines(other, ["b", "c"])
    merged = str(tmp_path / "merged.txt")
    assert merge_files([path, other], merged) == 3
    assert read_file_lines(merged) == ["a", "b", "c"]


def test_jsonl_reader_skips_junk(tmp_path):
    path = str(tmp_path / "out.jsonl")
    with open(path, "w") as fh:
        fh.write('{"a": 1}\n')
        fh.write("not json\n")
        fh.write("[1, 2]\n")
        fh.write('{"b": 2}\n')
    records = read_json_lines(path)
    assert records == [{"a": 1}, {"b": 2}]


def test_url_helpers():
    urls = [
        "https://a.com/app.js",
        "https://a.com/style.css",
        "https://a.com/api?id=1&x=2",
        "https://a.com/page",
    ]
    assert extract_js_urls(urls) == ["https://a.com/app.js"]
    assert filter_urls_by_extension(urls, ["css"]) == ["https://a.com/style.css"]
    assert extract_params_from_urls(urls) == ["https://a.com/api?id=1&x=2"]


def test_severity_helpers():
    assert normalize_severity("CRIT") == "critical"
    assert normalize_severity("Informational") == "info"
    assert normalize_severity(None) == "info"
    assert normalize_severity("banana") == "info"
    assert severity_rank("critical") > severity_rank("low") > severity_rank("info")


def test_normalize_security_headers_accepts_requests_style_mapping():
    flags = normalize_security_headers({"Strict-Transport-Security": "max-age=1"})
    assert flags["strict-transport-security"] is True
    assert flags["content-security-policy"] is False


def test_quote_args_neutralises_shell_metacharacters(tmp_path):
    """Quoted arguments must be passed through the shell literally."""
    import subprocess

    marker = tmp_path / "pwned"
    quoted = quote_args(["echo", f"http://x/$(touch {marker})", "&&", "whoami"])
    result = subprocess.run(
        f"printf '%s' {quoted}", shell=True, capture_output=True, text=True
    )
    assert not marker.exists(), "substitution must not execute inside quotes"
    assert "$(touch" in result.stdout  # passed through literally


def test_fenced_block_neutralises_embedded_fences():
    block = fenced_block("before ``` after")
    assert block.startswith("```")
    assert "` ` `" in block


def test_misc_helpers():
    assert format_duration(3661) == "1h 1m 1s"
    assert format_duration(61) == "1m 1s"
    assert format_duration(5) == "5s"
    assert sanitize_filename("a/b:c*d") == "a_b_c_d"
    assert len(truncate("x" * 100, 10)) == 10
    assert short_hash("a", "b") == short_hash("a", "b")
    assert short_hash("a", "b") != short_hash("b", "a")


def test_no_absolute_paths_leak_into_helpers(tmp_path):
    # sanity: helpers must not create files outside the given directory
    path = os.path.join(str(tmp_path), "x.txt")
    write_file_lines(path, ["1"])
    assert os.path.exists(path)
