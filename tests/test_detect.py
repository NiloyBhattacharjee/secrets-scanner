import fakes
from secrets_scanner import baseline
from secrets_scanner.detect import apply_path_policy, scan_text
from secrets_scanner.rules import aws_account_from_key_id


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


def test_aws_key_id_found_with_line_and_column():
    key = fakes.aws_key_id()
    [f] = scan_text(f"import os\nKEY = '{key}'\n")
    assert (f.rule_id, f.secret, f.line, f.column, f.confidence) == ("aws-access-key-id", key, 2, 8, "high")


def test_aws_account_decoding_roundtrip():
    key = fakes.aws_key_id_for_account(123456789012)
    assert aws_account_from_key_id(key) == "123456789012"
    [f] = scan_text(key)
    assert f.extra["aws_account_hint"] == "123456789012"


def test_temporary_aws_key_is_medium():
    [f] = scan_text(fakes.aws_key_id("ASIA"))
    assert f.confidence == "medium"


def test_aws_docs_example_key_ignored():
    assert scan_text("AKIAIOSFODNN7" + "EXAMPLE") == []


def test_aws_secret_access_key():
    text = f'aws_secret_access_key = "{fakes.aws_secret()}"'
    assert rule_ids(scan_text(text)) == ["aws-secret-access-key"]


def test_github_checksum_sets_confidence():
    [good] = scan_text(fakes.github_token(valid=True))
    [bad] = scan_text(fakes.github_token(valid=False))
    assert (good.confidence, good.extra["checksum"]) == ("high", "valid")
    assert (bad.confidence, bad.extra["checksum"]) == ("medium", "mismatch")


def test_private_key_block_reported_whole():
    pem = fakes.private_key_pem()
    [f] = scan_text("config:\n" + pem)
    assert f.rule_id == "private-key" and f.secret == pem.strip() and f.line == 2


def test_private_key_header_in_code_ignored():
    code = 'if line.startswith("-----BEGIN RSA PRIVATE KEY-----"):\n    parse(line)\n'
    assert scan_text(code) == []


def test_escaped_pem_in_json():
    pem = fakes.private_key_pem().replace("\n", "\\n")
    assert rule_ids(scan_text(f'{{"private_key": "{pem}"}}')) == ["private-key"]


def test_generic_high_entropy_assignment():
    [f] = scan_text(f'api_key = "{fakes.generic_secret()}"')
    assert (f.rule_id, f.confidence) == ("generic-secret", "low")


def test_generic_ignores_low_entropy_and_code():
    text = "\n".join([
        "api_key = getApiKeyFromEnvironmentSettings()",
        'password = "changeme"',
        "token_type = access_token_refresh_value",
        'secret_name = "production_database_password"',
    ])
    assert scan_text(text) == []


def test_specific_rule_wins_over_generic():
    assert rule_ids(scan_text(f'token = "{fakes.github_token()}"')) == ["github-token"]


def test_inline_allow_marker():
    assert scan_text(f"KEY = '{fakes.aws_key_id()}'  # secrets-scanner:allow") == []


def test_path_policy_downgrades_tests_and_skips_lockfiles():
    in_test, in_lock = scan_text(fakes.aws_key_id()) + scan_text(fakes.aws_key_id())
    in_test.path, in_lock.path = "tests/test_config.py", "web/package-lock.json"
    [f] = apply_path_policy([in_test, in_lock])
    assert f is in_test and f.confidence == "medium"


def test_baseline_roundtrip(tmp_path):
    a, b = scan_text(fakes.aws_key_id()) + scan_text(fakes.github_token())
    path = tmp_path / "baseline.json"
    baseline.write(path, [a])
    assert baseline.exclude([a, b], baseline.load(path)) == [b]
    assert a.secret not in path.read_text()
