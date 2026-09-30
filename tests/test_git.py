import subprocess

import pytest

import fakes
from secrets_scanner.cli import main
from secrets_scanner.scanner import scan_history, scan_staged


def git(repo, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def commit(repo, path, content, msg="change") -> str:
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(content, encoding="utf-8")
    git(repo, "add", path)
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.name", "Test User")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    git(tmp_path, "config", "commit.gpgsign", "false")
    commit(tmp_path, "README.md", "hello\n", "initial")
    return tmp_path


def test_history_finds_secret_deleted_later(repo):
    key = fakes.aws_key_id()
    leaked_in = commit(repo, "app/config.py", f"KEY = '{key}'\n", "add config")
    commit(repo, "app/config.py", "KEY = os.environ['KEY']\n", "remove key")

    [f] = scan_history(repo)
    assert (f.secret, f.commit, f.path, f.line) == (key, leaked_in, "app/config.py", 1)
    assert f.author == "Test User <test@example.invalid>"


def test_history_finds_unreachable_blob(repo):
    key = fakes.aws_key_id()
    commit(repo, "config.py", f"KEY = '{key}'\n", "oops")
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    git(repo, "reflog", "expire", "--expire=now", "--all")

    [f] = scan_history(repo)
    assert f.secret == key and f.commit is None and f.extra["unreachable"]


def test_secret_across_file_versions_reported_once(repo):
    key = fakes.aws_key_id()
    first = commit(repo, "config.py", f"KEY = '{key}'\n")
    commit(repo, "config.py", f"KEY = '{key}'\nDEBUG = True\n")

    [f] = scan_history(repo)
    assert f.commit == first and f.extra["blobs"] == 2


def test_staged_reports_only_added_lines(repo):
    old, new = fakes.aws_key_id(), fakes.aws_key_id()
    commit(repo, "config.py", f"OLD = '{old}'\n")
    (repo / "config.py").write_text(f"OLD = '{old}'\nNEW = '{new}'\n", encoding="utf-8")
    git(repo, "add", "config.py")

    [f] = scan_staged(repo)
    assert (f.secret, f.path, f.line) == (new, "config.py", 2)


def test_staged_clean_and_unstaged_ignored(repo):
    (repo / "config.py").write_text(f"KEY = '{fakes.aws_key_id()}'\n", encoding="utf-8")
    assert scan_staged(repo) == []


def test_pre_commit_hook_blocks_commit(repo):
    assert main(["install-hook", str(repo)]) == 0
    (repo / "config.py").write_text(f"KEY = '{fakes.aws_key_id()}'\n", encoding="utf-8")
    git(repo, "add", "config.py")
    result = subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "leak"],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "aws-access-key-id" in result.stdout + result.stderr


def test_cli_exit_codes(repo, capsys):
    assert main(["history", str(repo)]) == 0
    commit(repo, "config.py", f"KEY = '{fakes.aws_key_id()}'\n")
    assert main(["history", str(repo), "--json"]) == 1
