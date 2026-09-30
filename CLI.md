# Command-line reference

Run the tool from inside the project folder:

```sh
python3 -m secrets_scanner <command> [arguments] [options]
```

If you installed it with `pip install .`, you can type `secrets-scan <command> ...` instead.

Add `-h` to any command to see its built-in help, for example `python3 -m secrets_scanner audit -h`.

## Commands at a glance

| Command | What it does |
|---|---|
| [`audit`](#audit) | Full system check: Lynis, Trivy and the exposed-file scan, combined into one report |
| [`system`](#system) | Finds credential files, unencrypted sensitive files and badly set permissions on disk |
| [`files`](#files) | Looks for secrets (keys, tokens, passwords) inside files and folders |
| [`history`](#history) | Looks for secrets anywhere in a git repository's history |
| [`staged`](#staged) | Looks for secrets in changes you are about to commit |
| [`install-hook`](#install-hook) | Makes git run `staged` automatically before every commit |

## Exit codes

Every command ends with one of these codes, which is useful in scripts and CI:

| Code | Meaning |
|---|---|
| `0` | Nothing found |
| `1` | Something was found (secrets, flagged files, Lynis warnings or CVEs) |
| `2` | Error (for example, the folder is not a git repository) |

---

## `audit`

Runs three checks and writes one report:

1. **Lynis** checks how securely the system is configured (SSH, logins, permissions, services, firewall, kernel settings) and gives a hardening score out of 100.
2. **Trivy** checks installed packages against public vulnerability (CVE) databases and shows which version fixes each problem.
3. The **exposed-file scan** (the same as [`system`](#system)) finds leftover credentials and unencrypted sensitive files.

```sh
sudo python3 -m secrets_scanner audit [PATHS...] [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `PATHS...` | `/home /root /etc /opt /srv /var/www` | Folders to search for exposed files. Folders that don't exist are skipped. This does not limit Lynis or Trivy, which always check the whole system. |
| `-o FILE`, `--output FILE` | print to terminal | Save the report to `FILE`. A name ending in `.json` gives JSON; anything else gives Markdown. |
| `--skip-lynis` | off | Don't run Lynis (saves a few minutes). |
| `--skip-trivy` | off | Don't run Trivy. |

Notes:
- Run it with `sudo`. Without root, Lynis is skipped and many files can't be read.
- If Lynis or Trivy isn't installed, the report marks it as skipped and the other checks still run. Install both with `sudo apt install lynis trivy`.
- The first Trivy run downloads its vulnerability database, which takes a few minutes.
- The Markdown report lists the 30 most severe CVEs. The JSON report lists all of them.
- The report never shows the actual value of a secret, only a shortened preview.

Examples:
```sh
sudo python3 -m secrets_scanner audit -o report.md
sudo python3 -m secrets_scanner audit /home /var/www -o report.json
sudo python3 -m secrets_scanner audit --skip-lynis -o quick.md
```

---

## `system`

Searches folders for files that shouldn't be left lying around:

| Category | What it means | Examples |
|---|---|---|
| `credential-file` | A file that usually holds passwords, keys or tokens | `.env`, `*.pem`, `*.key`, `.netrc`, `.pgpass`, `.aws/credentials`, `wp-config.php`, `*.kdbx` |
| `world-readable-secret` | An SSH private key or `.env` file that other users on the machine can read | `~/.ssh/id_rsa` with permissions `-rw-r--r--` |
| `unencrypted-sensitive` | A backup, dump or export whose name suggests private data | `customer_backup.csv`, `passwords.bak`, `db_dump.sql` |

Text files under 5 MB that get flagged are also opened and checked for secrets, using the same rules as [`files`](#files). Files that look encrypted are marked `[appears encrypted]` instead.

```sh
sudo python3 -m secrets_scanner system PATHS... [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `PATHS...` | required | One or more folders (or files) to search. |
| `--json` | off | Output JSON instead of readable text. |
| `--no-peek` | off | Only report which files are risky; don't open them to look for secrets inside. |

Skipped folders: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.tox`, `proc`, `sys`, `dev`, `run`, `snap`.

Example:
```sh
sudo python3 -m secrets_scanner system /home /etc /opt
```

---

## `files`

Searches ordinary files and folders for secrets such as AWS keys, GitHub tokens, Slack tokens, Stripe keys, Google and Anthropic API keys, private keys, and passwords assigned in code or config.

```sh
python3 -m secrets_scanner files PATHS... [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `PATHS...` | required | Files or folders to scan. |
| plus the [shared secret-scan options](#shared-secret-scan-options) | | |

Files over 2 MB and binary files are skipped, and so are the same folders as in `system` except `proc`, `sys`, `dev`, `run` and `snap`.

---

## `history`

Scans **every version of every file** ever stored in a git repository, including files from rewritten or deleted history that git still keeps. Each secret is reported once, with the commit, author and date where it first appeared.

```sh
python3 -m secrets_scanner history [REPO] [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `REPO` | `.` (current folder) | Path to the git repository. |
| `--max-blob-size BYTES` | `2097152` (2 MB) | Skip stored file versions bigger than this. |
| plus the [shared secret-scan options](#shared-secret-scan-options) | | |

---

## `staged`

Checks only the lines you have added with `git add`, so it's fast enough to run on every commit.

```sh
python3 -m secrets_scanner staged [REPO] [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `REPO` | `.` | Path to the git repository. |
| plus the [shared secret-scan options](#shared-secret-scan-options) | | |

---

## `install-hook`

Installs a git pre-commit hook that runs `staged` before each commit and blocks the commit if a secret is found.

```sh
python3 -m secrets_scanner install-hook [REPO] [options]
```

| Argument / option | Default | What it does |
|---|---|---|
| `REPO` | `.` | Repository to install the hook in. |
| `--min-confidence {low,medium,high}` | `medium` | Only block commits for findings at this level or higher. |
| `--force` | off | Replace an existing pre-commit hook that wasn't installed by this tool. |

To commit anyway in an emergency, use `git commit --no-verify`.

---

## Shared secret-scan options

`files`, `history` and `staged` all accept these options:

| Option | Default | What it does |
|---|---|---|
| `--json` | off | Output JSON instead of readable text. |
| `--show-secrets` | off | Show full secret values instead of a shortened preview. Be careful where this output ends up. |
| `--min-confidence {low,medium,high}` | `low` | Only show findings at this confidence or higher (see below). |
| `--baseline FILE` | none | Hide findings already recorded in this baseline file. |
| `--write-baseline FILE` | none | Save the current findings to `FILE` as accepted, then exit with code `0`. If you also pass `--baseline`, it is ignored. |

### Confidence levels

| Level | Meaning |
|---|---|
| `high` | Almost certainly a real secret, for example a GitHub token with a valid checksum, an AWS `AKIA` key or a full private key. |
| `medium` | Probably a secret, for example a temporary AWS key or a Google API key (these are often meant to be public). |
| `low` | A random-looking value assigned to a name like `password` or `api_key`. Worth a look, but may be a false alarm. |

Findings in test folders (`tests/`, `fixtures/`, `examples/`, …) are lowered by one level. Lockfiles and minified files are skipped entirely.

### Ignoring a false alarm

- **One line:** add `secrets-scanner:allow` anywhere on that line, for example in a comment.
- **Everything found so far:** save a baseline with `--write-baseline baseline.json`, then pass `--baseline baseline.json` on later scans. Only new findings will appear.
