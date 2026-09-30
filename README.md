# secrets-scanner

Finds leaked credentials in git repositories: the full history, including objects left behind by rewritten history, plus a fast pre-commit mode.

```sh
python -m secrets_scanner history [repo]      # every blob in the object store
python -m secrets_scanner staged [repo]       # only lines added in the index
python -m secrets_scanner files PATH...       # plain files on disk
python -m secrets_scanner system PATH...       # audit a live filesystem (see below)
python -m secrets_scanner install-hook [repo] # pre-commit hook (blocks medium+)
```

## System audit mode

`system` walks a live filesystem and reports files that commonly hold secrets or
sensitive data in the clear, so you can secure or remove them:

- **credential files** — `.env`, private SSH keys (`id_rsa`), `*.pem`/`*.key`/`*.pfx`,
  `.netrc`, `.pgpass`, cloud/docker credential files, keystores, and similar;
- **unencrypted sensitive data** — backups, dumps, and exports whose names suggest
  passwords, customer data, SSNs, and the like;
- **weak permissions** — credential files that are group- or world-readable.

Flagged text files are also scanned for embedded secrets using the same rules as
the git modes. Files that look encrypted are noted but not opened for secret matching.

```sh
python -m secrets_scanner system /home /etc /var/www --json
```

It only reads and reports — it never modifies, transmits, or exfiltrates anything.

## Full audit mode

`audit` runs three checks and writes one report:

1. **Lynis** audits hardening: SSH and login settings, file permissions, running services, firewall, kernel settings. It gives a 0–100 hardening index plus warnings and suggested fixes. Needs root.
2. **Trivy** matches installed packages against public CVE databases and lists each known vulnerability with the version that fixes it.
3. The **system** scan above finds exposed credentials and unencrypted files.

```sh
sudo apt install lynis trivy
sudo python3 -m secrets_scanner audit -o report.md            # Markdown report
sudo python3 -m secrets_scanner audit /home /srv -o report.json  # JSON, chosen paths
```

If a tool isn't installed, it's marked as skipped in the report and the other checks still run.

## Scope of use and disclaimer

This is a **defensive auditing tool**. It is intended to help you find and fix
exposed credentials and sensitive files on systems **you own or are explicitly
authorised to test** — for example, your own machine, a lab VM, or a system you
have written permission to assess.

Scanning, accessing, or auditing computer systems without authorisation is illegal
in most jurisdictions. You are solely responsible for how you use this software and
for ensuring you have permission for any system you point it at. A disclaimer does
not grant authorisation — obtaining it is your responsibility.

The software is provided "as is", without warranty of any kind. The authors accept
no liability for any damage, data loss, or legal consequences arising from its use
or misuse. Using this tool means you accept these terms.

Common flags: `--json`, `--min-confidence {low,medium,high}`, `--baseline FILE`, `--write-baseline FILE`, `--show-secrets`.
Exit codes: `0` clean, `1` findings, `2` error.

## How it works

- **Blob-level history scan.** `git cat-file --batch-all-objects` lists every blob, reachable or not, and each one is scanned once through a single `cat-file --batch` process. Only blobs with hits are traced back to a commit, using `git log --find-object`. A secret that persists across many file versions is reported once, at the commit that introduced it.
- **Rules** (`secrets_scanner/rules.py`) use a keyword prefilter, then a regex, then an optional validator. Validators do offline structural checks: CRC32 checksums on GitHub tokens, AWS account-ID decoding from key IDs, and requiring a real body inside PEM blocks.
- **False-positive controls:**
  - a placeholder/stopword filter;
  - entropy plus character-class thresholds for the generic rule;
  - generic hits yield to specific rules on the same span;
  - lockfiles and minified files are skipped, and test paths are downgraded one confidence level;
  - lines with `secrets-scanner:allow` are ignored;
  - a baseline file holds accepted fingerprints.

## Development

```sh
python -m pytest
```
