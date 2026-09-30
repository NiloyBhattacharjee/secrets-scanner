"""Generate fake, well-formed tokens at test time so no secret-looking literals live in the repo."""

import base64
import random
import string

from secrets_scanner.rules import github_checksum

RNG = random.Random(1337)
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B62 = string.ascii_letters + string.digits


def rand(alphabet: str, n: int) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def aws_key_id(prefix: str = "AKIA") -> str:
    return prefix + rand(B32, 16)


def aws_key_id_for_account(account: int) -> str:
    raw = ((account << 7) | RNG.getrandbits(7)).to_bytes(6, "big") + RNG.randbytes(4)
    return "AKIA" + base64.b32encode(raw).decode()


def aws_secret() -> str:
    return rand(B62 + "+/", 40)


def github_token(valid: bool = True) -> str:
    payload = rand(B62, 30)
    checksum = github_checksum(payload) if valid else rand(B62, 6)
    return "ghp_" + payload + checksum


def private_key_pem() -> str:
    body = base64.b64encode(RNG.randbytes(600)).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"


def generic_secret(n: int = 32) -> str:
    return rand(B62, n)
