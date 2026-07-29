from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import base64
import hashlib
import hmac
import json
import os


MAGIC = "PHOBOS_SEALED_V1"
DEFAULT_ITERATIONS = 390_000


@dataclass(slots=True)
class SealedPayload:
    """Authenticated encrypted payload used for portable local snapshots.

    This keeps Phobos stdlib-only. It derives separate encryption/MAC keys with
    PBKDF2-HMAC-SHA256, XORs plaintext with an HMAC-SHA256 keystream, and MACs
    the header plus ciphertext before writing JSON. It is intended for local
    encrypted exports/backups. Operators who need live SQLite page encryption
    should still deploy on encrypted storage or package with SQLCipher.
    """

    magic: str
    kdf: str
    iterations: int
    salt: str
    nonce: str
    aad: str
    ciphertext: str
    mac: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "kdf": self.kdf,
            "iterations": self.iterations,
            "salt": self.salt,
            "nonce": self.nonce,
            "aad": self.aad,
            "ciphertext": self.ciphertext,
            "mac": self.mac,
        }


def seal_bytes(plaintext: bytes, passphrase: str, *, aad: bytes = b"", iterations: int = DEFAULT_ITERATIONS) -> bytes:
    if not passphrase:
        raise ValueError("passphrase is required")
    salt = os.urandom(16)
    nonce = os.urandom(16)
    enc_key, mac_key = _derive_keys(passphrase, salt, iterations)
    ciphertext = _xor_stream(plaintext, enc_key, nonce)
    aad_b64 = base64.b64encode(aad).decode("ascii")
    mac = _mac(mac_key, salt, nonce, aad, ciphertext, iterations)
    payload = SealedPayload(
        magic=MAGIC,
        kdf="PBKDF2-HMAC-SHA256",
        iterations=iterations,
        salt=base64.b64encode(salt).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        aad=aad_b64,
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        mac=base64.b64encode(mac).decode("ascii"),
    )
    return (json.dumps(payload.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def unseal_bytes(sealed: bytes, passphrase: str, *, aad: bytes = b"") -> bytes:
    if not passphrase:
        raise ValueError("passphrase is required")
    payload = json.loads(sealed.decode("utf-8"))
    if payload.get("magic") != MAGIC:
        raise ValueError("unsupported sealed payload")
    iterations = int(payload.get("iterations", DEFAULT_ITERATIONS))
    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    payload_aad = base64.b64decode(payload.get("aad", ""))
    if aad and payload_aad != aad:
        raise ValueError("sealed payload AAD does not match")
    effective_aad = aad or payload_aad
    ciphertext = base64.b64decode(payload["ciphertext"])
    expected_mac = _mac(_derive_keys(passphrase, salt, iterations)[1], salt, nonce, effective_aad, ciphertext, iterations)
    supplied_mac = base64.b64decode(payload["mac"])
    if not hmac.compare_digest(expected_mac, supplied_mac):
        raise ValueError("sealed payload authentication failed")
    enc_key, _ = _derive_keys(passphrase, salt, iterations)
    return _xor_stream(ciphertext, enc_key, nonce)


def _derive_keys(passphrase: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=64)
    return material[:32], material[32:]


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(value ^ stream for value, stream in zip(data, out))


def _mac(mac_key: bytes, salt: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, iterations: int) -> bytes:
    message = b"|".join([
        MAGIC.encode("ascii"),
        str(iterations).encode("ascii"),
        salt,
        nonce,
        aad,
        ciphertext,
    ])
    return hmac.new(mac_key, message, hashlib.sha256).digest()
