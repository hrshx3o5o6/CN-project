"""Crypto primitives: identities, consortium-CA certificates, signed envelopes, sealed boxes.

Ed25519  -> signatures (identity, envelopes, ledger blocks)
X25519 + HKDF-SHA256 + AES-256-GCM -> end-to-end encryption of patient records (ECIES style)
"""
import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from cryptography.exceptions import InvalidSignature

MAX_SKEW = 120  # seconds an envelope timestamp may differ from local clock


class CryptoError(Exception):
    pass


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def canon(obj) -> bytes:
    """Canonical JSON bytes (stable for signing / hashing)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pid_hash(patient_id: str) -> str:
    """Pseudonymous patient reference used on the wire/ledger instead of the raw ID."""
    return sha256_hex(("medmesh|" + patient_id).encode())[:16]


def _pub_raw(pub) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _priv_raw(priv) -> bytes:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def verify_sig(pub_b64: str, data: bytes, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(unb64(pub_b64)).verify(unb64(sig_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- certificates
def new_ca() -> dict:
    sk = Ed25519PrivateKey.generate()
    return {"ca_priv": b64(_priv_raw(sk)), "ca_pub": b64(_pub_raw(sk.public_key()))}


def issue_identity(ca_priv_b64: str, name: str) -> dict:
    """Consortium CA enrols a hospital: generates its keys and signs its certificate."""
    sk, ek = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
    sign_pub, enc_pub = b64(_pub_raw(sk.public_key())), b64(_pub_raw(ek.public_key()))
    body = {"name": name, "node_id": sha256_hex(unb64(sign_pub))[:12], "sign_pub": sign_pub, "enc_pub": enc_pub}
    ca = Ed25519PrivateKey.from_private_bytes(unb64(ca_priv_b64))
    cert = dict(body, ca_sig=b64(ca.sign(canon(body))))
    return {"name": name, "sign_priv": b64(_priv_raw(sk)), "enc_priv": b64(_priv_raw(ek)), "cert": cert}


def verify_cert(ca_pub_b64: str, cert: dict) -> bool:
    try:
        body = {k: cert[k] for k in ("name", "node_id", "sign_pub", "enc_pub")}
        return (sha256_hex(unb64(body["sign_pub"]))[:12] == body["node_id"]
                and verify_sig(ca_pub_b64, canon(body), cert["ca_sig"]))
    except (KeyError, ValueError, TypeError):
        return False


class Identity:
    def __init__(self, d: dict):
        self.name = d["name"]
        self.cert = d["cert"]
        self.node_id = self.cert["node_id"]
        self._sk = Ed25519PrivateKey.from_private_bytes(unb64(d["sign_priv"]))
        self._ek = X25519PrivateKey.from_private_bytes(unb64(d["enc_priv"]))

    def sign(self, data: bytes) -> str:
        return b64(self._sk.sign(data))

    def open(self, box: dict, aad: bytes = b"") -> bytes:
        return open_sealed(self._ek, box, aad)


# ---------------------------------------------------------------- sealed boxes
def _derive(shared: bytes, epk: bytes, rpk: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"medmesh-v1" + epk + rpk).derive(shared)


def seal(recipient_enc_pub_b64: str, plaintext: bytes, aad: bytes = b"") -> dict:
    rpk = unb64(recipient_enc_pub_b64)
    esk = X25519PrivateKey.generate()
    epk = _pub_raw(esk.public_key())
    key = _derive(esk.exchange(X25519PublicKey.from_public_bytes(rpk)), epk, rpk)
    nonce = os.urandom(12)
    return {"epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, aad))}


def open_sealed(enc_priv: X25519PrivateKey, box: dict, aad: bytes = b"") -> bytes:
    try:
        epk = unb64(box["epk"])
        rpk = _pub_raw(enc_priv.public_key())
        key = _derive(enc_priv.exchange(X25519PublicKey.from_public_bytes(epk)), epk, rpk)
        return AESGCM(key).decrypt(unb64(box["nonce"]), unb64(box["ct"]), aad)
    except Exception as e:  # wrong key, tampered ciphertext, bad aad
        raise CryptoError("cannot decrypt sealed box") from e


# ---------------------------------------------------------------- signed envelopes
def make_envelope(identity: Identity, payload: dict) -> dict:
    meta = {"payload": payload, "ts": time.time(), "nonce": b64(os.urandom(12))}
    return {**meta, "cert": identity.cert, "sig": identity.sign(canon(meta))}


def verify_envelope(env: dict, ca_pub_b64: str, seen_nonces: dict | None = None) -> dict:
    """Return sender cert if the envelope is authentic, fresh and not replayed; else raise."""
    try:
        cert, meta = env["cert"], {k: env[k] for k in ("payload", "ts", "nonce")}
    except (KeyError, TypeError):
        raise CryptoError("malformed envelope")
    if not verify_cert(ca_pub_b64, cert):
        raise CryptoError("certificate not issued by consortium CA")
    if not verify_sig(cert["sign_pub"], canon(meta), env.get("sig", "")):
        raise CryptoError("bad signature")
    now = time.time()
    if abs(now - meta["ts"]) > MAX_SKEW:
        raise CryptoError("stale envelope")
    if seen_nonces is not None:
        for n in [n for n, t in seen_nonces.items() if now - t > 2 * MAX_SKEW]:
            del seen_nonces[n]
        if meta["nonce"] in seen_nonces:
            raise CryptoError("replayed envelope")
        seen_nonces[meta["nonce"]] = now
    return cert
