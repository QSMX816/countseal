#!/usr/bin/env python3
"""CountSeal reference demo — provider / relay / user in one process.

Run:  python3 demo.py
Depends on: cryptography>=41  (pip install -r requirements.txt)
"""
import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

INFO = b"countseal-v1"
WINDOW = 300  # seconds


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(b: bytes) -> str:
    return b64e(hashlib.sha256(b).digest())


def derive_key(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    shared = priv.exchange(pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)


def seal(recipient_pub: X25519PublicKey, plaintext: bytes, aad: bytes) -> dict:
    e = X25519PrivateKey.generate()
    key = derive_key(e, recipient_pub)
    nonce = os.urandom(12)
    return {
        "v": 1,
        "kem": b64e(e.public_key().public_bytes_raw()),
        "nonce": b64e(nonce),
        "ct": b64e(AESGCM(key).encrypt(nonce, plaintext, aad)),
    }


def unseal(recipient_priv: X25519PrivateKey, box: dict, aad: bytes) -> bytes:
    key = derive_key(recipient_priv, X25519PublicKey.from_public_bytes(b64d(box["kem"])))
    return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ct"]), aad)


def canonical(meter: dict) -> bytes:
    return json.dumps(meter, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def show(title: str):
    print(f"\n=== {title} ===")


# ---------------------------------------------------------------- setup
show("SETUP (long-term keys)")
provider_sign = Ed25519PrivateKey.generate()
provider_sign_pub = provider_sign.public_key()
provider_recv = X25519PrivateKey.generate()
provider_recv_pub = provider_recv.public_key()
print("provider Ed25519 pk_p  :", b64e(provider_sign_pub.public_bytes_raw())[:24], "… (pinned)")
print("provider X25519  pk_pr :", b64e(provider_recv_pub.public_bytes_raw())[:24], "… (pinned)")

# ------------------------------------------------- S1 user -> relay -> provider
show("S1  USER builds request")
sk_u = X25519PrivateKey.generate()
pk_u_raw = sk_u.public_key().public_bytes_raw()
nonce_q = os.urandom(12)
prompt = b"Summarize the quarterly revenue report in three bullet points."
request = {
    "v": 1,
    "pk_u": b64e(pk_u_raw),
    "nonce_q": b64e(nonce_q),
    "sealed_prompt": seal(provider_recv_pub, prompt, b"request"),
}
print("relay now sees        : pk_u, nonce_q, sealed_prompt")
print("prompt plaintext      :", prompt.decode())

# --------------------------------------------------------------- S2 provider
show("S2  PROVIDER seals response + signs meter")
response = b"- Revenue up 12% QoQ\n- Margin stable at 41%\n- Churn improved to 3.1%"
n = len(response.split()) + len(prompt.split())  # demo token count; real impl uses tokenizer
k = AESGCM.generate_key(bit_length=256)
nonce_c = os.urandom(12)
ct = AESGCM(k).encrypt(nonce_c, response, b"response")
sealed_response = {"v": 1, "kem": None, "nonce": b64e(nonce_c), "ct": b64e(ct)}
# content key k is sealed to the user's ephemeral pk_u
sealed_k = seal(X25519PublicKey.from_public_bytes(pk_u_raw), k, b"key")
sealed_response["kem"] = sealed_k["kem"]  # one KEM for both boxes in the full spec demo
meter = {
    "v": 1,
    "model_id": "example-model",
    "n": n,
    "h_R": sha256(response),
    "h_C": sha256(ct),
    "h_K": sha256(b64d(sealed_k["ct"])),
    "nonce_q": b64e(nonce_q),
    "ts": int(time.time()),
}
attestation = b64e(provider_sign.sign(canonical(meter)))
envelope = {
    "v": 1,
    "sealed_response": sealed_response,
    "sealed_k": sealed_k,
    "meter": meter,
    "attestation": attestation,
}
print("response plaintext    :", response.decode().replace("\n", " | "))
print("billed token count n  :", n)

# ----------------------------------------------------------------- S3 relay
show("S3  RELAY verifies & bills (cannot decrypt)")
m = envelope["meter"]
canon = canonical(m)
provider_sign_pub.verify(b64d(envelope["attestation"]), canon)
assert abs(time.time() - m["ts"]) <= WINDOW, "stale timestamp"
replay_cache = set()
assert b64d(m["nonce_q"]) not in replay_cache, "replay!"
replay_cache.add(b64d(m["nonce_q"]))
assert 1 <= m["n"] <= 10**6, "n out of bounds"
assert sha256(b64d(envelope["sealed_response"]["ct"])) == m["h_C"]
assert sha256(b64d(envelope["sealed_k"]["ct"])) == m["h_K"]
print("signature             : OK (Ed25519, pk_p)")
print("replay / window / n   : OK")
print("bill                  :", m["n"], "tokens")
print("plaintext visible?    : NO — relay holds no private key")

# ------------------------------------------------------------------ S4 user
show("S4  USER unseals & verifies")
key_back = unseal(sk_u, envelope["sealed_k"], b"key")
box = envelope["sealed_response"]
plain = AESGCM(key_back).decrypt(b64d(box["nonce"]), b64d(box["ct"]), b"response")
assert sha256(plain) == m["h_R"], "content hash mismatch"
assert b64d(m["nonce_q"]) == nonce_q
print("decrypted response    :", plain.decode().replace("\n", " | "))
print("h_R check             : OK — content matches attestation")

# ------------------------------------------------------------ tamper demo
show("TAMPER TEST — corrupt one byte of the ciphertext")
tampered = dict(box)
raw = bytearray(b64d(box["ct"]))
raw[0] ^= 0x01
tampered["ct"] = b64e(bytes(raw))
try:
    bad = AESGCM(key_back).decrypt(b64d(tampered["nonce"]), b64d(tampered["ct"]), b"response")
    assert sha256(bad) != m["h_R"], "accepted tampered content!"
    print("RESULT                : hash mismatch → REJECTED")
except Exception as e:
    print("RESULT                : rejected —", type(e).__name__)

show("DONE — billable but unreadable")
