#!/usr/bin/env python3
"""
Offline SealedSecret generator -- Python standard library only (3.8+).
Drop-in alternative to `kubeseal --cert cert.pem`, no pip packages needed.

Crypto (same as the sealed-secrets controller):
  - random 32-byte AES-256-GCM session key, zero nonce (key is single-use)
  - session key wrapped with RSA-OAEP (SHA-256), label depends on scope
  - payload = uint16 BE len(rsa_ct) || rsa_ct || aes_gcm_ct (incl. tag), base64

Because the stdlib has no YAML parser, the secret is given like
`kubectl create secret generic`, or as a JSON Secret (kubectl ... -o json):

  python seal_stdlib.py --cert cert.pem --name db --namespace app \
      --from-literal user=admin --from-literal password=hunter2 \
      --from-file tls.crt=./tls.crt  -o sealed.yaml

  kubectl create secret generic db -n app --from-literal=a=b --dry-run=client -o json > s.json
  python seal_stdlib.py --cert cert.pem --secret-json s.json -o sealed.yaml

Image pull secret (type kubernetes.io/dockerconfigjson), like
`kubectl create secret docker-registry`. The token is prompted for (hidden)
unless --docker-password-stdin is given, so it never lands in shell history:

  python seal.py --cert cert.pem --name regcred -n app \
      --docker-server registry.cluster.lan --docker-username robot -o sealed.yaml

  echo "$TOKEN" | python seal.py ... --docker-server ghcr.io \
      --docker-username me --docker-password-stdin

Options: --scope strict|namespace-wide|cluster-wide (default strict),
         --type (default Opaque), --label k=v (template labels), -o FILE (default stdout)

Note: the pure-Python AES is not constant-time. That's irrelevant for a
one-shot encryption on your own workstation, but don't reuse it as a server lib.
"""
import argparse
import base64
import hashlib
import json
import os
import getpass
import re
import struct
import sys

# ---------------------------------------------------------------- AES-256 ---

def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a

def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r

def _make_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if _gmul(x, y) == 1)
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox[x] = s ^ 0x63
    return sbox

SBOX = _make_sbox()
MUL2 = [_gmul(x, 2) for x in range(256)]
MUL3 = [_gmul(x, 3) for x in range(256)]

def aes256_expand(key):
    assert len(key) == 32
    w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - 8], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(15)]

def aes_encrypt_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for rnd in range(1, 15):
        s = [SBOX[b] for b in s]
        # ShiftRows (column-major state: index = col*4 + row)
        s = [s[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]
        if rnd != 14:
            m = []
            for c in range(4):
                a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
                m += [MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3,
                      a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3,
                      a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3],
                      MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]]
            s = m
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)

# ------------------------------------------------------------------- GCM ---

_R = 0xE1 << 120

def _gf128_mul(x, y):
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z

def aes256_gcm_encrypt(key, nonce, plaintext):
    assert len(nonce) == 12
    rk = aes256_expand(key)
    h = int.from_bytes(aes_encrypt_block(rk, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ct = bytearray()
    for i in range(0, len(plaintext), 16):
        ctr = nonce + struct.pack(">I", 2 + i // 16)
        ks = aes_encrypt_block(rk, ctr)
        ct += bytes(a ^ b for a, b in zip(plaintext[i:i + 16], ks))
    # GHASH (no AAD)
    y = 0
    padded = bytes(ct) + b"\x00" * (-len(ct) % 16)
    for i in range(0, len(padded), 16):
        y = _gf128_mul(y ^ int.from_bytes(padded[i:i + 16], "big"), h)
    y = _gf128_mul(y ^ (len(ct) * 8), h)  # len(AAD)=0 || len(C) in bits
    tag = (y ^ int.from_bytes(aes_encrypt_block(rk, j0), "big")).to_bytes(16, "big")
    return bytes(ct) + tag

# --------------------------------------------------------------- RSA-OAEP ---

def _mgf1(seed, length):
    out = b""
    for c in range((length + 31) // 32):
        out += hashlib.sha256(seed + struct.pack(">I", c)).digest()
    return out[:length]

def rsa_oaep_sha256_encrypt(n, e, msg, label):
    k = (n.bit_length() + 7) // 8
    hlen = 32
    if len(msg) > k - 2 * hlen - 2:
        raise ValueError("message too long for RSA key")
    db = hashlib.sha256(label).digest() + b"\x00" * (k - len(msg) - 2 * hlen - 2) + b"\x01" + msg
    seed = os.urandom(hlen)
    masked_db = bytes(a ^ b for a, b in zip(db, _mgf1(seed, k - hlen - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1(masked_db, hlen)))
    em = b"\x00" + masked_seed + masked_db
    return pow(int.from_bytes(em, "big"), e, n).to_bytes(k, "big")

# ------------------------------------------------- minimal DER / PEM read ---

def _der_read(buf, pos):
    tag = buf[pos]
    ln = buf[pos + 1]
    pos += 2
    if ln & 0x80:
        nb = ln & 0x7F
        ln = int.from_bytes(buf[pos:pos + nb], "big")
        pos += nb
    return tag, buf[pos:pos + ln], pos + ln

def _der_children(content):
    pos, out = 0, []
    while pos < len(content):
        tag, val, pos = _der_read(content, pos)
        out.append((tag, val))
    return out

def _rsa_from_spki(spki):
    alg, bitstr = _der_children(spki)[:2]
    _, rsakey, _ = _der_read(bitstr[1], 1)  # skip "unused bits" byte
    (_, n), (_, e) = _der_children(rsakey)[:2]
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")

def load_rsa_public_key(path):
    text = open(path, "r", encoding="ascii").read()
    m = re.search(r"-----BEGIN (CERTIFICATE|PUBLIC KEY)-----(.+?)-----END \1-----", text, re.S)
    if not m:
        raise ValueError("no CERTIFICATE or PUBLIC KEY PEM block found in " + path)
    der = base64.b64decode("".join(m.group(2).split()))
    _, top, _ = _der_read(der, 0)
    if m.group(1) == "PUBLIC KEY":
        return _rsa_from_spki(top)
    tbs = _der_children(top)[0][1]
    fields = _der_children(tbs)
    if fields[0][0] == 0xA0:  # explicit version tag
        fields = fields[1:]
    # serial, sigAlg, issuer, validity, subject, subjectPublicKeyInfo
    return _rsa_from_spki(fields[5][1])

# ------------------------------------------------------------------ main ---

def hybrid_encrypt(n, e, plaintext, label):
    session_key = os.urandom(32)
    rsa_ct = rsa_oaep_sha256_encrypt(n, e, session_key, label)
    return struct.pack(">H", len(rsa_ct)) + rsa_ct + aes256_gcm_encrypt(session_key, b"\x00" * 12, plaintext)

def q(s):
    """Quote a scalar for YAML (JSON strings are valid YAML)."""
    return json.dumps(s)

def kv(arg):
    if "=" not in arg:
        raise argparse.ArgumentTypeError("expected key=value: " + arg)
    return tuple(arg.split("=", 1))

def main():
    ap = argparse.ArgumentParser(description="Seal a Kubernetes Secret offline (stdlib only).")
    ap.add_argument("--cert", required=True, help="controller cert (PEM certificate or public key)")
    ap.add_argument("--scope", default="strict", choices=["strict", "namespace-wide", "cluster-wide"])
    ap.add_argument("--secret-json", help="Secret as JSON (e.g. kubectl ... -o json)")
    ap.add_argument("--name")
    ap.add_argument("-n", "--namespace")
    ap.add_argument("--type", default=None)
    ap.add_argument("--from-literal", type=kv, action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("--from-file", type=kv, action="append", default=[], metavar="KEY=PATH")
    g = ap.add_argument_group("image pull secret (kubernetes.io/dockerconfigjson)")
    g.add_argument("--docker-server", help="registry host, e.g. registry.cluster.lan or ghcr.io")
    g.add_argument("--docker-username", help="registry user (robot/deploy-token name)")
    g.add_argument("--docker-password", help="token (insecure: visible in shell history; prefer prompt/stdin)")
    g.add_argument("--docker-password-stdin", action="store_true", help="read the token from stdin")
    g.add_argument("--docker-email", help="optional email field")
    ap.add_argument("--label", type=kv, action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("-o", "--output", help="output file (default: stdout)")
    a = ap.parse_args()

    labels, annotations, data, stype = {}, {}, {}, "Opaque"
    name, ns = a.name, a.namespace
    if a.secret_json:
        with open(a.secret_json, encoding="utf-8-sig") as f:
            sec = json.load(f)
        meta = sec.get("metadata", {})
        name = name or meta.get("name")
        ns = ns or meta.get("namespace")
        labels.update(meta.get("labels") or {})
        annotations.update(meta.get("annotations") or {})
        stype = sec.get("type", stype)
        data.update({k: base64.b64decode(v) for k, v in (sec.get("data") or {}).items()})
        data.update({k: v.encode() for k, v in (sec.get("stringData") or {}).items()})
    for k, v in a.from_literal:
        data[k] = v.encode()
    for k, p in a.from_file:
        with open(p, "rb") as f:
            data[k] = f.read()
    if a.docker_server:
        if not a.docker_username:
            sys.exit("error: --docker-username is required with --docker-server")
        if a.docker_password_stdin:
            pw = sys.stdin.read().rstrip("\r\n")
        elif a.docker_password is not None:
            pw = a.docker_password
        else:
            pw = getpass.getpass(f"token for {a.docker_username}@{a.docker_server}: ")
        if not pw:
            sys.exit("error: empty registry token")
        entry = {"username": a.docker_username, "password": pw,
                 "auth": base64.b64encode(f"{a.docker_username}:{pw}".encode()).decode()}
        if a.docker_email:
            entry["email"] = a.docker_email
        data[".dockerconfigjson"] = json.dumps({"auths": {a.docker_server: entry}}).encode()
        stype = "kubernetes.io/dockerconfigjson"
    elif a.docker_username or a.docker_password or a.docker_password_stdin:
        sys.exit("error: --docker-* options need --docker-server")
    labels.update(dict(a.label))
    stype = a.type or stype

    if not name:
        sys.exit("error: --name is required")
    if a.scope != "cluster-wide" and not ns:
        sys.exit("error: --namespace is required for scope " + a.scope)
    if not data:
        sys.exit("error: no data given (--from-literal / --from-file / --secret-json / --docker-server)")

    label = {"strict": f"{ns}/{name}", "namespace-wide": ns or "", "cluster-wide": ""}[a.scope].encode()
    n, e = load_rsa_public_key(a.cert)
    if a.scope != "strict":
        annotations[f"sealedsecrets.bitnami.com/{a.scope}"] = "true"

    L = ["apiVersion: bitnami.com/v1alpha1", "kind: SealedSecret", "metadata:", f"  name: {q(name)}"]
    if ns:
        L.append(f"  namespace: {q(ns)}")
    if a.scope != "strict":
        L += ["  annotations:", f"    sealedsecrets.bitnami.com/{a.scope}: \"true\""]
    L += ["spec:", "  encryptedData:"]
    for k in sorted(data):
        L.append(f"    {q(k)}: {base64.b64encode(hybrid_encrypt(n, e, data[k], label)).decode()}")
    L += ["  template:", "    metadata:", f"      name: {q(name)}"]
    if ns:
        L.append(f"      namespace: {q(ns)}")
    for section, d in (("labels", labels), ("annotations", annotations)):
        if d:
            L.append(f"      {section}:")
            L += [f"        {q(k)}: {q(v)}" for k, v in sorted(d.items())]
    L.append(f"    type: {q(stype)}")
    out = "\n".join(L) + "\n"

    if a.output:
        with open(a.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(out)
    else:
        sys.stdout.write(out)

if __name__ == "__main__":
    main()
