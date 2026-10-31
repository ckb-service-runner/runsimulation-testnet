#!/usr/bin/env python3
"""runsimulation-testnet: a lightweight job simulator for the CKB Service Runner (CSR) network.

It plays the *consumer* side of CSR on the testnet: it posts small, real CSR job cells (the CSR job
type + job lock of the deployed contracts), lets any registered CSR runner execute them with the
simulation service (service/simsvc.elf), follows what happens on chain, refunds what nobody ran and
reports anything that should not happen. It never runs jobs itself.

Python 3.8+ standard library only. One process per tick (systemd timer); state is one JSON file.

    python3 sim.py init                 create the key and print the address to fund
    python3 sim.py status               balance, budget, open jobs, outcomes
    python3 sim.py deploy-service       publish service/simsvc.elf as a code cell (once)
    python3 sim.py tick [--dry-run]     one round: faucet, follow jobs, refunds, maybe a new job
    python3 sim.py faucet               ask the testnet faucet once for this month
    python3 sim.py selftest             offline checks (crypto, encodings)
"""

import argparse
import configparser
import hashlib
import hmac
import json
import math
import os
import random
import sys
import time
import urllib.error
import urllib.request

VERSION = "0.1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
CKB = 10 ** 8
SECP_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
FEE_RATE = 1100  # shannons per 1,000 bytes, as the CSR runner (node minimum 1,000)

# --------------------------------------------------------------------------------------------
# hashing, secp256k1 (RFC 6979, recoverable, low-S), addresses
# --------------------------------------------------------------------------------------------


def blake2b(data):
    return hashlib.blake2b(data, digest_size=32, person=b"ckb-default-hash").digest()


P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _jadd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1, z1 = a
    x2, y2, z2 = b
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jdouble(a)
    h, r = (u2 - u1) % P, (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    x3 = (r * r - h3 - 2 * u1 * h2) % P
    y3 = (r * (u1 * h2 - x3) - s1 * h3) % P
    return (x3, y3, h * z1 * z2 % P)


def _jdouble(a):
    if a is None:
        return None
    x, y, z = a
    if y == 0:
        return None
    ys = y * y % P
    s = 4 * x * ys % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * ys * ys) % P
    return (x3, y3, 2 * y * z % P)


def _mul(k, pt=G):
    r, a = None, (pt[0], pt[1], 1)
    while k:
        if k & 1:
            r = _jadd(r, a)
        a = _jdouble(a)
        k >>= 1
    if r is None:
        return None
    zi = pow(r[2], P - 2, P)
    return (r[0] * zi * zi % P, r[1] * zi * zi * zi % P)


def pubkey(priv):
    x, y = _mul(priv)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _rfc6979_k(priv, h):
    x, hb = priv.to_bytes(32, "big"), (int.from_bytes(h, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        c = int.from_bytes(v, "big")
        if 1 <= c < N:
            return c
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_recoverable(priv, msg32):
    """65 bytes r ‖ s ‖ recid as CKB's secp256k1_blake160_sighash_all expects."""
    z = int.from_bytes(msg32, "big")
    k = _rfc6979_k(priv, msg32)
    rx, ry = _mul(k)
    r = rx % N
    s = pow(k, N - 2, N) * (z + r * priv) % N
    recid = (ry & 1) | (2 if rx >= N else 0)
    if s > N // 2:
        s, recid = N - s, recid ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recid])


def recover(msg32, sig):
    r, s, recid = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    x = r + (N if recid & 2 else 0)
    alpha = (x * x * x + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)
    y = beta if (beta & 1) == (recid & 1) else P - beta
    rinv = pow(r, N - 2, N)
    z = int.from_bytes(msg32, "big")
    a = _mul(s * rinv % N, (x, y))
    b = _mul((-z * rinv) % N)
    q = _jadd((a[0], a[1], 1), (b[0], b[1], 1))
    zi = pow(q[2], P - 2, P)
    qx, qy = q[0] * zi * zi % P, q[1] * zi * zi * zi % P
    return bytes([2 + (qy & 1)]) + qx.to_bytes(32, "big")


_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frm, to, pad=True):
    acc = bits = 0
    out = []
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if pad and bits:
        out.append((acc << (to - bits)) & ((1 << to) - 1))
    elif not pad and (bits >= frm or (acc << (to - bits)) & ((1 << to) - 1)):
        raise ValueError("invalid padding")
    return out


HASH_TYPES = {"data": 0, "type": 1, "data1": 2, "data2": 4}


def encode_address(script, hrp="ckt"):
    payload = bytes([0]) + h2b(script["code_hash"]) + bytes([HASH_TYPES[script["hash_type"]]]) + h2b(script["args"])
    data = _convertbits(payload, 8, 5)
    chk = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 0x2BC830A3
    return hrp + "1" + "".join(_B32[d] for d in data + [(chk >> 5 * (5 - i)) & 31 for i in range(6)])


def decode_address(addr):
    hrp, _, rest = addr.lower().rpartition("1")
    data = [_B32.index(c) for c in rest]
    const = _polymod(_hrp_expand(hrp) + data)
    payload = bytes(_convertbits(data[:-6], 5, 8, False))
    if payload[0] == 0 and const == 0x2BC830A3:  # full format (bech32m)
        ht = {v: k for k, v in HASH_TYPES.items()}[payload[33]]
        return {"code_hash": b2h(payload[1:33]), "hash_type": ht, "args": b2h(payload[34:])}
    if payload[0] == 1 and const == 1 and payload[1] == 0:  # deprecated short secp256k1 (bech32)
        return {"code_hash": SECP_CODE_HASH, "hash_type": "type", "args": b2h(payload[2:22])}
    raise ValueError("unsupported address format")


def h2b(h):
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def b2h(b):
    return "0x" + b.hex()


def u32(n):
    return n.to_bytes(4, "little")


def u64(n):
    return n.to_bytes(8, "little")


# --------------------------------------------------------------------------------------------
# molecule
# --------------------------------------------------------------------------------------------


def mol_table(fields):
    head = 4 + 4 * len(fields)
    offs, pos = [], head
    for f in fields:
        offs.append(pos)
        pos += len(f)
    return u32(pos) + b"".join(u32(o) for o in offs) + b"".join(fields)


def mol_fixvec(items):
    return u32(len(items)) + b"".join(items)


def mol_bytes(b):
    return u32(len(b)) + b


def mol_dynvec(items):
    return mol_table(items)  # same layout


def mol_table_fields(data, count):
    """Splits a molecule table into its fields (strict: exact field count)."""
    total = int.from_bytes(data[0:4], "little")
    if total != len(data):
        raise ValueError("bad table size")
    if total == 4:
        return []
    first = int.from_bytes(data[4:8], "little")
    n = first // 4 - 1
    if n < count:
        raise ValueError("too few fields")
    offs = [int.from_bytes(data[4 + 4 * i: 8 + 4 * i], "little") for i in range(n)] + [total]
    return [data[offs[i]:offs[i + 1]] for i in range(n)]


def ser_script(s):
    return mol_table([h2b(s["code_hash"]), bytes([HASH_TYPES[s["hash_type"]]]), mol_bytes(h2b(s["args"]))])


def script_hash(s):
    return blake2b(ser_script(s))


def ser_outpoint(op):
    return h2b(op["tx_hash"]) + u32(int(op["index"], 16))


def ser_raw_tx(tx):
    deps = [ser_outpoint(d["out_point"]) + bytes([0 if d["dep_type"] == "code" else 1]) for d in tx["cell_deps"]]
    inputs = [u64(int(i["since"], 16)) + ser_outpoint(i["previous_output"]) for i in tx["inputs"]]
    outputs = []
    for o in tx["outputs"]:
        typ = ser_script(o["type"]) if o.get("type") else b""
        outputs.append(mol_table([u64(int(o["capacity"], 16)), ser_script(o["lock"]), typ]))
    return mol_table([
        u32(int(tx["version"], 16)),
        mol_fixvec(deps),
        mol_fixvec([h2b(h) for h in tx["header_deps"]]),
        mol_fixvec(inputs),
        mol_dynvec(outputs),
        mol_dynvec([mol_bytes(h2b(d)) for d in tx["outputs_data"]]),
    ])


def tx_hash(tx):
    return blake2b(ser_raw_tx(tx))


def ser_tx(tx):
    return mol_table([ser_raw_tx(tx), mol_dynvec([mol_bytes(h2b(w)) for w in tx["witnesses"]])])


def witness_args(lock=None):
    opt = (lambda b: b"" if b is None else mol_bytes(b))
    return mol_table([opt(lock), b"", b""])


def occupied(lock, typ, data_len):
    """Occupied capacity in shannons."""
    n = 8 + 33 + len(h2b(lock["args"])) + data_len
    if typ:
        n += 33 + len(h2b(typ["args"]))
    return n * CKB


# CSR job data (contracts/schemas/csr.mol)
TRIGGERS = {"on_demand": 0, "at_block": 1, "at_epoch": 2, "at_timestamp": 3, "every": 4}


def encode_job(trigger, value, tip, max_fee, max_cycles, payload, expiry_block, refund_lock_hash, runs):
    item = mol_table([]) if trigger == "on_demand" else mol_table([u64(value)])
    return mol_table([
        u32(TRIGGERS[trigger]) + item,
        u64(tip), u64(max_fee), u64(max_cycles), mol_bytes(payload), u64(expiry_block),
        refund_lock_hash, u32(runs),
    ])


def decode_job(data):
    f = mol_table_fields(data, 8)
    return {
        "trigger": int.from_bytes(f[0][:4], "little"),
        "tip": int.from_bytes(f[1], "little"),
        "max_fee": int.from_bytes(f[2], "little"),
        "max_cycles": int.from_bytes(f[3], "little"),
        "payload": f[4][4:],
        "expiry_block": int.from_bytes(f[5], "little"),
        "refund_lock_hash": f[6],
        "runs": int.from_bytes(f[7], "little"),
    }


# simsvc payload
MODES = {"ok": 1, "fail": 2, "crt_release": 3, "crt_cleanup": 4, "crowdcell": 5}


def sim_payload(mode, nonce, assigned=b"\x00" * 32, args=b"", watch=None):
    p = b"CSRS" + b"\x01" + bytes([MODES[mode]]) + nonce + assigned + args
    if watch:
        p = b"CSRW" + b"\x01" + watch + p
    return p


# --------------------------------------------------------------------------------------------
# RPC
# --------------------------------------------------------------------------------------------


class RpcError(Exception):
    pass


class Rpc:
    def __init__(self, url, timeout=30):
        self.url, self.timeout, self.n = url, timeout, 0

    def call(self, method, *params):
        self.n += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, body, {"content-type": "application/json",
                                                      "user-agent": "runsimulation-testnet/" + VERSION})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            res = json.loads(r.read())
        if res.get("error"):
            raise RpcError("%s: %s" % (method, res["error"]))
        return res["result"]

    def tip(self):
        return int(self.call("get_tip_block_number"), 16)

    def cells(self, script, script_type="lock", filt=None, limit=200, mode="exact", max_pages=10):
        key = {"script": script, "script_type": script_type, "script_search_mode": mode, "with_data": True}
        if filt:
            key["filter"] = filt
        out, cursor = [], None
        for _ in range(max_pages):
            r = self.call("get_cells", key, "asc", hex(limit), cursor)
            out += r["objects"]
            if len(r["objects"]) < limit:
                break
            cursor = r["last_cursor"]
        return out

    def transactions(self, script, script_type, frm, to, limit=200):
        key = {"script": script, "script_type": script_type,
               "filter": {"block_range": [hex(frm), hex(to + 1)]}}
        out, cursor = [], None
        for _ in range(50):
            r = self.call("get_transactions", key, "asc", hex(limit), cursor)
            out += r["objects"]
            if len(r["objects"]) < limit:
                break
            cursor = r["last_cursor"]
        return out


# --------------------------------------------------------------------------------------------
# config and state
# --------------------------------------------------------------------------------------------

DEFAULTS = {
    "rpc_url": "https://testnet.ckb.dev/rpc",
    "data_dir": "/var/lib/runsim",
    "deployments": os.path.join(HERE, "deployments", "csr-testnet.json"),
    "service_elf": os.path.join(HERE, "service", "simsvc.elf"),
    "address_prefix": "ckt",
    # money
    "monthly_cap_ckb": "100000",
    "pacing": "on",
    "tip_min_ckb": "1",
    "tip_max_ckb": "3",
    "max_fee_shannons": "100000",
    "max_cycles": "1000000",
    "reserve_ckb": "2000",
    # schedule
    "mean_interval_minutes": "150",
    "tick_minutes": "10",
    "expiry_blocks": "1500",
    "delay_max_blocks": "300",
    "assign_fraction": "0.25",
    "weights": "ok:30,timed:15,every:10,fail:15,crt:20,crowdcell:10",
    # faucet
    "faucet": "auto",
    "faucet_url": "https://faucet.nervos.org/claim_events",
    "faucet_amount_ckb": "100000",
    "faucet_below_ckb": "50000",
    # crowdcell
    "crowdcell_campaign_code_hash": "0x1d9b9e5959c932c0ff6486e03cd69d0e51a6b087dacf80b909c23d713bd2659c",
}


def load_config(path):
    cp = configparser.ConfigParser()
    cp["sim"] = DEFAULTS
    if path and os.path.exists(path):
        cp.read(path)
    c = dict(cp["sim"])
    for k in list(c):
        c[k] = c[k].split("#")[0].strip()
    return c


class State:
    def __init__(self, path):
        self.path = path
        try:
            with open(path) as f:
                self.d = json.load(f)
        except FileNotFoundError:
            self.d = {}
        for k, v in {"jobs": {}, "switches": {}, "pending": {}, "months": {}, "stats": {},
                     "runners_seen": {}, "anomalies": [], "scan_from": None}.items():
            self.d.setdefault(k, v)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.d, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    def month(self, key=None):
        key = key or time.strftime("%Y-%m", time.gmtime())
        return self.d["months"].setdefault(key, {"committed": 0, "tips": 0, "fees": 0, "jobs": 0, "faucet": None})

    def stat(self, name, n=1):
        self.d["stats"][name] = self.d["stats"].get(name, 0) + n


def log(data_dir, event, **kw):
    kw.update({"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event})
    line = json.dumps(kw, sort_keys=True)
    print(line, file=sys.stderr)
    path = os.path.join(data_dir, "events.jsonl")
    try:
        if os.path.exists(path) and os.path.getsize(path) > 2_000_000:
            with open(path) as f:
                keep = f.readlines()[-5000:]
            with open(path, "w") as f:
                f.writelines(keep)
        with open(path, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------------------------
# the simulator
# --------------------------------------------------------------------------------------------


class Sim:
    def __init__(self, cfg, dry_run=False):
        self.cfg, self.dry = cfg, dry_run
        self.dir = cfg["data_dir"]
        os.makedirs(self.dir, exist_ok=True)
        self.rpc = Rpc(cfg["rpc_url"])
        self.state = State(os.path.join(self.dir, "state.json"))
        with open(cfg["deployments"]) as f:
            self.dep = json.load(f)
        self.priv = self._load_key()
        args = blake2b(pubkey(self.priv))[:20]
        self.lock = {"code_hash": SECP_CODE_HASH, "hash_type": "type", "args": b2h(args)}
        self.lock_hash = script_hash(self.lock)
        self.address = encode_address(self.lock, cfg["address_prefix"])
        self.spent = set()  # out points spent by this tick (or pending)
        self.new_cells = []  # change cells created this tick, usable as inputs

    # -- keys ------------------------------------------------------------------------------
    def _load_key(self):
        path = os.path.join(self.dir, "sim.key")
        if not os.path.exists(path):
            while True:
                k = int.from_bytes(os.urandom(32), "big")
                if 1 <= k < N:
                    break
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("%064x\n" % k)
        with open(path) as f:
            return int(f.read().strip(), 16)

    # -- chain helpers -----------------------------------------------------------------------
    def script(self, name, args):
        s = self.dep["scripts"][name]
        return {"code_hash": s["code_hash"], "hash_type": s["hash_type"], "args": args}

    def code_dep(self, name):
        s = self.dep["scripts"][name]
        return {"out_point": {"tx_hash": s["tx_hash"], "index": hex(s["index"])}, "dep_type": "code"}

    def secp_dep(self):
        sd = self.state.d.get("secp_dep")
        if not sd:
            blk = self.rpc.call("get_block_by_number", "0x0")
            sd = {"tx_hash": blk["transactions"][1]["hash"], "index": "0x0"}
            self.state.d["secp_dep"] = sd
        return {"out_point": sd, "dep_type": "dep_group"}

    def service_hash(self):
        return self.state.d.get("service", {}).get("code_hash")

    def job_type(self):
        return self.script("job_type", self.service_hash())

    def job_lock(self):
        return self.script("job_lock", self.dep["registry_type_hash"])

    def free_cells(self):
        cells = self.rpc.cells(self.lock, "lock", {"script_len_range": ["0x0", "0x1"],
                                                    "output_data_len_range": ["0x0", "0x1"]})
        out = []
        for c in cells:
            key = c["out_point"]["tx_hash"] + ":" + c["out_point"]["index"]
            if key not in self.spent:
                out.append({"out_point": c["out_point"], "capacity": int(c["output"]["capacity"], 16)})
        for c in self.new_cells:
            key = c["out_point"]["tx_hash"] + ":" + c["out_point"]["index"]
            if key not in self.spent and all(o["out_point"] != c["out_point"] for o in out):
                out.append(c)
        return out

    def balance(self):
        return sum(c["capacity"] for c in self.free_cells())

    # -- transactions ------------------------------------------------------------------------
    def build(self, outputs, outputs_data, extra_inputs=(), deps=(), own_inputs=()):
        """Funds `outputs` from free plain cells, adds change, signs the sim lock group, returns tx.

        extra_inputs: cells of other locks (a job cell) with their since; own_inputs: sim cells that must be
        spent (a switch). Inputs are the own cells first (one sighash group), then the extra ones. There is
        always at least one own input: the refund path of the job lock needs it, and it pays the fee.
        """
        out_sum = sum(int(o["capacity"], 16) for o in outputs)
        extra_cap = sum(i["capacity"] for i in extra_inputs)
        min_change = 61 * CKB
        fee = 3000
        for _ in range(4):
            chosen = list(own_inputs)
            free = sorted(self.free_cells(), key=lambda c: -c["capacity"])
            for c in free:
                have = extra_cap + sum(x["capacity"] for x in chosen)
                if chosen and have >= out_sum + fee + min_change:
                    break
                chosen.append(c)
            have = extra_cap + sum(x["capacity"] for x in chosen)
            change = have - out_sum - fee
            if not chosen or change < min_change:
                raise RuntimeError("not enough CKB: have %.2f, need %.2f" % (have / CKB, (out_sum + fee + min_change) / CKB))
            tx = {
                "version": "0x0",
                "cell_deps": [self.secp_dep()] + list(deps),
                "header_deps": [],
                "inputs": [{"since": "0x0", "previous_output": c["out_point"]} for c in chosen]
                + [{"since": i["since"], "previous_output": i["out_point"]} for i in extra_inputs],
                "outputs": list(outputs) + [{"capacity": hex(change), "lock": self.lock, "type": None}],
                "outputs_data": list(outputs_data) + ["0x"],
                "witnesses": [],
            }
            self.sign(tx, len(chosen))
            need_fee = -(-(len(ser_tx(tx)) + 4) * FEE_RATE // 1000)
            if need_fee <= fee:
                return tx, chosen, fee
            fee = need_fee
        raise RuntimeError("fee did not converge")

    def sign(self, tx, group_len):
        n_in = len(tx["inputs"])
        zero = witness_args(b"\x00" * 65)
        tx["witnesses"] = [b2h(zero)] + ["0x"] * (n_in - 1)
        h = tx_hash(tx)
        m = h + u64(len(zero)) + zero
        for i in range(1, group_len):
            m += u64(0)
        msg = blake2b(m)
        sig = sign_recoverable(self.priv, msg)
        tx["witnesses"][0] = b2h(witness_args(sig))

    def send(self, tx, inputs, label):
        h = b2h(tx_hash(tx))
        if self.dry:
            r = self.rpc.call("test_tx_pool_accept", tx, "passthrough")
            log(self.dir, "dry_run_ok", what=label, tx=h, cycles=int(r["cycles"], 16), fee=int(r["fee"], 16))
        else:
            sent = self.rpc.call("send_transaction", tx, "passthrough")
            if sent != h:
                raise RuntimeError("node returned another tx hash %s != %s" % (sent, h))
            self.state.d["pending"][h] = {"inputs": [c["out_point"]["tx_hash"] + ":" + c["out_point"]["index"]
                                                     for c in inputs], "label": label, "at": int(time.time())}
            last = len(tx["outputs"]) - 1
            self.state.d["pending"][h]["change"] = {"out_point": {"tx_hash": h, "index": hex(last)},
                                                    "capacity": int(tx["outputs"][last]["capacity"], 16)}
        for c in inputs:
            self.spent.add(c["out_point"]["tx_hash"] + ":" + c["out_point"]["index"])
        if self.dry:
            return h
        # own change (the last output) is usable as an input within this tick
        last = len(tx["outputs"]) - 1
        o = tx["outputs"][last]
        if o["lock"] == self.lock and not o.get("type") and tx["outputs_data"][last] == "0x":
            self.new_cells.append({"out_point": {"tx_hash": h, "index": hex(last)}, "capacity": int(o["capacity"], 16)})
        return h

    def refresh_pending(self):
        for h, p in list(self.state.d["pending"].items()):
            st = None
            try:
                r = self.rpc.call("get_transaction", h)
                st = r["tx_status"]["status"] if r else "unknown"
            except RpcError:
                st = "unknown"
            if st == "committed":
                for s in self.state.d["switches"].values():
                    if s["state"] == "spending" and s["outpoint"] in p["inputs"]:
                        s["state"] = "consumed"
                        s["consumed_block"] = int(r["tx_status"]["block_number"], 16)
            if st == "committed" or st == "rejected" or (st == "unknown" and time.time() - p["at"] > 3600):
                if st != "committed":
                    log(self.dir, "tx_dropped", tx=h, status=st, what=p["label"])
                    self.forget_tx(h)
                del self.state.d["pending"][h]
            else:
                self.spent.update(p["inputs"])
                if p.get("change"):  # unconfirmed change of our own: usable (CKB accepts chained txs)
                    self.new_cells.append(p["change"])

    def forget_tx(self, h):
        """A transaction of ours was dropped: forget the jobs/switches it would have created."""
        for jid, j in list(self.state.d["jobs"].items()):
            if j["outpoint"].startswith(h + ":") and j["state"] == "open" and j.get("runs_done", 0) == 0:
                del self.state.d["jobs"][jid]
        for sid, s in list(self.state.d["switches"].items()):
            if s["outpoint"].startswith(h + ":"):
                del self.state.d["switches"][sid]

    # -- budget ------------------------------------------------------------------------------
    def budget_left(self):
        cap = int(float(self.cfg["monthly_cap_ckb"]) * CKB)
        m = self.state.month()
        t = time.gmtime()
        days = [31, 29 if t.tm_year % 4 == 0 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][t.tm_mon - 1]
        pace = min(1.0, (t.tm_mday - 1 + t.tm_hour / 24.0 + 1) / days)  # spread over the month
        if self.cfg["pacing"] == "off":
            pace = 1.0
        return min(cap - m["committed"], int(cap * pace) - m["committed"])

    def commit(self, shannons):
        if not self.dry:
            self.state.month()["committed"] += shannons

    # -- faucet ------------------------------------------------------------------------------
    def faucet(self, force=False):
        mode = self.cfg["faucet"]
        m = self.state.month()
        if mode == "off" or (m.get("faucet") and not force):
            return
        bal = self.balance()
        if not force and bal >= float(self.cfg["faucet_below_ckb"]) * CKB:
            return
        if mode == "manual" and not force:
            log(self.dir, "funding_needed", address=self.address, balance_ckb=bal / CKB,
                note="send testnet CKB to this address (faucet = manual)")
            m["faucet"] = "asked"
            return
        body = json.dumps({"claim_event": {"address_hash": self.address,
                                           "amount": str(int(float(self.cfg["faucet_amount_ckb"])))}}).encode()
        req = urllib.request.Request(self.cfg["faucet_url"], body, {
            "content-type": "application/json", "accept": "application/json",
            "user-agent": "runsimulation-testnet/" + VERSION})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                res = r.read().decode()[:300]
            m["faucet"] = "claimed"
            log(self.dir, "faucet_claimed", amount_ckb=self.cfg["faucet_amount_ckb"], response=res)
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")[:300]
            m["faucet"] = "refused"
            log(self.dir, "faucet_refused", status=e.code, response=msg, address=self.address,
                note="fund the address by hand, see README")
        except OSError as e:
            log(self.dir, "faucet_error", error=str(e))  # retried next tick

    # -- service code cell -------------------------------------------------------------------
    def deploy_service(self):
        with open(self.cfg["service_elf"], "rb") as f:
            elf = f.read()
        code_hash = b2h(blake2b(elf))
        svc = self.state.d.get("service")
        if svc and svc["code_hash"] == code_hash:
            try:
                live = self.rpc.call("get_live_cell", {"tx_hash": svc["tx_hash"], "index": "0x0"}, False)
            except RpcError:
                live = {"status": "unknown"}
            if live["status"] == "live":
                return svc
        cap = occupied(self.lock, None, len(elf))
        out = [{"capacity": hex(cap), "lock": self.lock, "type": None}]
        tx, chosen, fee = self.build(out, [b2h(elf)])
        h = self.send(tx, chosen, "deploy_service")
        self.commit(cap)
        svc = {"code_hash": code_hash, "tx_hash": h, "index": 0, "outpoint": h + ":0", "capacity_ckb": cap / CKB}
        if not self.dry:
            self.state.d["service"] = svc
        log(self.dir, "service_deployed", **svc)
        return svc

    # -- discovery ---------------------------------------------------------------------------
    def runners(self):
        """Registered runners: the runner lock hash of each registry cell with a valid attestation."""
        reg = self.script("registry", self.dep["config_cell"]["type_args"])
        out = []
        try:
            clock = self.clock_ms()
            for c in self.rpc.cells(reg, "type", limit=100, max_pages=2):
                la = h2b(c["output"]["lock"]["args"])
                f = mol_table_fields(h2b(c["output_data"]), 10)
                expiry = int.from_bytes(f[6], "little")
                if expiry > clock and len(la) in (32, 64):
                    out.append(b2h(la[-32:]))
        except (RpcError, ValueError, KeyError) as e:
            log(self.dir, "runner_scan_failed", error=str(e))
        return sorted(set(out))

    def clock_ms(self):
        cc = self.dep["config_cell"]
        c = self.rpc.call("get_live_cell", {"tx_hash": cc["tx_hash"], "index": hex(cc["index"])}, True)
        return int.from_bytes(h2b(c["cell"]["data"]["content"])[33:41], "little")

    def campaigns(self, tip):
        cache = self.state.d.get("campaign_cache")
        if cache and time.time() - cache["at"] < 3600:
            return cache["items"]
        items = []
        for ht in ("data1", "data2", "type"):
            s = {"code_hash": self.cfg["crowdcell_campaign_code_hash"], "hash_type": ht, "args": "0x"}
            try:
                cells = self.rpc.cells(s, "type", limit=50, mode="prefix", max_pages=1)
            except RpcError:
                continue
            for c in cells:
                d = h2b(c["output_data"])
                if len(d) >= 57:
                    items.append({"outpoint": c["out_point"]["tx_hash"] + ":" + c["out_point"]["index"],
                                  "deadline": int.from_bytes(d[40:48], "little"), "status": d[56]})
            if items:
                break
        self.state.d["campaign_cache"] = {"at": time.time(), "items": items}
        return items

    # -- job creation ------------------------------------------------------------------------
    def create_job(self, kind, mode, trigger, tvalue, runs, payload, expiry, expect, extra=None,
                   outputs_before=(), datas_before=()):
        tip = random.randint(int(float(self.cfg["tip_min_ckb"]) * CKB), int(float(self.cfg["tip_max_ckb"]) * CKB))
        tip -= tip % 10 ** 6  # round to 0.01 CKB
        max_fee = int(self.cfg["max_fee_shannons"])
        data = encode_job(trigger, tvalue, tip, max_fee, int(self.cfg["max_cycles"]), payload, expiry,
                          self.lock_hash, runs)
        lock, typ = self.job_lock(), self.job_type()
        cap = occupied(lock, typ, len(data)) + runs * (tip + max_fee)
        commit = cap + sum(int(o["capacity"], 16) for o in outputs_before)
        if commit > self.budget_left():
            log(self.dir, "skip_budget", kind=kind, need_ckb=commit / CKB, left_ckb=self.budget_left() / CKB)
            return None
        outs = list(outputs_before) + [{"capacity": hex(cap), "lock": lock, "type": typ}]
        datas = list(datas_before) + [b2h(data)]
        reserve = int(float(self.cfg["reserve_ckb"]) * CKB)
        if self.balance() - cap < reserve:
            log(self.dir, "skip_low_balance", kind=kind, balance_ckb=self.balance() / CKB, reserve_ckb=reserve / CKB)
            return None
        tx, chosen, fee = self.build(outs, datas, deps=[self.code_dep("job_type")])
        h = self.send(tx, chosen, "create_" + kind)
        self.commit(commit)
        idx = len(outs) - 1
        jid = h[2:18]
        job = {"id": jid, "kind": kind, "mode": mode, "trigger": trigger, "tvalue": tvalue, "runs": runs,
               "runs_done": 0, "tip": tip, "max_fee": max_fee, "capacity": cap, "expiry": expiry,
               "outpoint": "%s:%s" % (h, hex(idx)), "expect": expect, "state": "open", "created": int(time.time()),
               "settlements": [], "fee": fee}
        if extra:
            job.update(extra)
        if not self.dry:
            self.state.d["jobs"][jid] = job
            m = self.state.month()
            m["jobs"] += 1
            m["fees"] += fee
            self.state.stat("created_" + kind)
        log(self.dir, "job_created", id=jid, kind=kind, mode=mode, trigger=trigger, tvalue=tvalue, runs=runs,
            tip_ckb=tip / CKB, capacity_ckb=cap / CKB, outpoint=job["outpoint"], expiry=expiry,
            assigned=job.get("assigned"))
        return job, h

    def new_job(self, tip, kind=None):
        self.dmax = max(2, int(self.cfg["delay_max_blocks"]))
        weights = []
        for part in self.cfg["weights"].split(","):
            k, _, w = part.partition(":")
            weights.append((k.strip(), float(w)))
        kind = kind or random.choices([k for k, _ in weights], [w for _, w in weights])[0]
        nonce = os.urandom(8)
        win = int(self.cfg["expiry_blocks"])
        assigned = b"\x00" * 32
        extra = {}
        if random.random() < float(self.cfg["assign_fraction"]):
            rs = self.runners()
            if rs:
                pick = random.choice(rs)
                assigned = h2b(pick)
                extra["assigned"] = pick
        if kind == "ok":
            return self.create_job(kind, "ok", "on_demand", 0, 1, sim_payload("ok", nonce, assigned),
                                   tip + win, "settle", extra)
        if kind == "timed":
            at = tip + random.randint(min(20, self.dmax), self.dmax)
            return self.create_job(kind, "ok", "at_block", at, 1, sim_payload("ok", nonce, assigned),
                                   at + win, "settle", extra)
        if kind == "every":
            k, runs = random.randint(2, max(2, self.dmax // 8)), 3
            return self.create_job(kind, "ok", "every", k, runs, sim_payload("ok", nonce, assigned),
                                   tip + k * runs + win, "settle", extra)
        if kind == "fail":
            return self.create_job(kind, "fail", "on_demand", 0, 1, sim_payload("fail", nonce, assigned),
                                   tip + random.randint(min(20, self.dmax), self.dmax), "never", extra)
        if kind == "crowdcell":
            camps = [c for c in self.campaigns(tip)]
            if not camps:
                log(self.dir, "skip_no_campaign")
                return None
            c = random.choice(camps)
            tx_h, idx = c["outpoint"].split(":")
            args = h2b(tx_h) + u32(int(idx, 16))
            extra["campaign"] = c["outpoint"]
            if c["status"] == 0 and tip < c["deadline"] < tip + win:  # close at the campaign's deadline
                return self.create_job(kind, "crowdcell", "at_block", c["deadline"], 1,
                                       sim_payload("crowdcell", nonce, assigned, args), c["deadline"] + win,
                                       "either", extra)
            return self.create_job(kind, "crowdcell", "on_demand", 0, 1,
                                   sim_payload("crowdcell", nonce, assigned, args), tip + win, "either", extra)
        if kind == "crt":
            return self.new_crt(tip, nonce, assigned, extra)
        return None

    def new_crt(self, tip, nonce, assigned, extra):
        """CRT pattern: a switch cell (the condition anchor), a release job at block T whose service only
        succeeds while the switch is live, and a cleanup job that watches the switch (CSR watch convention)
        and runs once it is consumed. Half of the switches are revoked before T: their release job must
        never settle and is refunded; the others are reclaimed after the release, which triggers the
        cleanup job. Three transactions, because one transaction may carry one job of a service only."""
        win = int(self.cfg["expiry_blocks"])
        release_at = tip + random.randint(max(2, self.dmax // 2), self.dmax)
        revoke = random.random() < 0.5
        sw_data = b"CRTSIM01" + nonce
        sw_cap = occupied(self.lock, None, len(sw_data))
        if sw_cap + 1000 * CKB > self.budget_left():
            log(self.dir, "skip_budget", kind="crt", left_ckb=self.budget_left() / CKB)
            return None
        tx, chosen, fee = self.build([{"capacity": hex(sw_cap), "lock": self.lock, "type": None}], [b2h(sw_data)])
        sh = self.send(tx, chosen, "create_switch")
        self.commit(sw_cap)
        sid = sh[2:18]
        sw = {"outpoint": sh + ":0x0", "capacity": sw_cap, "revoke": revoke, "revoke_at": tip + 1,
              "release_at": release_at, "state": "live", "created": int(time.time())}
        if not self.dry:
            self.state.d["switches"][sid] = sw
            self.state.month()["fees"] += fee
        op = h2b(sh) + u32(0)
        rel = self.create_job("crt", "crt_release", "at_block", release_at, 1,
                              sim_payload("crt_release", nonce, assigned, op), release_at + win,
                              "crt", dict(extra, switch=sid, revoke=revoke))
        if rel:
            sw["release_job"] = rel[0]["id"]
        cl = self.create_job("crt_cleanup", "crt_cleanup", "on_demand", 0, 1,
                             sim_payload("crt_cleanup", nonce, assigned, watch=op), release_at + 2 * win,
                             "settle", dict(extra, switch=sid))
        if cl:
            sw["cleanup_job"] = cl[0]["id"]
        return rel

    # -- following jobs ----------------------------------------------------------------------
    def follow(self, tip):
        jobs = {j["outpoint"]: j for j in self.state.d["jobs"].values() if j["state"] in ("open", "refunding")}
        frm = self.state.d["scan_from"]
        if frm is None:
            frm = max(0, tip - 2000)
        if not self.service_hash() or frm > tip:
            self.state.d["scan_from"] = tip + 1 if frm is None else frm
            return
        seen = set()
        txs = []
        for e in self.rpc.transactions(self.job_type(), "type", frm, tip):
            if e["io_type"] == "input" and e["tx_hash"] not in seen:
                seen.add(e["tx_hash"])
                txs.append(e)
        for e in txs:
            r = self.rpc.call("get_transaction", e["tx_hash"])
            tx = r["transaction"]
            block = int(e["block_number"], 16)
            for i, inp in enumerate(tx["inputs"]):
                op = inp["previous_output"]["tx_hash"] + ":" + inp["previous_output"]["index"]
                if op in jobs:
                    self.on_job_consumed(jobs[op], tx, i, block)
        self.state.d["scan_from"] = tip + 1

    def on_job_consumed(self, job, tx, i, block):
        h = tx["hash"]
        own = [k for k, inp in enumerate(tx["inputs"]) if k != i and self.is_own(inp)]
        if own:  # our refund
            job["state"] = "refunded"
            job["end_block"] = block
            outcome = "refunded"
            sw = self.state.d["switches"].get(job.get("switch"), {})
            if job["expect"] == "crt" and sw.get("consumed_block") is not None and not job["settlements"]:
                outcome = "refunded_revoked"
            elif job["expect"] in ("settle", "crt") and not job["settlements"]:
                outcome = "refunded_unserved"
            elif job["settlements"]:
                outcome = "refunded_after_%d_runs" % len(job["settlements"])
            self.state.stat(outcome)
            log(self.dir, "job_refunded", id=job["id"], kind=job["kind"], tx=h, outcome=outcome)
            return
        # a runner's settlement: inputs [runner wallet cell, job, ...], outputs [wallet + tip, job/refund, ...]
        problems = []
        prev = self.rpc.call("get_transaction", tx["inputs"][0]["previous_output"]["tx_hash"])["transaction"]
        pidx = int(tx["inputs"][0]["previous_output"]["index"], 16)
        wallet_in = prev["outputs"][pidx]
        runner = b2h(script_hash(wallet_in["lock"]))
        got = int(tx["outputs"][0]["capacity"], 16) - int(wallet_in["capacity"], 16)
        if tx["outputs"][0]["lock"] != wallet_in["lock"]:
            problems.append("output 0 is not the runner wallet")
        if got < job["tip"]:
            problems.append("tip short: %d < %d" % (got, job["tip"]))
        out_i = tx["outputs"][i] if i < len(tx["outputs"]) else None
        left = job["runs"] - len(job["settlements"]) - 1
        floor = job["capacity"] - job["tip"] - job["max_fee"]
        if out_i is None:
            problems.append("no output at the job index")
        elif left >= 1:
            if out_i.get("type") != self.job_type() or int(out_i["capacity"], 16) < floor:
                problems.append("recreated job wrong")
        else:
            if script_hash(out_i["lock"]) != self.lock_hash or int(out_i["capacity"], 16) < floor:
                problems.append("refund at the job index wrong")
        if job["expect"] == "never":
            problems.append("settled although the service must fail (%s)" % job["mode"])
        if job["expect"] == "crt":
            sw = self.state.d["switches"].get(job.get("switch"), {})
            cb = sw.get("consumed_block")
            if cb is not None and cb + 10 < block:
                problems.append("released %d blocks after the switch was revoked" % (block - cb))
            elif job.get("revoke"):
                self.state.stat("crt_released_before_revoke")
        job["settlements"].append({"tx": h, "block": block, "runner": runner, "tip": got})
        rs = self.state.d["runners_seen"].setdefault(runner, {"runs": 0, "tips": 0, "assigned_ok": 0})
        rs["runs"] += 1
        rs["tips"] += got
        if not self.dry:
            self.state.month()["tips"] += got
        assigned = job.get("assigned")
        if assigned:
            self.state.stat("assigned_served_by_target" if assigned == runner else "assigned_served_by_other")
            if assigned == runner:
                rs["assigned_ok"] += 1
        if job["trigger"] == "at_block" and block < job["tvalue"]:
            problems.append("ran before its trigger block")
        self.state.stat("settled_" + job["kind"])
        if left >= 1 and out_i is not None:
            job["outpoint"] = "%s:%s" % (h, hex(i))
            job["capacity"] = int(out_i["capacity"], 16)
        else:
            job["state"] = "settled"
            job["end_block"] = block
        for p in problems:
            self.anomaly(job, p, h)
        log(self.dir, "job_settled", id=job["id"], kind=job["kind"], tx=h, runner=runner, tip_ckb=got / CKB,
            runs_left=max(left, 0), problems=problems)

    def is_own(self, inp):
        op = inp["previous_output"]
        prev = self.rpc.call("get_transaction", op["tx_hash"])["transaction"]
        return prev["outputs"][int(op["index"], 16)]["lock"] == self.lock

    def anomaly(self, job, text, tx):
        a = {"t": int(time.time()), "job": job["id"], "kind": job["kind"], "problem": text, "tx": tx}
        self.state.d["anomalies"] = (self.state.d["anomalies"] + [a])[-200:]
        self.state.stat("anomalies")
        log(self.dir, "ANOMALY", **a)

    # -- refunds and switches ----------------------------------------------------------------
    def refunds(self, tip):
        for j in list(self.state.d["jobs"].values()):
            if j["state"] != "open" or tip < j["expiry"]:
                continue
            tx_h, idx = j["outpoint"].split(":")
            try:
                live = self.rpc.call("get_live_cell", {"tx_hash": tx_h, "index": idx}, False)
            except RpcError:
                continue
            if live["status"] != "live":
                continue  # consumed: follow() will see it
            cap = int(live["cell"]["output"]["capacity"], 16)
            job_in = {"out_point": {"tx_hash": tx_h, "index": idx}, "capacity": cap, "since": hex(j["expiry"])}
            try:
                tx, chosen, fee = self.build([], [], extra_inputs=[job_in],
                                             deps=[self.code_dep("job_lock"), self.code_dep("job_type")])
                self.send(tx, chosen + [job_in], "refund_" + j["id"])
                if not self.dry:
                    j["state"] = "refunding"
                    self.state.month()["fees"] += fee
            except (RpcError, RuntimeError) as e:
                log(self.dir, "refund_failed", id=j["id"], error=str(e))
        for j in self.state.d["jobs"].values():  # a refund that was dropped: try again
            if j["state"] == "refunding" and not any(("refund_" + j["id"]) == p["label"]
                                                     for p in self.state.d["pending"].values()):
                tx_h, idx = j["outpoint"].split(":")
                try:
                    live = self.rpc.call("get_live_cell", {"tx_hash": tx_h, "index": idx}, False)
                    if live["status"] == "live":
                        j["state"] = "open"
                except RpcError:
                    pass

    def switches(self, tip):
        jobs = self.state.d["jobs"]
        for sid, s in self.state.d["switches"].items():
            if s["state"] != "live":
                continue
            rel = jobs.get(s.get("release_job"), {})
            act = None
            if s["revoke"] and tip >= s["revoke_at"]:
                act = "revoke"
            elif not s["revoke"] and rel.get("state") in ("settled", "refunded", None):
                act = "reclaim"
            if not act:
                continue
            tx_h, idx = s["outpoint"].split(":")
            cell = {"out_point": {"tx_hash": tx_h, "index": idx}, "capacity": s["capacity"]}
            try:
                tx, chosen, fee = self.build([], [], own_inputs=[cell])
                self.send(tx, chosen, act + "_switch")
                if not self.dry:
                    s["state"] = "spending"
                    s["action"] = act
                log(self.dir, "switch_" + act, switch=sid, outpoint=s["outpoint"])
            except (RpcError, RuntimeError) as e:
                log(self.dir, "switch_failed", switch=sid, error=str(e))
        for s in self.state.d["switches"].values():
            if s["state"] == "spending" and not any(p["label"].endswith("_switch") and s["outpoint"] in p["inputs"]
                                                    for p in self.state.d["pending"].values()):
                tx_h, idx = s["outpoint"].split(":")
                try:
                    live = self.rpc.call("get_live_cell", {"tx_hash": tx_h, "index": idx}, False)
                    s["state"] = "live" if live["status"] == "live" else "consumed"
                except RpcError:
                    pass

    def prune(self):
        cutoff = time.time() - 30 * 86400
        for k in [k for k, j in self.state.d["jobs"].items() if j["state"] in ("settled", "refunded")
                  and j["created"] < cutoff]:
            del self.state.d["jobs"][k]
        for k in [k for k, s in self.state.d["switches"].items() if s["state"] == "consumed"
                  and s.get("created", 0) < cutoff]:
            del self.state.d["switches"][k]
        months = sorted(self.state.d["months"])
        for k in months[:-13]:
            del self.state.d["months"][k]

    # -- one tick ----------------------------------------------------------------------------
    def tick(self, create=None):
        tip = self.rpc.tip()
        self.refresh_pending()
        if not self.dry:
            self.faucet()
        if not self.service_hash():
            log(self.dir, "no_service", note="run `sim.py deploy-service` first")
            self.state.save()
            return
        self.follow(tip)
        self.refunds(tip)
        self.switches(tip)
        p = 1 - math.exp(-float(self.cfg["tick_minutes"]) / float(self.cfg["mean_interval_minutes"]))
        if create or self.dry or random.random() < p:
            try:
                self.new_job(tip, create)
            except (RpcError, RuntimeError) as e:
                log(self.dir, "create_failed", error=str(e))
        self.prune()
        if not self.dry:
            self.state.save()

    def status(self):
        tip = self.rpc.tip()
        bal = self.balance()
        m = self.state.month()
        jobs = self.state.d["jobs"].values()
        by = {}
        for j in jobs:
            by[j["state"]] = by.get(j["state"], 0) + 1
        return {
            "version": VERSION, "address": self.address, "lock_hash": b2h(self.lock_hash), "tip": tip,
            "balance_ckb": bal / CKB, "service": self.state.d.get("service"),
            "month": {k: (v / CKB if k in ("committed", "tips", "fees") else v) for k, v in m.items()},
            "budget_left_now_ckb": self.budget_left() / CKB, "jobs_by_state": by,
            "stats": self.state.d["stats"], "runners_seen": {k: dict(v, tips=v["tips"] / CKB)
                                                             for k, v in self.state.d["runners_seen"].items()},
            "anomalies": self.state.d["anomalies"][-10:], "pending_txs": len(self.state.d["pending"]),
        }


# --------------------------------------------------------------------------------------------
# self test (offline)
# --------------------------------------------------------------------------------------------


def selftest():
    # secp256k1: known public key of private key 1 and 3; sign/recover round trip
    assert pubkey(1).hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    for k in (1, 3, 0xC0FFEE, N - 5):
        m = blake2b(b"msg%d" % k)
        s = sign_recoverable(k, m)
        assert int.from_bytes(s[32:64], "big") <= N // 2
        assert recover(m, s) == pubkey(k), "recover"
    # blake2b-ckb of empty input (CKB's well-known value)
    assert blake2b(b"").hex() == "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e"
    # address round trip; the well-known testnet example address
    lock = {"code_hash": SECP_CODE_HASH, "hash_type": "type", "args": "0xb39bbc0b3673c7d36450bc14cfcdad2d559c6c64"}
    a = encode_address(lock)
    assert a == "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdnnw7qkdnnclfkg59uzn8umtfd2kwxceqgutnjd", a
    assert decode_address(a) == lock
    assert decode_address("ckt1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jq5t63cs") == lock
    # job data round trip
    d = encode_job("at_block", 1234, 5 * CKB, 100000, 5000000, b"\x01\x02", 9999, b"\xaa" * 32, 1)
    j = decode_job(d)
    assert (j["trigger"], j["tip"], j["payload"], j["expiry_block"], j["runs"]) == (1, 5 * CKB, b"\x01\x02", 9999, 1)
    assert encode_job("on_demand", 0, 1, 2, 3, b"", 4, b"\x00" * 32, 1)[36:44] == u32(0) + u32(4)
    p = sim_payload("crt_cleanup", b"n" * 8, watch=b"\x11" * 36)
    assert p[:5] == b"CSRW\x01" and p[41:45] == b"CSRS" and len(p) == 41 + 46
    print("selftest ok")


# --------------------------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="CSR testnet job simulator")
    ap.add_argument("--config", default=os.environ.get("RUNSIM_CONFIG", "/etc/runsim/runsim.ini"))
    ap.add_argument("cmd", choices=["init", "status", "deploy-service", "tick", "faucet", "selftest", "address"])
    ap.add_argument("--dry-run", action="store_true", help="check transactions with test_tx_pool_accept, save nothing")
    ap.add_argument("--create", choices=["ok", "timed", "every", "fail", "crt", "crowdcell"],
                    help="tick: create a job of this kind now (manual test)")
    a = ap.parse_args()
    if a.cmd == "selftest":
        selftest()
        return
    cfg = load_config(a.config)
    sim = Sim(cfg, a.dry_run)
    if a.cmd in ("init", "address"):
        print(json.dumps({"address": sim.address, "lock_hash": b2h(sim.lock_hash), "data_dir": sim.dir}, indent=1))
        sim.state.save()
    elif a.cmd == "status":
        print(json.dumps(sim.status(), indent=1, sort_keys=True))
    elif a.cmd == "deploy-service":
        sim.refresh_pending()
        svc = sim.deploy_service()
        if not a.dry_run:
            sim.state.save()
        print(json.dumps(svc, indent=1))
    elif a.cmd == "faucet":
        sim.faucet(force=True)
        sim.state.save()
    elif a.cmd == "tick":
        lockf = os.path.join(sim.dir, "tick.lock")
        try:
            fd = os.open(lockf, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            if time.time() - os.path.getmtime(lockf) < 1800:
                return
            os.remove(lockf)
            fd = os.open(lockf, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            sim.tick(a.create)
        finally:
            os.close(fd)
            os.remove(lockf)


if __name__ == "__main__":
    main()
