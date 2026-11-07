"""Deterministic consensus rules; no networking, storage or private keys."""
import copy
import hashlib
import json
import re
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

COIN = 100_000_000
MAX_INT = 2**63 - 1
MAX_TXS = 100
MAX_BLOCK_BYTES = 128_000
ZERO = "0" * 64


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def integer(value, low=0, high=MAX_INT):
    require(type(value) is int and low <= value <= high, "invalid integer")
    return value


def shape(obj, keys):
    require(type(obj) is dict and set(obj) == set(keys.split()), "unexpected fields")


def hexstr(value, length=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None,
            "invalid lowercase hexadecimal value")
    return value


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def validate_config(c):
    shape(c, "version name symbol network pow_bits reward halving_interval maturity genesis_time")
    integer(c["version"], 1, 1)
    for key, length in (("name", 40), ("symbol", 8), ("network", 80)):
        require(type(c[key]) is str and 1 <= len(c[key]) <= length
                and re.fullmatch(r"[A-Za-z0-9 _.-]+", c[key]), "invalid " + key)
    integer(c["pow_bits"], 8, 28)
    integer(c["reward"], 1, 100_000 * COIN)
    integer(c["halving_interval"], 1, 10_000_000)
    integer(c["maturity"], 1, 1000)
    integer(c["genesis_time"], 1)
    return c


def chain_id(config):
    return digest(validate_config(config))


def target(config):
    return (1 << (256 - config["pow_bits"])) - 1


def block_work(config):
    return (1 << 256) // (target(config) + 1)


def subsidy(config, height):
    return config["reward"] >> min(64, (height - 1) // config["halving_interval"])


def address(public_hex):
    hexstr(public_hex)
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()


TX_KEYS = "chain sender public_key recipient amount fee nonce signature"


def unsigned(tx):
    return {k: v for k, v in tx.items() if k != "signature"}


def verify_tx(tx, config):
    shape(tx, TX_KEYS)
    require(tx["chain"] == chain_id(config), "wrong network")
    for key in ("sender", "recipient", "public_key"):
        hexstr(tx[key])
    hexstr(tx["signature"], 128)
    integer(tx["amount"], 1)
    integer(tx["fee"])
    integer(tx["nonce"], 1)
    require(tx["amount"] + tx["fee"] <= MAX_INT, "amount overflow")
    require(address(tx["public_key"]) == tx["sender"], "sender/key mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx["public_key"])).verify(
            bytes.fromhex(tx["signature"]), canonical(unsigned(tx)))
    except (InvalidSignature, ValueError) as exc:
        raise Invalid("invalid signature") from exc


def merkle_root(txs):
    leaves = [bytes.fromhex(digest(t)) for t in txs]
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [hashlib.sha256(leaves[i] + leaves[i + 1]).digest()
                  for i in range(0, len(leaves), 2)]
    return leaves[0].hex()


BLOCK_KEYS = "version chain height previous timestamp nonce miner reward merkle transactions hash"


def header(block):
    return {k: v for k, v in block.items() if k not in ("hash", "transactions")}


def block_hash(block):
    return digest(header(block))


def genesis(config):
    return {"version": 1, "chain": chain_id(config), "height": 0,
            "hash": digest({"genesis": config})}


@dataclass
class State:
    balances: dict = field(default_factory=dict)
    nonces: dict = field(default_factory=dict)
    # (unlock height, mining address, reward including fees)
    immature: list = field(default_factory=list)

    def clone(self):
        return copy.deepcopy(self)

    def mature(self, height):
        waiting = []
        for unlock, who, amount in self.immature:
            if unlock <= height:
                self.balances[who] = self.balances.get(who, 0) + amount
            else:
                waiting.append((unlock, who, amount))
        self.immature = waiting


def apply_tx(state, tx, config):
    verify_tx(tx, config)
    sender, recipient = tx["sender"], tx["recipient"]
    require(tx["nonce"] == state.nonces.get(sender, 0) + 1, "wrong nonce or replay")
    cost = tx["amount"] + tx["fee"]
    require(state.balances.get(sender, 0) >= cost, "insufficient spendable balance")
    state.balances[sender] = state.balances.get(sender, 0) - cost
    state.balances[recipient] = state.balances.get(recipient, 0) + tx["amount"]
    state.nonces[sender] = tx["nonce"]


def validate_next(block, chain, state, config, now=None):
    shape(block, BLOCK_KEYS)
    require(len(canonical(block)) <= MAX_BLOCK_BYTES, "block too large")
    integer(block["version"], 1, 1)
    require(block["chain"] == chain_id(config), "wrong network")
    integer(block["height"], 1)
    require(block["height"] == len(chain), "wrong height")
    require(block["previous"] == chain[-1]["hash"], "wrong parent")
    integer(block["timestamp"], config["genesis_time"])
    previous_time = chain[-1].get("timestamp", config["genesis_time"])
    require(block["timestamp"] >= previous_time, "timestamp moved backwards")
    require(block["timestamp"] <= (time.time() if now is None else now) + 120,
            "timestamp too far in future")
    integer(block["nonce"])
    integer(block["reward"])
    hexstr(block["miner"])
    hexstr(block["merkle"])
    hexstr(block["hash"])
    require(type(block["transactions"]) is list and len(block["transactions"]) <= MAX_TXS,
            "too many transactions")
    require(block["merkle"] == merkle_root(block["transactions"]), "wrong merkle root")
    require(block["hash"] == block_hash(block), "wrong block hash")
    require(int(block["hash"], 16) <= target(config), "insufficient proof of work")
    result = state.clone()
    result.mature(block["height"])
    fees = 0
    for tx in block["transactions"]:
        apply_tx(result, tx, config)
        fees += tx["fee"]
    require(block["reward"] == subsidy(config, block["height"]) + fees,
            "incorrect mining reward")
    result.immature.append((block["height"] + config["maturity"],
                            block["miner"], block["reward"]))
    return result


def validate_chain(chain, config, now=None):
    require(type(chain) is list and len(chain) >= 1, "empty chain")
    # Canonical byte comparison also rejects booleans disguised as integers.
    require(canonical(chain[0]) == canonical(genesis(config)), "wrong genesis")
    state = State()
    prefix = [chain[0]]
    for block in chain[1:]:
        state = validate_next(block, prefix, state, config, now)
        prefix.append(block)
    return state


def candidate(chain, config, miner, txs):
    hexstr(miner)
    height = len(chain)
    b = {"version": 1, "chain": chain_id(config), "height": height,
         "previous": chain[-1]["hash"],
         "timestamp": max(int(time.time()), chain[-1].get("timestamp", config["genesis_time"])),
         "nonce": 0, "miner": miner,
         "reward": subsidy(config, height) + sum(t["fee"] for t in txs),
         "merkle": merkle_root(txs), "transactions": copy.deepcopy(txs), "hash": ZERO}
    return b


def mine(block, config, cancelled=lambda: False, progress=None):
    """Hash only the committed header; cancel periodically when the tip changes."""
    h = header(block)
    limit = target(config)
    for nonce in range(MAX_INT):
        if nonce % 2048 == 0 and cancelled():
            return None
        h["nonce"] = nonce
        hashed = digest(h)
        if progress and nonce % 256 == 255:
            progress(nonce + 1)
        if int(hashed, 16) <= limit:
            if progress:
                progress(nonce + 1)
            block["nonce"], block["hash"] = nonce, hashed
            return block
    raise Invalid("nonce space exhausted")
