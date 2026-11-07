"""Full chain and mempool with atomic SQLite persistence and replay on startup."""
import copy
import json
import sqlite3
import threading
from pathlib import Path

from .consensus import (Invalid, State, apply_tx, block_work, candidate, canonical,
                        chain_id, digest, genesis, MAX_TXS, validate_chain,
                        validate_config, validate_next, hexstr, integer)

MAX_POOL = 1000


class Ledger:
    def __init__(self, config, data_dir):
        self.config = copy.deepcopy(validate_config(config))
        self.lock = threading.RLock()
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(Path(data_dir) / "chain.sqlite3"), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS pending (position INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        # One live node per directory: OS releases this lock after a crash.
        self._lock_file = open(Path(data_dir) / "node.lock", "a+b")
        try:
            if __import__("os").name == "nt":
                import msvcrt
                self._lock_file.seek(0)
                self._lock_file.write(b"0")
                self._lock_file.flush()
                self._lock_file.seek(0)
                msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.db.close()
            self._lock_file.close()
            raise ValueError("Data directory already used by another node") from exc
        stored = self.db.execute("SELECT value FROM metadata WHERE key='chain_id'").fetchone()
        if stored and stored[0] != chain_id(config):
            self.close()
            raise ValueError("Configuration differs from the saved chain; use a new data directory")
        self.chain = [json.loads(row[0]) for row in self.db.execute("SELECT body FROM blocks ORDER BY height")]
        if not self.chain:
            self.chain = [genesis(config)]
        try:
            self.state = validate_chain(self.chain, config)
        except Exception:
            self.close()
            raise
        self.pool = [json.loads(row[0]) for row in self.db.execute("SELECT body FROM pending ORDER BY position")]
        self._rebuild_pool(self.pool)
        self._persist()

    def close(self):
        self.db.close()
        self._lock_file.close()

    def _persist(self, append=False):
        with self.db:
            if not append:
                self.db.execute("DELETE FROM blocks")
            blocks = self.chain[-1:] if append else self.chain
            self.db.executemany("INSERT OR REPLACE INTO blocks VALUES (?, ?)",
                                [(b["height"], canonical(b).decode()) for b in blocks])
            self.db.execute("DELETE FROM pending")
            self.db.executemany("INSERT INTO pending VALUES (?, ?)",
                                [(i, canonical(t).decode()) for i, t in enumerate(self.pool)])
            self.db.execute("INSERT OR REPLACE INTO metadata VALUES ('chain_id', ?)",
                            (chain_id(self.config),))

    def _pending_state(self):
        s = self.state.clone()
        s.mature(len(self.chain))
        for tx in self.pool:
            apply_tx(s, tx, self.config)
        return s

    def _rebuild_pool(self, transactions):
        s = self.state.clone()
        s.mature(len(self.chain))
        valid, seen = [], set()
        # Repeated passes retain dependent transfers after a reorganization.
        todo = list(transactions)[:MAX_POOL]
        while todo and len(valid) < MAX_POOL:
            remaining = []
            for tx in todo:
                txid = digest(tx)
                if txid in seen:
                    continue
                try:
                    apply_tx(s, tx, self.config)
                except (Invalid, ValueError, TypeError, KeyError):
                    remaining.append(tx)
                    continue
                valid.append(copy.deepcopy(tx))
                seen.add(txid)
            if len(remaining) == len(todo):
                break
            todo = remaining
        self.pool = valid

    def status(self):
        with self.lock:
            return {"name": self.config["name"], "symbol": self.config["symbol"],
                    "chain_id": chain_id(self.config), "height": len(self.chain) - 1,
                    "tip": self.chain[-1]["hash"], "work": str((len(self.chain) - 1) * block_work(self.config)),
                    "pending": len(self.pool), "pow_bits": self.config["pow_bits"]}

    def account(self, who):
        hexstr(who)
        with self.lock:
            pending = self._pending_state()
            locked = sum(v for _, a, v in self.state.immature if a == who)
            return {"address": who, "balance": self.state.balances.get(who, 0),
                    "immature": locked, "next_block_available": pending.balances.get(who, 0),
                    "confirmed_nonce": self.state.nonces.get(who, 0),
                    "next_nonce": pending.nonces.get(who, 0) + 1, "units_per_coin": 100_000_000}

    def add_tx(self, tx):
        with self.lock:
            txid = digest(tx)
            if any(digest(t) == txid for t in self.pool):
                return txid
            if len(self.pool) >= MAX_POOL:
                raise Invalid("mempool full")
            s = self._pending_state()
            apply_tx(s, tx, self.config)
            with self.db:
                self.db.execute("INSERT INTO pending VALUES (?, ?)",
                                (len(self.pool), canonical(tx).decode()))
            self.pool.append(copy.deepcopy(tx))
            return txid

    def template(self, miner):
        with self.lock:
            return candidate(self.chain, self.config, miner, self.pool[:MAX_TXS])

    def add_block(self, block):
        with self.lock:
            state = validate_next(block, self.chain, self.state, self.config)
            previous_state, previous_pool = self.state, self.pool
            self.chain.append(copy.deepcopy(block))
            self.state = state
            try:
                self._rebuild_pool(self.pool)
                self._persist(append=True)
            except Exception:
                self.chain.pop()
                self.state, self.pool = previous_state, previous_pool
                raise

    def adopt(self, other):
        with self.lock:
            # Fixed difficulty: strictly more blocks means strictly more work.
            # Ties retain the current tip until one branch gains more work.
            if len(other) <= len(self.chain):
                return False
            state = validate_chain(other, self.config)
            old_txs = [t for b in self.chain[1:] for t in b["transactions"]]
            previous = self.chain, self.state, self.pool
            self.chain, self.state = copy.deepcopy(other), state
            try:
                self._rebuild_pool(self.pool + old_txs[-MAX_POOL:])
                self._persist()
            except Exception:
                self.chain, self.state, self.pool = previous
                raise
            return True

    def blocks(self, start, count):
        integer(start)
        integer(count, 1, 50)
        with self.lock:
            return {"tip": self.chain[-1]["hash"],
                    "blocks": copy.deepcopy(self.chain[start:start + count])}

    def mempool(self):
        with self.lock:
            return copy.deepcopy(self.pool)

    def mempool_details(self):
        with self.lock:
            return [{"txid": digest(tx), "confirmations": 0,
                     "transaction": copy.deepcopy(tx)} for tx in self.pool]

    def transaction(self, txid):
        hexstr(txid)
        with self.lock:
            for b in reversed(self.chain[1:]):
                for tx in b["transactions"]:
                    if digest(tx) == txid:
                        return {"status": "confirmed", "height": b["height"],
                                "confirmations": len(self.chain) - b["height"], "transaction": tx}
            for tx in self.pool:
                if digest(tx) == txid:
                    return {"status": "pending", "confirmations": 0, "transaction": tx}
            return {"status": "unknown", "confirmations": 0}
