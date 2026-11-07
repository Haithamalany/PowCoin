import copy
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from powcoin import wallet
from powcoin.consensus import (COIN, Invalid, address, block_hash, candidate, digest,
                               genesis, mine, subsidy, target, validate_chain, merkle_root)
from powcoin.ledger import Ledger


def config(**changes):
    c = {"version": 1, "name": "Test Coin", "symbol": "TST", "network": "test-network",
         "pow_bits": 8, "reward": 50 * COIN, "halving_interval": 10,
         "maturity": 2, "genesis_time": 1700000000}
    c.update(changes)
    return c


class ConsensusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = config()
        self.a, self.b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.alice, self.bob = [address(wallet.public_hex(k)) for k in (self.a, self.b)]
        self.ledger = self.new_ledger("main")

    def new_ledger(self, name, conf=None):
        ledger = Ledger(conf or self.config, Path(self.temp.name) / name)
        self.addCleanup(ledger.close)
        return ledger

    def mine(self, ledger=None, who=None):
        ledger = ledger or self.ledger
        block = mine(ledger.template(who or self.alice), ledger.config)
        ledger.add_block(block)
        return block

    def fund(self):
        for _ in range(3):
            self.mine()

    def tx(self, amount=COIN, fee=1000, nonce=1):
        return wallet.sign(self.a, self.config, self.bob, amount, fee, nonce)

    def test_transfer_fees_supply_and_confirmations(self):
        self.fund()
        tx = self.tx(7 * COIN)
        txid = self.ledger.add_tx(tx)
        b = self.mine(who=self.bob)
        self.assertEqual(b["reward"], 50 * COIN + 1000)
        self.assertEqual(self.ledger.account(self.bob)["balance"], 7 * COIN)
        self.assertEqual(self.ledger.transaction(txid)["confirmations"], 1)
        s = self.ledger.state
        self.assertEqual(sum(s.balances.values()) + sum(v for _, _, v in s.immature), 200 * COIN)
        self.assertEqual(self.ledger.mempool(), [])

    def test_immature_rewards_cannot_be_spent_early(self):
        self.mine()
        with self.assertRaisesRegex(Invalid, "insufficient"):
            self.ledger.add_tx(self.tx())
        self.mine()
        self.ledger.add_tx(self.tx())  # Reward at height 1 becomes spendable in block 3.
        self.mine()
        self.assertEqual(self.ledger.account(self.bob)["balance"], COIN)

    def test_invalid_signature_wrong_key_and_mutation(self):
        self.fund()
        for field, value in (("amount", 2 * COIN), ("sender", self.bob),
                             ("signature", "0" * 128), ("recipient", self.alice)):
            with self.subTest(field=field):
                tx = self.tx()
                tx[field] = value
                with self.assertRaises(Invalid):
                    self.ledger.add_tx(tx)

    def test_double_spend_replay_and_pending_reservation(self):
        self.fund()
        tx = self.tx(80 * COIN)
        self.ledger.add_tx(tx)
        with self.assertRaises(Invalid):
            self.ledger.add_tx(self.tx(80 * COIN, nonce=2))
        with self.assertRaises(Invalid):
            self.ledger.add_tx(self.tx(2 * COIN))
        self.mine()
        with self.assertRaises(Invalid):
            self.ledger.add_tx(tx)

    def test_cross_network_replay_rejected(self):
        self.fund()
        tx = wallet.sign(self.a, config(network="another-network"), self.bob, COIN, 0, 1)
        with self.assertRaisesRegex(Invalid, "network"):
            self.ledger.add_tx(tx)

    def test_malformed_values_rejected(self):
        self.fund()
        for field, value in (("amount", True), ("amount", 1.5), ("amount", -1),
                             ("amount", 0), ("nonce", True), ("fee", -1),
                             ("recipient", "x" * 64), ("extra", "field")):
            tx = self.tx()
            tx[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(Invalid):
                self.ledger.add_tx(tx)

    def test_bad_pow_hash_merkle_and_parent_rejected(self):
        b = mine(self.ledger.template(self.alice), self.config)
        for field, value in (("previous", "a" * 64), ("hash", "a" * 64),
                             ("merkle", "b" * 64), ("height", 3), ("version", True)):
            bad = copy.deepcopy(b)
            bad[field] = value
            with self.subTest(field=field), self.assertRaises(Invalid):
                self.ledger.add_block(bad)
        bad = self.ledger.template(self.alice)
        while int(block_hash(bad), 16) <= target(self.config):
            bad["nonce"] += 1
        bad["hash"] = block_hash(bad)
        with self.assertRaisesRegex(Invalid, "proof of work"):
            self.ledger.add_block(bad)

    def test_inflation_rejected_even_with_valid_pow(self):
        b = self.ledger.template(self.alice)
        b["reward"] += COIN
        with self.assertRaisesRegex(Invalid, "reward"):
            self.ledger.add_block(mine(b, self.config))

    def test_invalid_transaction_in_valid_pow_block(self):
        b = self.ledger.template(self.alice)
        b["transactions"] = [self.tx()]
        b["merkle"] = merkle_root(b["transactions"])
        b["reward"] += 1000
        with self.assertRaisesRegex(Invalid, "insufficient"):
            self.ledger.add_block(mine(b, self.config))

    def test_halving(self):
        self.assertEqual(subsidy(self.config, 10), 50 * COIN)
        self.assertEqual(subsidy(self.config, 11), 25 * COIN)
        self.assertEqual(subsidy(self.config, 10000), 0)

    def test_more_work_reorg_restores_orphaned_transfer(self):
        self.fund()
        branch = self.new_ledger("branch")
        branch.adopt(self.ledger.chain)
        tx = self.tx()
        txid = self.ledger.add_tx(tx)
        self.mine()
        self.mine(branch, self.bob)
        self.assertFalse(self.ledger.adopt(branch.chain))  # Equal work retains local branch.
        self.mine(branch, self.bob)
        self.assertTrue(self.ledger.adopt(branch.chain))
        self.assertEqual(self.ledger.account(self.bob)["balance"], 0)
        self.assertEqual(self.ledger.transaction(txid)["status"], "pending")
        self.mine()
        self.assertEqual(self.ledger.transaction(txid)["status"], "confirmed")

    def test_invalid_longer_chain_cannot_replace_valid_chain(self):
        self.mine()
        chain = copy.deepcopy(self.ledger.chain)
        block = candidate(chain, self.config, self.bob, [])
        block["reward"] *= 2
        chain.append(mine(block, self.config))
        before = self.ledger.status()
        with self.assertRaises(Invalid):
            self.ledger.adopt(chain)
        self.assertEqual(self.ledger.status(), before)

    def test_timestamp_and_genesis_rules(self):
        b = self.ledger.template(self.alice)
        b["timestamp"] += 1000
        with self.assertRaisesRegex(Invalid, "future"):
            self.ledger.add_block(mine(b, self.config))
        g = genesis(self.config)
        g["version"] = True
        with self.assertRaisesRegex(Invalid, "genesis"):
            validate_chain([g], self.config)

    def test_directory_lock(self):
        with self.assertRaisesRegex(ValueError, "already used"):
            Ledger(self.config, Path(self.temp.name) / "main")

    def test_database_failure_does_not_advance_memory(self):
        before = self.ledger.status()
        with patch.object(self.ledger, "_persist", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.mine()
        self.assertEqual(self.ledger.status(), before)
        self.assertEqual(self.ledger.state.balances, {})

    def test_startup_rejects_different_configuration_and_corrupted_blocks(self):
        self.mine()
        self.ledger.close()
        with self.assertRaisesRegex(ValueError, "Configuration differs"):
            Ledger(config(network="wrong"), Path(self.temp.name) / "main")
        import sqlite3
        import json
        from contextlib import closing
        with closing(sqlite3.connect(Path(self.temp.name) / "main" / "chain.sqlite3")) as db, db:
            bad = copy.deepcopy(self.ledger.chain[1])
            bad["reward"] *= 2
            db.execute("UPDATE blocks SET body=? WHERE height=1", (json.dumps(bad),))
        with self.assertRaises(Invalid):
            Ledger(self.config, Path(self.temp.name) / "main")

    def test_encrypted_wallet_roundtrip_and_no_overwrite(self):
        path = Path(self.temp.name) / "wallet.pem"
        who = wallet.create(path, "test-password-123")
        key = wallet.load(path, "test-password-123")
        self.assertEqual(who, address(wallet.public_hex(key)))
        self.assertIn(b"ENCRYPTED PRIVATE KEY", path.read_bytes())
        with self.assertRaises(ValueError):
            wallet.load(path, "wrong-password")
        with self.assertRaises(FileExistsError):
            wallet.create(path, "test-password-123")


if __name__ == "__main__":
    unittest.main()
