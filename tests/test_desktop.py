"""Exercise the desktop app's wallet and mining workflow against a real node."""

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import tkinter as tk

from powcoin import wallet
from powcoin.desktop import DemoApp, DemoClient, units
from powcoin.ledger import Ledger
from powcoin.network import Node
from test_consensus import config


class DesktopWorkflowTests(unittest.TestCase):
    def test_wallet_transfer_and_mining(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = config()
            (root / "network.json").write_text(json.dumps(cfg), encoding="utf-8")
            token = "desktop-test-token-long-enough"
            (root / "token").write_text(token, encoding="utf-8")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            ledger = Ledger(cfg, root / "node")
            node = Node(ledger, "127.0.0.1", port, token=token)
            node.start()
            try:
                client = DemoClient(root / "network.json", f"http://127.0.0.1:{port}", root / "token")
                alice_file, bob_file = root / "alice.pem", root / "bob.pem"
                alice_wallet = client.create_wallet(alice_file, "alice-password-123")
                bob_wallet = client.create_wallet(bob_file, "bob-password-123")
                alice, bob = alice_wallet.address, bob_wallet.address
                self.assertEqual((root / "alice-password.txt").read_text(encoding="utf-8").strip(),
                                 "alice-password-123")
                self.assertEqual((root / "alice-address.txt").read_text(encoding="utf-8").strip(), alice)
                self.assertEqual(wallet.bundle_paths(alice_file),
                                 (alice_file, root / "alice-password.txt", root / "alice-address.txt"))
                with self.assertRaises(ValueError):
                    client.open_wallet(alice_file, "wrong-password")
                opened = client.open_wallet(alice_file, "alice-password-123")
                self.assertEqual(opened.address, alice)
                self.assertEqual(client.status()["height"], 0)
                progress = []
                self.assertEqual(client.mine_blocks(alice, 3, threading.Event(),
                                                    lambda kind, value: progress.append((kind, value))), 3)
                self.assertEqual(client.account(alice)["balance"], 50 * 100_000_000)
                with patch("powcoin.desktop.wallet.load", side_effect=AssertionError("Wallet must stay unlocked")):
                    txid = client.send(opened, bob, units("7.25"), units("0.001", allow_zero=True))
                self.assertEqual(client.transaction(txid)["status"], "pending")
                self.assertEqual(client.mine_blocks(alice, 1, threading.Event(),
                                                    lambda kind, value: progress.append((kind, value))), 1)
                self.assertEqual(client.transaction(txid)["status"], "confirmed")
                self.assertEqual(client.account(bob)["balance"], units("7.25"))
                self.assertTrue(any(kind == "mined" for kind, _ in progress))
                stop = threading.Event()
                stop.set()
                self.assertEqual(client.mine_blocks(alice, 1, stop, lambda *_: None), 0)
            finally:
                node.close()

    def test_bundle_never_overwrites_a_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "student-address.txt").write_text("existing address", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                wallet.create_bundle(root / "student.pem", "student-password-123")
            self.assertFalse((root / "student.pem").exists())
            self.assertFalse((root / "student-password.txt").exists())
            self.assertEqual((root / "student-address.txt").read_text(encoding="utf-8"),
                             "existing address")


class DesktopSessionTests(unittest.TestCase):
    """Exercise asynchronous UI state without a window or a real transfer."""

    def setUp(self):
        interpreter = tk.Tcl()
        self.app = DemoApp.__new__(DemoApp)
        app = self.app
        app.root = Mock()
        app.client = Mock(config={"symbol": "PWN"})
        app.sender_wallet = SimpleNamespace(address="a" * 64)
        app.sender_address = app.sender_wallet.address
        app.sender_file = "alice.pem"
        app.last_txid = None
        app.refresh_generation = 0
        app.last_refresh_applied = 0
        app.transfer_pending = False
        app.opening_wallet = False
        app.send_button = Mock()
        app.ask_password = Mock(side_effect=AssertionError("Unexpected password prompt"))
        for name, value in (("recipient", "b" * 64), ("amount", "1"), ("fee", "0.001"),
                            ("notice", ""), ("balance_text", ""), ("network_text", ""),
                            ("tx_text", "")):
            setattr(app, name, tk.StringVar(master=interpreter, value=value))
        self.jobs = []
        app.work = lambda action, success, failure=None: self.jobs.append((action, success, failure))

    def test_transfer_uses_open_wallet_without_password_prompt(self):
        app = self.app
        app.client.send.return_value = "c" * 64
        with patch("powcoin.desktop.messagebox.askyesno", return_value=True):
            app.send()
            app.send()  # A double click must not submit a second payment.
        self.assertEqual(len(self.jobs), 1)
        action, done, _ = self.jobs[0]
        txid = action()
        app.client.send.assert_called_once_with(app.sender_wallet, "b" * 64, units("1"), units("0.001"))
        app.ask_password.assert_not_called()
        done(txid)
        self.assertEqual(app.last_txid, "c" * 64)
        self.assertFalse(app.transfer_pending)

    def test_balance_ignores_old_wallet_response(self):
        app = self.app
        app.refresh()
        old_reply = self.jobs[-1][1]
        app.sender_address = "b" * 64
        app.refresh()
        latest_reply = self.jobs[-1][1]
        status = {"height": 3, "pending": 0}
        app.balance_text.set("Balance: loading...")
        old_reply((status, {"balance": units("50"), "immature": 0}, None))
        self.assertEqual(app.balance_text.get(), "Balance: loading...")
        latest_reply((status, {"balance": units("7.25"), "immature": 0}, None))
        old_reply((status, {"balance": units("50"), "immature": 0}, None))
        self.assertIn("7.25000000 PWN", app.balance_text.get())
        self.assertNotIn("50.00000000", app.balance_text.get())

    def test_unavailable_balance_is_not_displayed_as_old_balance(self):
        app = self.app
        app.balance_text.set("Balance: 50.00000000 PWN")
        app.refresh()
        old_failure = self.jobs[-1][2]
        app.refresh()
        _, latest_reply, latest_failure = self.jobs[-1]
        old_failure()  # A slow failure still clears stale funds while a newer poll is pending.
        self.assertIn("unavailable", app.balance_text.get().lower())
        latest_reply(({"height": 3, "pending": 0}, {"balance": units("7"), "immature": 0}, None))
        old_failure()
        self.assertIn("7.00000000 PWN", app.balance_text.get())
        latest_failure()
        self.assertIn("unavailable", app.balance_text.get().lower())
        self.assertNotIn("7.00000000", app.balance_text.get())
