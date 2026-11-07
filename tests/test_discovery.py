"""VPN discovery must prove token possession before authenticated RPCs."""
import hmac
import hashlib
import json
import secrets
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock
import time

from powcoin.consensus import chain_id, mine
from powcoin.ledger import Ledger
from powcoin.network import Node, discovery_origin, rpc
from test_consensus import config


TOKEN = "discovery-integration-token-123456"
SEED = "http://10.8.0.1:8844"
CANDIDATE = "http://10.8.0.20:8844"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def proof(nonce, origin, cid):
    msg = b"powcoin-vpn-discovery-v1|" + bytes.fromhex(nonce) + b"|" + origin.encode() + b"|" + cid.encode()
    return hmac.new(TOKEN.encode(), msg, hashlib.sha256).hexdigest()


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cfg = config()
        self.cid = chain_id(self.cfg)
        self.ledger = Ledger(self.cfg, Path(self.temp.name) / "local")
        self.addCleanup(self.ledger.close)

    def node(self, **kwargs):
        node = Node(self.ledger, host="127.0.0.1", port=free_port(), peers=[SEED],
                    token=TOKEN, discover_peer_list=True, **kwargs)
        self.addCleanup(node.server.server_close)
        return node

    def test_peer_list_filtering_and_removal(self):
        valid = ["http://10.8.0.%d:8844" % i for i in range(2, 40) if i != 10]
        bad = ["https://10.8.0.40:8844", "http://172.28.84.2:8844",
               "http://example.com:8844", "http://user@10.8.0.41:8844",
               "http://10.8.0.42:8844/path", "http://10.8.0.43:9999",
               "http://10.8.0.10:8844"]
        self.assertEqual(discovery_origin(valid[0], "10.8.0.10"), valid[0])
        for item in bad:
            self.assertIsNone(discovery_origin(item, "10.8.0.10"))
        node = self.node()
        calls = []
        advertised = [valid + bad + valid]
        def fake_rpc(url, path, body=None, token=None):
            calls.append((url, path, token))
            if url == SEED:
                return dict(self.ledger.status(), peers=advertised[0])
            if path.startswith("/discovery-proof?"):
                nonce = path.split("nonce=")[1]
                return {"chain_id": self.cid, "proof": proof(nonce, url, self.cid)}
            return dict(self.ledger.status(), mining=False) if path == "/status" else []
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertLessEqual(len(node.peers), 32)
        self.assertTrue(all(p == SEED or p in valid for p in node.peers))
        self.assertLessEqual(len({u for u, p, t in calls if p.startswith('/discovery-proof?')}), 31)
        advertised[0] = "malformed"
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertGreater(len(node.peers), 1)
        advertised[0] = []
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertEqual(node.peers, [SEED])

    def test_successful_proof_then_sync(self):
        remote = Ledger(self.cfg, Path(self.temp.name) / "remote")
        self.addCleanup(remote.close)
        from powcoin import wallet
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        address = wallet.address(wallet.public_hex(Ed25519PrivateKey.generate()))
        remote.add_block(mine(remote.template(address), self.cfg))
        node = self.node()
        calls = []
        def fake_rpc(url, path, body=None, token=None):
            calls.append((url, path, token))
            if url == SEED:
                return dict(self.ledger.status(), peers=[CANDIDATE]) if path == "/status" else []
            if path.startswith("/discovery-proof?"):
                nonce = path.split("nonce=")[1]
                self.assertIsNone(token)
                return {"chain_id": self.cid, "proof": proof(nonce, url, self.cid)}
            if path == "/status":
                return dict(remote.status(), mining=False)
            if path.startswith("/blocks?"):
                return remote.blocks(0, 50)
            if path == "/mempool":
                return []
            raise AssertionError(path)
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertEqual(self.ledger.status()["tip"], remote.status()["tip"])
        self.assertTrue(any(u == CANDIDATE and p == "/status" and t == TOKEN for u, p, t in calls))

    def test_fake_listener_never_receives_bearer(self):
        received = []
        class Fake(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"chain_id": self.server.cid, "proof": "0" * 64}).encode())
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        server.cid = self.cid
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        candidate = "http://127.0.0.1:%d" % server.server_port
        node = self.node()
        def fake_rpc(url, path, body=None, token=None):
            if url == SEED:
                return dict(self.ledger.status(), peers=[candidate])
            return rpc(url, path, body, token)
        with patch("powcoin.network.discovery_origin", return_value=candidate), patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertEqual(received, [None])
        self.assertFalse(node.peer_status()[-1]["reachable"])

    def test_invalid_proof_is_rejected(self):
        node = self.node()
        calls = []
        def fake_rpc(url, path, body=None, token=None):
            calls.append((url, path, token))
            if url == SEED:
                return dict(self.ledger.status(), peers=[CANDIDATE])
            return {"chain_id": self.cid, "proof": "f" * 64}
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertFalse(any(u == CANDIDATE and t == TOKEN for u, p, t in calls))
        self.assertFalse(node.peer_status()[-1]["reachable"])

    def test_discovery_proof_endpoint_and_authentication(self):
        node = self.node()
        thread = threading.Thread(target=node.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(node.server.shutdown)
        nonce = secrets.token_hex(16)
        origin = "http://127.0.0.1:%d" % node.server.server_port
        result = rpc(origin, "/discovery-proof?nonce=" + nonce)
        self.assertEqual(result, {"chain_id": self.cid, "proof": proof(nonce, origin, self.cid)})
        from powcoin.consensus import Invalid
        for bad in ("A" * 32, "a" * 31, "a" * 33, "a" * 32 + "&nonce=" + nonce):
            with self.assertRaises(Invalid):
                rpc(origin, "/discovery-proof?nonce=" + bad)
        with self.assertRaises(Invalid):
            rpc(origin, "/status")

    def test_announcement_is_verified_advertised_and_expires(self):
        node = self.node()
        node.server.server_address = ("10.8.0.1", 8844)
        def fake_rpc(url, path, body=None, token=None):
            self.assertEqual(url, CANDIDATE)
            self.assertIsNone(token)
            nonce = path.split("nonce=")[1]
            return {"chain_id": self.cid, "proof": proof(nonce, url, self.cid)}
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            with self.assertRaises(Exception):
                node.register_peer(CANDIDATE, "10.8.0.21")
            self.assertEqual(node.peer_snapshot(), [SEED])
            node.register_peer(CANDIDATE, "10.8.0.20")
        self.assertIn(CANDIDATE, node.peer_snapshot())
        self.assertIn(CANDIDATE, node._verified_peers)
        node.discover({"peers": []})
        self.assertIn(CANDIDATE, node.peer_snapshot())
        with patch("powcoin.network.time.monotonic", return_value=time.monotonic() + 121):
            self.assertEqual(node.peer_snapshot(), [SEED])

    def test_announcement_rejects_invalid_proof(self):
        node = self.node()
        node.server.server_address = ("10.8.0.1", 8844)
        with patch("powcoin.network.rpc", return_value={"chain_id": self.cid,
                                                           "proof": "0" * 64}):
            with self.assertRaises(Exception):
                node.register_peer(CANDIDATE, "10.8.0.20")
        self.assertEqual(node.peer_snapshot(), [SEED])

    def test_new_node_announces_to_seed(self):
        node = self.node()
        node.server.server_address = ("10.8.0.10", 8844)
        calls = []
        def fake_rpc(url, path, body=None, token=None):
            calls.append((url, path, body, token))
            if path == "/status":
                return dict(self.ledger.status(), peers=[])
            if path == "/mempool":
                return []
            if path == "/announce":
                return {"registered": True}
            raise AssertionError(path)
        with patch("powcoin.network.rpc", side_effect=fake_rpc):
            node.sync_once()
        self.assertIn((SEED, "/announce", {"origin": "http://10.8.0.10:8844"}, TOKEN), calls)

    def test_announcement_endpoint_requires_authentication(self):
        node = self.node()
        thread = threading.Thread(target=node.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(node.server.shutdown)
        origin = "http://127.0.0.1:%d" % node.server.server_port
        register = Mock()
        node.register_peer = register
        from powcoin.consensus import Invalid
        with self.assertRaises(Invalid):
            rpc(origin, "/announce", {"origin": CANDIDATE})
        register.assert_not_called()
        self.assertEqual(rpc(origin, "/announce", {"origin": CANDIDATE}, TOKEN),
                         {"registered": True})
        register.assert_called_once_with(CANDIDATE, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
