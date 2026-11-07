"""Real subprocess integration: HTTP, wallet CLI, mining, sync and restart."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from powcoin import wallet
from powcoin.consensus import COIN, Invalid, mine
from powcoin.network import rpc
from test_consensus import config


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def eventually(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except Exception as exc:
            last = exc
        time.sleep(0.15)
    raise AssertionError("Timed out waiting for network convergence: %s" % last)


class NetworkTests(unittest.TestCase):
    def test_three_process_network_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cfg = config(pow_bits=10, halving_interval=210000)
            (root / "network.json").write_text(json.dumps(cfg))
            passwd = "integration-password-123"
            alice = wallet.create(root / "alice.pem", passwd)
            bob = wallet.create(root / "bob.pem", passwd)
            ports = [free_port() for _ in range(3)]
            urls = ["http://127.0.0.1:%d" % p for p in ports]
            token = "integration-token-with-at-least-24-characters"
            env = dict(os.environ, POWCOIN_TOKEN=token, POWCOIN_WALLET_PASSWORD=passwd)
            processes, logs = {}, []

            def call(i, path, body=None):
                return rpc(urls[i], path, body, token)

            def start(i, mining=False):
                log = open(root / ("node%d-%d.log" % (i, len(logs))), "w+")
                logs.append(log)
                args = [sys.executable, "-m", "powcoin", "node", "--config", str(root / "network.json"),
                        "--data", str(root / ("node%d" % i)), "--port", str(ports[i])]
                for j in range(3):
                    if j != i:
                        args += ["--peer", urls[j]]
                if mining:
                    args += ["--mine-to", [alice, bob, bob][i]]
                processes[i] = subprocess.Popen(args, env=env, stdout=log, stderr=log)
                eventually(lambda: call(i, "/status"))

            def stop(i):
                p = processes.pop(i)
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()

            def cli(*args):
                done = subprocess.run([sys.executable, "-m", "powcoin", *args], env=env,
                                      text=True, capture_output=True, timeout=20)
                self.assertEqual(done.returncode, 0, done.stderr)
                return done.stdout

            def mine_at(i, who, blocks):
                return cli("mine", "--config", str(root / "network.json"), "--url", urls[i],
                           "--address", who, "--blocks", str(blocks))

            try:
                start(0)
                start(1)
                self.assertFalse(call(0, "/status")["mining_progress"]["enabled"])
                eventually(lambda: any(p["reachable"] for p in call(0, "/status")["peer_status"]))
                with self.assertRaisesRegex(Invalid, "401"):
                    rpc(urls[0], "/status")
                mine_at(0, alice, 3)
                eventually(lambda: call(1, "/status")["height"] == 3)
                txresult = json.loads(cli("send", "--config", str(root / "network.json"),
                                         "--wallet", str(root / "alice.pem"), "--url", urls[1],
                                         "--to", bob, "--amount", "7.25", "--fee", "0.001"))
                eventually(lambda: call(0, "/status")["pending"] == 1)
                details = call(0, "/mempool/details")
                self.assertEqual(details[0]["txid"], txresult["txid"])
                self.assertEqual(details[0]["confirmations"], 0)
                # Pending transaction survives an abrupt process restart.
                stop(1)
                start(1)
                self.assertEqual(call(1, "/status")["pending"], 1)
                mine_at(1, bob, 1)
                eventually(lambda: call(0, "/status")["height"] == 4)
                self.assertEqual(call(0, "/mempool/details"), [])
                self.assertGreaterEqual(call(0, "/transactions/" + txresult["txid"])["confirmations"], 1)
                start(2)  # Late joining node reconstructs the ledger from genesis.
                eventually(lambda: call(2, "/status")["height"] == 4)
                tips = [call(i, "/status")["tip"] for i in range(3)]
                self.assertEqual(len(set(tips)), 1)
                for i in range(3):
                    self.assertEqual(call(i, "/accounts/" + bob)["balance"], 725_000_000)
                    self.assertEqual(call(i, "/transactions/" + txresult["txid"])["status"], "confirmed")
                # Two independent miner processes compete and retry stale work.
                miners = [subprocess.Popen([sys.executable, "-m", "powcoin", "mine", "--config",
                          str(root / "network.json"), "--url", urls[i], "--address", who,
                          "--blocks", "2"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                          for i, who in ((0, alice), (1, bob))]
                for miner in miners:
                    try:
                        out, err = miner.communicate(timeout=20)
                    except subprocess.TimeoutExpired:
                        miner.kill()
                        miner.communicate()
                        raise
                    self.assertEqual(miner.returncode, 0, err.decode())
                # Finite miners can stop on equal-work forks. As in Nakamoto
                # consensus, one further block on a maximal branch breaks a tie.
                leader = max(range(3), key=lambda i: call(i, "/status")["height"])
                mine_at(leader, alice, 1)
                eventually(lambda: len({call(i, "/status")["tip"] for i in range(3)}) == 1)
                self.assertGreaterEqual(call(0, "/status")["height"], 6)
                before = call(2, "/status")
                stop(2)
                start(2)
                self.assertEqual(call(2, "/status")["tip"], before["tip"])
                # Built-in node miner also operates without a wallet private key.
                stop(2)
                start(2, mining=True)
                eventually(lambda: call(2, "/status")["height"] > before["height"])
                self.assertTrue(call(2, "/status")["mining"])
                self.assertEqual(call(2, "/status")["mining_progress"]["reward_address"], bob)
                eventually(lambda: any(p["reachable"] and p["mining"] and p["reward_address"] == bob
                                       for p in call(0, "/status")["peer_status"]))
            finally:
                for i in list(processes):
                    stop(i)
                for log in logs:
                    log.close()


if __name__ == "__main__":
    unittest.main()
