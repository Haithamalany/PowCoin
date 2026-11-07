"""Bounded HTTP transport for trusted LAN/VPN peers; no wallet secrets exposed."""
import hmac
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .consensus import (Invalid, block_work, canonical, chain_id, hexstr,
                        integer, mine, require)
from .dashboard import DASHBOARD

LOG = logging.getLogger("powcoin")
MAX_REQUEST = 128_000
MAX_RESPONSE = 8_000_000
MAX_SYNC_BLOCKS = 100_000  # Local resource policy for this experimental release.
VPN_SUBNET = ipaddress.ip_network("10.8.0.0/24")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
PROOF_RE = re.compile(r"[0-9a-f]{64}\Z")
ANNOUNCE_INTERVAL = 30
ANNOUNCE_TTL = 120


def peer_url(url):
    p = urllib.parse.urlsplit(url)
    if (p.scheme not in ("http", "https") or not p.hostname or p.username or p.password
            or p.query or p.fragment or p.path not in ("", "/")):
        raise ValueError("Peer must be an http(s) origin, e.g. http://192.168.1.10:8844")
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError("Invalid peer port")
    return url.rstrip("/")


def discovery_origin(url, own_host):
    """Return only a canonical VPN HTTP origin, never a claimed hostname."""
    if type(url) is not str:
        return None
    try:
        parsed = urllib.parse.urlsplit(url)
        address = ipaddress.IPv4Address(parsed.hostname)
        if (parsed.scheme != "http" or parsed.netloc != "%s:8844" % address
                or parsed.path or parsed.query or parsed.fragment
                or parsed.port != 8844 or address not in VPN_SUBNET
                or str(address) == own_host):
            return None
        return "http://%s:8844" % address
    except (ValueError, TypeError):
        return None


def discovery_proof(token, nonce, origin, network_id):
    message = (b"powcoin-vpn-discovery-v1|" + bytes.fromhex(nonce) + b"|"
               + origin.encode("ascii") + b"|" + network_id.encode("ascii"))
    return hmac.new(token.encode("ascii"), message, hashlib.sha256).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def rpc(url, path, body=None, token=None):
    data = None if body is None else canonical(body)
    req = urllib.request.Request(peer_url(url) + path, data=data,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=5) as response:
            payload = response.read(MAX_RESPONSE + 1)
            if len(payload) > MAX_RESPONSE:
                raise Invalid("Peer response exceeds local limit")
            return json.loads(payload)
    except urllib.error.HTTPError as exc:
        with exc:
            detail = exc.read(1024).decode(errors="replace")
        raise Invalid("HTTP %s: %s" % (exc.code, detail)) from exc


class Server(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True

    def __init__(self, bind, node):
        self.node = node
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(bind, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "PowCoin/0.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, fmt, *args):
        LOG.debug("HTTP " + fmt, *args)

    def reply(self, status, obj):
        payload = canonical(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def reply_html(self, html):
        payload = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def dispatch(self, post=False):
        node = self.server.node
        try:
            p = urllib.parse.urlsplit(self.path)
            if not post and p.path == "/discovery-proof":
                # The only unauthenticated endpoint: a keyed challenge response.
                values = urllib.parse.parse_qs(p.query, keep_blank_values=True)
                nonce = values.get("nonce", [])
                require(not p.fragment and set(values) == {"nonce"}
                        and len(nonce) == 1 and NONCE_RE.fullmatch(nonce[0])
                        and p.query == "nonce=" + nonce[0],
                        "Invalid discovery nonce")
                host, port = self.server.server_address[:2]
                require(host not in ("0.0.0.0", "::") and node.token,
                        "Discovery proof unavailable")
                origin = "http://%s:%d" % (host, port)
                network_id = chain_id(node.ledger.config)
                self.reply(200, {"chain_id": network_id,
                                 "proof": discovery_proof(node.token, nonce[0], origin, network_id)})
                return
            if node.token and not hmac.compare_digest(
                    self.headers.get("Authorization", ""), "Bearer " + node.token):
                self.reply(401, {"error": "Authentication required"})
                return
            args = urllib.parse.parse_qs(p.query)
            if not post and p.path == "/":
                self.reply_html(DASHBOARD)
                return
            if post:
                if self.headers.get("Transfer-Encoding"):
                    raise Invalid("Chunked bodies are unsupported")
                n = int(self.headers.get("Content-Length", "0"))
                require(0 < n <= MAX_REQUEST, "request body exceeds limit or is missing")
                if self.headers.get_content_type() != "application/json":
                    raise Invalid("Content-Type must be application/json")
                raw = self.rfile.read(n)
                require(len(raw) == n, "incomplete body")
                body = json.loads(raw)
                if p.path == "/transactions":
                    result = {"txid": node.ledger.add_tx(body), "status": "pending"}
                elif p.path == "/blocks":
                    node.ledger.add_block(body)
                    result = node.ledger.status()
                elif p.path == "/announce":
                    require(type(body) is dict and set(body) == {"origin"},
                            "Invalid announcement")
                    node.register_peer(body["origin"], self.client_address[0])
                    result = {"registered": True}
                else:
                    self.reply(404, {"error": "Unknown endpoint"})
                    return
            elif p.path == "/status":
                result = dict(node.ledger.status(), mining=bool(node.mine_to),
                              peers=node.peer_snapshot(), mining_progress=node.mining_progress(),
                              peer_status=node.peer_status())
            elif p.path == "/config":
                result = node.ledger.config
            elif p.path == "/blocks":
                result = node.ledger.blocks(int(args.get("start", ["0"])[0]),
                                            int(args.get("count", ["50"])[0]))
            elif p.path == "/mempool":
                result = node.ledger.mempool()
            elif p.path == "/mempool/details":
                result = node.ledger.mempool_details()
            elif p.path.startswith("/accounts/"):
                result = node.ledger.account(p.path.split("/")[-1])
            elif p.path.startswith("/transactions/"):
                result = node.ledger.transaction(p.path.split("/")[-1])
            elif p.path == "/template":
                result = node.ledger.template(args.get("address", [""])[0])
            else:
                self.reply(404, {"error": "Unknown endpoint"})
                return
            self.reply(200, result)
        except (Invalid, ValueError, KeyError, TypeError, OverflowError, RecursionError) as exc:
            self.reply(400, {"error": str(exc)[:200]})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            LOG.exception("Request failed")
            self.reply(500, {"error": "Internal node error; inspect node log"})

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch(post=True)


class Node:
    def __init__(self, ledger, host="127.0.0.1", port=8844, peers=(), token=None,
                 mine_to=None, interval=2, discover_peer_list=False):
        self.ledger = ledger
        self.peers = [peer_url(p) for p in peers]
        require(len(self.peers) <= 32, "Maximum 32 configured peers")
        if token and (len(token) < 24 or not token.isascii() or any(c.isspace() for c in token)):
            raise ValueError("Node token must contain at least 24 ASCII characters without whitespace")
        if host not in ("127.0.0.1", "localhost") and not token:
            raise ValueError("Set POWCOIN_TOKEN before binding a LAN address")
        if mine_to:
            hexstr(mine_to)
        self.token, self.mine_to, self.interval = token, mine_to, interval
        self.discover_peer_list = discover_peer_list
        if discover_peer_list and not token:
            raise ValueError("Peer discovery requires POWCOIN_TOKEN")
        self.seed_peers = tuple(self.peers)
        self._discovered_peers = []
        self._announced_peers = {}
        self._last_announce = {}
        self._verified_peers = set(self.seed_peers)
        self.sync_lock = threading.Lock()
        self.stopped = threading.Event()
        self.info_lock = threading.Lock()
        self._mining = {"active": False, "candidate_height": None, "attempts": 0,
                        "started": None, "last_block_height": None, "last_block_hash": None}
        self._peer_status = {p: {"url": p, "reachable": False, "height": None,
                                 "mining": None, "reward_address": None,
                                 "hash_rate": None, "last_seen": None} for p in self.peers}
        self.server = Server((host, port), self)
        self.threads = []

    def mining_progress(self):
        with self.info_lock:
            m = self._mining.copy()
        elapsed = max(time.monotonic() - m["started"], 0.001) if m["started"] else 0
        return {"enabled": bool(self.mine_to), "reward_address": self.mine_to,
                "active": m["active"], "candidate_height": m["candidate_height"],
                "attempts": m["attempts"],
                "hash_rate": round(m["attempts"] / elapsed, 1) if m["active"] else 0,
                "last_block_height": m["last_block_height"],
                "last_block_hash": m["last_block_hash"]}

    def peer_status(self):
        with self.info_lock:
            self._refresh_peers_locked()
            return [self._peer_status[p].copy() for p in self.peers]

    def peer_snapshot(self):
        with self.info_lock:
            self._refresh_peers_locked()
            return list(self.peers)

    def _refresh_peers_locked(self):
        now = time.monotonic()
        self._announced_peers = {p: expiry for p, expiry in self._announced_peers.items()
                                 if expiry > now}
        peers = list(self.seed_peers)
        for peer in list(self._announced_peers) + self._discovered_peers:
            if peer not in peers and len(peers) < 32:
                peers.append(peer)
        removed = set(self.peers) - set(peers)
        self._verified_peers.difference_update(removed)
        for peer in removed:
            self._peer_status.pop(peer, None)
        self.peers = peers
        for peer in peers:
            self._peer_status.setdefault(peer, {"url": peer, "reachable": False,
                "height": None, "mining": None, "reward_address": None,
                "hash_rate": None, "last_seen": None})

    def register_peer(self, origin, source_host):
        host = self.server.server_address[0]
        require(self.token and ipaddress.IPv4Address(host) in VPN_SUBNET,
                "Registration requires a VPN bind")
        candidate = discovery_origin(origin, host)
        require(candidate is not None and source_host == urllib.parse.urlsplit(candidate).hostname,
                "Announcement must come from its VPN origin")
        self.check_discovery_proof(candidate)
        with self.info_lock:
            self._refresh_peers_locked()
            require(candidate in self._announced_peers
                    or len(self.seed_peers) + len(self._announced_peers) < 32,
                    "Peer limit reached")
            self._announced_peers[candidate] = time.monotonic() + ANNOUNCE_TTL
            self._refresh_peers_locked()
            self._verified_peers.add(candidate)

    def announce_to_seed(self, peer):
        if not self.discover_peer_list:
            return
        origin = "http://%s:%d" % self.server.server_address[:2]
        if discovery_origin(origin, "") is None or discovery_origin(peer, "") is None:
            return
        now = time.monotonic()
        if now - self._last_announce.get(peer, float("-inf")) < ANNOUNCE_INTERVAL:
            return
        self._last_announce[peer] = now
        try:
            self.call(peer, "/announce", {"origin": origin})
        except Exception as exc:
            LOG.debug("Announcement to %s failed: %s", peer, exc)

    def discover(self, seed_status):
        entries = seed_status.get("peers")
        if type(entries) is not list:
            return  # Malformed lists do not erase previously verified peers.
        desired = []
        for entry in entries[:64]:
            origin = discovery_origin(entry, self.server.server_address[0])
            if origin and origin not in self.seed_peers and origin not in desired:
                desired.append(origin)
        with self.info_lock:
            self._discovered_peers = desired
            self._refresh_peers_locked()

    def check_discovery_proof(self, peer):
        nonce = secrets.token_hex(16)
        response = rpc(peer, "/discovery-proof?nonce=" + nonce)
        network_id = chain_id(self.ledger.config)
        require(type(response) is dict and response.get("chain_id") == network_id,
                "discovery chain mismatch")
        proof = response.get("proof")
        require(type(proof) is str and PROOF_RE.fullmatch(proof), "invalid discovery proof")
        expected = discovery_proof(self.token, nonce, peer, network_id)
        require(hmac.compare_digest(proof, expected), "discovery proof mismatch")

    def verify_discovered(self, peer):
        self.check_discovery_proof(peer)
        with self.info_lock:
            if peer in self.peers:
                self._verified_peers.add(peer)

    def call(self, peer, path, body=None):
        return rpc(peer, path, body, self.token)

    def sync_once(self):
        with self.sync_lock:
            self._sync_once()

    def _sync_once(self):
        for peer in self.peer_snapshot():
            if peer in self.seed_peers:
                self._sync_peer(peer)
        for peer in self.peer_snapshot():
            if peer not in self.seed_peers:
                self._sync_peer(peer)

    def _sync_peer(self, peer):
            if self.stopped.is_set():
                return
            try:
                with self.info_lock:
                    verified = peer in self._verified_peers
                if not verified:
                    self.verify_discovered(peer)
                remote = self.call(peer, "/status")
                require(remote["chain_id"] == chain_id(self.ledger.config), "peer network mismatch")
                integer(remote["height"], 0, MAX_SYNC_BLOCKS)
                hexstr(remote["tip"])
                if self.discover_peer_list and peer in self.seed_peers:
                    self.discover(remote)
                if peer in self.seed_peers:
                    self.announce_to_seed(peer)
                mining = remote.get("mining_progress", {})
                reward = mining.get("reward_address") if type(mining) is dict else None
                if reward is not None:
                    hexstr(reward)
                rate = mining.get("hash_rate") if type(mining) is dict else None
                if type(rate) not in (int, float) or rate < 0:
                    rate = None
                with self.info_lock:
                    self._peer_status[peer].update(reachable=True, height=remote["height"],
                                                    mining=bool(remote.get("mining")),
                                                    reward_address=reward, hash_rate=rate,
                                                    last_seen=int(time.time()))
                # Never trust a peer's claimed work; derive from local consensus.
                claimed_work = remote["height"] * block_work(self.ledger.config)
                if claimed_work > int(self.ledger.status()["work"]):
                    chain = []
                    while len(chain) <= remote["height"]:
                        if self.stopped.is_set():
                            return
                        count = min(50, remote["height"] + 1 - len(chain))
                        page = self.call(peer, "/blocks?start=%d&count=%d" % (len(chain), count))
                        blocks = page["blocks"]
                        require(type(blocks) is list and 1 <= len(blocks) <= count, "invalid block page")
                        chain.extend(blocks)
                        require(len(chain) <= remote["height"] + 1, "unexpected chain size")
                    require(chain[-1]["hash"] == remote["tip"], "peer tip mismatch")
                    if self.ledger.adopt(chain):
                        LOG.info("Synchronized height %s from %s", remote["height"], peer)
                pool = self.call(peer, "/mempool")
                require(type(pool) is list and len(pool) <= 1000, "invalid peer mempool")
                for tx in pool:
                    try:
                        self.ledger.add_tx(tx)
                    except (Invalid, ValueError, TypeError, KeyError):
                        continue
            except Exception as exc:
                with self.info_lock:
                    if peer in self._peer_status:
                        self._peer_status[peer]["reachable"] = False
                    if peer not in self.seed_peers:
                        self._verified_peers.discard(peer)
                LOG.debug("Peer %s unavailable/rejected: %s", peer, exc)

    def broadcast(self, block):
        with self.info_lock:
            peers = [p for p in self.peers if p in self._verified_peers]
        for peer in peers:
            try:
                self.call(peer, "/blocks", block)
            except Exception:
                pass  # Polling synchronization recovers dropped/racing blocks.

    def sync_loop(self):
        while not self.stopped.is_set():
            self.sync_once()
            self.stopped.wait(self.interval)

    def mine_loop(self):
        # Catch up once before starting work on the local tip.
        self.sync_once()
        while not self.stopped.is_set():
            b = self.ledger.template(self.mine_to)
            tip = b["previous"]
            with self.info_lock:
                self._mining.update(active=True, candidate_height=b["height"],
                                    attempts=0, started=time.monotonic())
            def progress(attempts):
                with self.info_lock:
                    self._mining["attempts"] = attempts
            found = mine(b, self.ledger.config, lambda: self.stopped.is_set()
                         or self.ledger.status()["tip"] != tip, progress)
            with self.info_lock:
                self._mining["active"] = False
            if found:
                try:
                    self.ledger.add_block(found)
                except Invalid:
                    continue
                LOG.info("Mined block %s: %s", found["height"], found["hash"])
                with self.info_lock:
                    self._mining.update(last_block_height=found["height"],
                                        last_block_hash=found["hash"])
                self.broadcast(found)
            self.stopped.wait(0.05)

    def start(self):
        functions = [self.server.serve_forever, self.sync_loop]
        if self.mine_to:
            functions.append(self.mine_loop)
        for function in functions:
            t = threading.Thread(target=function, daemon=True)
            t.start()
            self.threads.append(t)

    def close(self):
        self.stopped.set()
        self.server.shutdown()
        self.server.server_close()
        for thread in self.threads:
            thread.join()  # Requests have finite timeouts; no ledger use after close.
        self.ledger.close()
