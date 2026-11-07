# Protocol and implementation reference

Edition: 6 November 2026. Package 0.1.0 with VPN discovery and announcements.
This describes the current code, including local resource policies. Read the
[manual](MANUAL.md) for deployment, operations, and security analysis.

## Configuration and consensus

The chain ID is SHA-256 of canonical validated configuration JSON. Canonical
serialization uses sorted keys, ASCII escaping, compact separators, and no NaN.
Changing configuration values changes network identity. Genesis is a deterministic
unmined record with no coins. Never initialize a replacement configuration for
the existing deployment.

| Property | Rule |
| --- | --- |
| Header hash | SHA-256 of canonical header JSON |
| Target | `2^(256 - pow_bits) - 1`; fixed difficulty |
| Work per valid block | `floor(2^256 / (target + 1))` |
| Chain selection | Fully validate and adopt only strictly greater cumulative work; retain local tip on ties |
| State model | Account balances and per-sender nonces beginning at 1 |
| Address | Lowercase hex SHA-256 of raw 32-byte Ed25519 public key |
| Signature | Ed25519 over all transaction fields except signature |
| Monetary unit | 100,000,000 integer base units per coin |
| Subsidy at height h | Initial reward right-shifted by `min(64, floor((h - 1) / halving_interval))` |
| Reward | Exactly subsidy plus transaction fees, locked until `h + maturity` |
| Timestamp | Integer Unix seconds, at least previous timestamp, at most local clock plus 120 seconds |
| Transactions per block | Zero to 100, applied in order |
| Canonical block bytes | At most 128,000 |
| Ordinary integer fields | Strict integers, not booleans/floats; upper bound `2^63 - 1` |

The mined header contains `version`, `chain`, `height`, `previous`,
`timestamp`, `nonce`, `miner`, `reward`, and `merkle`. The full block
adds `transactions` and `hash`. A transaction ID hashes its complete signed
canonical JSON. Merkle leaves are transaction hashes, pairs are hashed with
SHA-256, and an odd leaf is duplicated. The empty root is SHA-256 of empty bytes.

Transactions contain exactly `chain sender public_key recipient amount fee nonce
signature`. Validation checks chain, key/address relationship, signature, next
nonce, positive amount, nonnegative fee, amount-plus-fee bound, and available
balance. Self-transfers are allowed and still consume nonce and fee. A sender
may also be the block miner.

At height h, rewards due by h mature first, then transfers execute in order.
A later transfer can spend an earlier receipt in the same block. The new reward
cannot pay for transfers in its own block. Pending-state validation previews the
next height and reserves local balances/nonces.

## Persistence, reorganization, and sync

SQLite stores canonical blocks, pending transactions, and chain identity using
WAL and FULL synchronous mode. Each data directory has one OS-locked owner.
Nodes validate saved blocks on startup and reject mismatched configuration.

A received block must extend the current tip and satisfy every rule. For a peer
claiming a greater height, synchronization fetches blocks from genesis in pages
of at most 50, checks the advertised tip, and validates the candidate chain.
Remote reported work is not authoritative. Reorganizations rebuild balances and
nonces and offer still-valid orphaned transactions back to the bounded pool.
Historical side branches are not archived.

## Node HTTP API

Except GET `/discovery-proof`, all routes require
`Authorization: Bearer TOKEN` when `POWCOIN_TOKEN` is configured.
Non-loopback binds require a token. Loopback nodes without a token remain
unauthenticated. The built-in listener is HTTP; explicitly configured outbound
peers may use HTTP or HTTPS. Outbound node RPC disables environment proxies and
rejects redirects.

| Method | Path | Result or request body |
| --- | --- | --- |
| GET | `/` | Explorer HTML |
| GET | `/status` | Chain identity, height, tip, decimal work string, pending count, mining data, peers, cached peer status |
| GET | `/config` | Consensus configuration |
| GET | `/blocks?start=0&count=50` | Canonical block page; genesis at 0, count at most 50 |
| GET | `/mempool` | Pending signed transactions |
| GET | `/mempool/details` | Transactions with IDs and zero confirmations |
| GET | `/accounts/ADDRESS` | Balance, immature rewards, next-height pending preview, nonces |
| GET | `/transactions/TXID` | Pending/confirmed/unknown and current-chain confirmations |
| GET | `/template?address=ADDRESS` | Candidate block for the reward address |
| POST | `/transactions` | One complete signed transaction |
| POST | `/blocks` | One complete valid block extending the local tip |
| POST | `/announce` | Authenticated VPN peer registration with `{"origin":"http://10.8.0.x:8844"}` |
| GET | `/discovery-proof?nonce=NONCE` | Unauthenticated challenge response as specified below |

JSON money values are base-unit integers. CLI monetary inputs use decimal coins.
POSTs require JSON Content-Type and Content-Length; chunked bodies are rejected.
There are no wallet-unlock, private-key import, or remote administrative endpoints.

The separate Windows loopback dashboard exposes only `/`, `/status`,
`/blocks`, `/mempool/details`, and `/accounts/...` through its own read-only
interface. It is not a full API endpoint for wallet/mining clients.

## Discovery eligibility and lifecycle

`node --discover-peer-list` enables list learning and announcements to explicitly
configured VPN seeds. Those seeds are trusted token destinations before proof. In the standard
Windows deployment, the sole seed is `http://10.8.0.1:8844`.

After validating a seed's status, a VPN-bound node sends authenticated
`POST /announce` with its own VPN origin to that seed. The seed checks that the
request's VPN source IP matches the claimed IP and challenges the origin through
`/discovery-proof` before retaining it. Registered origins appear in `/status`
peers, refresh no more than once per 30 seconds, and expire after 120 seconds
without refresh. The seed needs this version of the code; an older seed rejects
`/announce`. Registrations are in memory.

After authenticated status and chain/height/tip checks, examine the first 64
elements of the seed's `peers` list. Retain at most 32 total peers, including
seeds. Discovered entries must normalize to an origin exactly of the form
`http://10.8.0.x:8844`, with IPv4 in `10.8.0.0/24`. Reject hostnames,
credentials, other schemes/ports, all paths including a trailing slash, queries,
fragments, non-VPN addresses, and the node's own bound address. Deduplicate
discovered origins.

Valid changed lists replace the seed-learned set while preserving configured
seeds and unexpired inbound registrations. Empty valid lists remove seed-learned peers; malformed non-lists are
ignored. Seed outages retain the last set. Lists learned from discovered peers
are not recursively explored. Multiple seeds are processed sequentially and
the last valid list replaces the others rather than forming a union.

Peer/status collections are accessed under locks or by snapshot; sync passes
are serialized. A failed sync marks a discovered peer unreachable and removes
its verified state. Its next authenticated sync requires another successful
proof. Removed peers lose cached status/proof. State is not persisted across
restarts. Unverified peers are omitted from block broadcasts.

## Exact discovery proof protocol

The requester generates 16 fresh cryptographically random bytes and lower-hex
encodes them to a 32-character nonce. It sends:

```text
GET /discovery-proof?nonce=<32 lowercase hex characters>
```

There is **no Authorization header**, and redirects are not followed. The
requester requires a JSON object containing its local `chain_id` and a
64-character lowercase hex `proof`.

The exact message and key are:

```python
key = POWCOIN_TOKEN.encode("ascii")
message = (
    b"powcoin-vpn-discovery-v1|"
    + bytes.fromhex(nonce)
    + b"|" + candidate_origin.encode("ascii")
    + b"|" + chain_id.encode("ascii")
)
expected = hmac.new(key, message, hashlib.sha256).hexdigest()
valid = hmac.compare_digest(response["proof"], expected)
```

The origin is exactly `http://<candidate-ip>:8844`. A chain match or claimed IP
without the valid proof is insufficient. On any failure, no authenticated
request is sent to that candidate. After success, normal authenticated sync
still checks every block against unchanged consensus rules.

The responder accepts one literal `nonce=` query with exactly 32 lowercase
hex characters and no other parameters. It derives its origin from its actual
server bind, ignoring Host headers and caller claims. It requires a configured
token and a concrete bind; wildcard binds cannot produce proofs. It returns:

```json
{"chain_id": "<local chain ID>", "proof": "<64 lowercase hex characters>"}
```

The token is not returned. The responder exists even if outbound list discovery
is disabled. Proof demonstrates shared-key possession for the challenge, origin,
and chain; it is not an individual identity certificate or encrypted session.
A container signing a Docker-bound origin will not validate when advertised
under an unrelated forwarded VPN origin.

## Resource policies and limitations

| Resource | Limit |
| --- | --- |
| Node request body | 128,000 bytes |
| Node RPC response | 8,000,000 bytes |
| Node request handlers | 16 simultaneous |
| Node socket/outbound timeout | 5 seconds |
| Pending pool | 1,000 transactions |
| Total peers | 32 |
| Seed entries examined | 64 |
| Remote sync height | 100,000 |
| Block page | 50 blocks |
| Sync delay | 2 seconds after each completed pass |

These local policies are distinct from consensus. There is no TLS listener,
difficulty retargeting, rate-limited proof service, per-node credential,
public peer reputation, or incremental branch synchronization. The wallet GUI
and restricted discovery are implemented. See the
[security chapter](MANUAL.md#13-security-model-and-weaknesses) for known risks
and the [validation record](VALIDATION.md) for tested scope.
