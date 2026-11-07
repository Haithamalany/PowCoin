import argparse
import getpass
import json
import logging
import os
import secrets
import sys
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

from . import wallet
from .consensus import (COIN, Invalid, address, chain_id, integer, mine, validate_config)
from .ledger import Ledger
from .network import Node, rpc


def coins(value):
    try:
        amount = Decimal(value) * COIN
        if not amount.is_finite() or amount != amount.to_integral_value():
            raise ValueError("Use at most 8 decimal places")
        return integer(int(amount))
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def read_config(path):
    return validate_config(json.loads(Path(path).read_text()))


def password(confirm=False):
    # Environment option exists for noninteractive local scripts; prompt preferred.
    value = os.environ.get("POWCOIN_WALLET_PASSWORD")
    if value is None:
        value = getpass.getpass("Wallet password: ")
        if confirm and value != getpass.getpass("Repeat password: "):
            raise ValueError("Passwords do not match")
    return value


def output(obj):
    print(json.dumps(obj, indent=2))


def parser():
    p = argparse.ArgumentParser(description="Experimental local proof-of-work cryptocurrency")
    sub = p.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create a new network configuration; distribute the same file")
    init.add_argument("--out", default="network.json")
    init.add_argument("--name", default="MyCoin")
    init.add_argument("--symbol", default="MYC")
    init.add_argument("--network", default=None)
    init.add_argument("--pow-bits", type=int, default=20)
    init.add_argument("--reward", type=coins, default=50 * COIN)
    init.add_argument("--halving-interval", type=int, default=210000)
    init.add_argument("--maturity", type=int, default=2)
    sub.add_parser("token", help="Generate a shared LAN/VPN API token")
    for command in ("wallet-create", "wallet-address"):
        w = sub.add_parser(command)
        w.add_argument("--wallet", required=True)
    node = sub.add_parser("node", help="Run a full validating node, optionally mining")
    node.add_argument("--config", default="network.json")
    node.add_argument("--data", required=True)
    node.add_argument("--host", default="127.0.0.1")
    node.add_argument("--port", type=int, default=8844)
    node.add_argument("--peer", action="append", default=[])
    node.add_argument("--discover-peer-list", action="store_true",
                      help="Discover VPN peers from seed status and announce this VPN node to seeds")
    node.add_argument("--mine-to")
    node.add_argument("--verbose", action="store_true")
    for command in ("status", "balance", "send", "mine", "tx"):
        cmd = sub.add_parser(command)
        cmd.add_argument("--url", default="http://127.0.0.1:8844")
        if command == "balance":
            cmd.add_argument("--address", required=True)
        elif command == "send":
            cmd.add_argument("--config", default="network.json")
            cmd.add_argument("--wallet", required=True)
            cmd.add_argument("--to", required=True)
            cmd.add_argument("--amount", type=coins, required=True)
            cmd.add_argument("--fee", type=coins, default=coins("0.001"))
        elif command == "mine":
            cmd.add_argument("--config", default="network.json")
            cmd.add_argument("--address", required=True)
            cmd.add_argument("--blocks", type=int, default=1)
        elif command == "tx":
            cmd.add_argument("--id", required=True)
    return p


def run(args):
    token = os.environ.get("POWCOIN_TOKEN")
    if args.command == "init":
        config = validate_config({"version": 1, "name": args.name, "symbol": args.symbol,
                                  "network": args.network or "private-" + secrets.token_hex(8),
                                  "pow_bits": args.pow_bits, "reward": args.reward,
                                  "halving_interval": args.halving_interval,
                                  "maturity": args.maturity, "genesis_time": int(time.time())})
        with open(args.out, "x", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        output({"config": args.out, "chain_id": chain_id(config)})
    elif args.command == "token":
        print(secrets.token_urlsafe(32))
    elif args.command == "wallet-create":
        who = wallet.create_bundle(args.wallet, password(True))
        key_path, password_path, address_path = wallet.bundle_paths(args.wallet)
        output({"address": who, "wallet": str(key_path),
                "password_file": str(password_path), "address_file": str(address_path)})
    elif args.command == "wallet-address":
        output({"address": address(wallet.public_hex(wallet.load(args.wallet, password())))})
    elif args.command == "node":
        logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
        ledger = Ledger(read_config(args.config), args.data)
        try:
            node = Node(ledger, args.host, args.port, args.peer, token, args.mine_to,
                        discover_peer_list=args.discover_peer_list)
        except Exception:
            ledger.close()
            raise
        node.start()
        output(dict(ledger.status(), bind="%s:%s" % (args.host, args.port),
                    mining=bool(args.mine_to)))
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            node.close()
    elif args.command == "status":
        output(rpc(args.url, "/status", token=token))
    elif args.command == "balance":
        result = rpc(args.url, "/accounts/" + args.address, token=token)
        result["balance_coins"] = str(Decimal(result["balance"]) / COIN)
        result["immature_coins"] = str(Decimal(result["immature"]) / COIN)
        result["next_block_available_coins"] = str(Decimal(result["next_block_available"]) / COIN)
        output(result)
    elif args.command == "tx":
        output(rpc(args.url, "/transactions/" + args.id, token=token))
    elif args.command in ("send", "mine"):
        config = read_config(args.config)
        remote = rpc(args.url, "/status", token=token)
        if remote["chain_id"] != chain_id(config):
            raise Invalid("Node does not match your local network configuration")
        if args.command == "send":
            key = wallet.load(args.wallet, password())
            who = address(wallet.public_hex(key))
            account = rpc(args.url, "/accounts/" + who, token=token)
            tx = wallet.sign(key, config, args.to, args.amount, args.fee, account["next_nonce"])
            output(rpc(args.url, "/transactions", tx, token))
        else:
            integer(args.blocks, 1, 100000)
            done = 0
            while done < args.blocks:
                b = rpc(args.url, "/template?address=" + args.address, token=token)
                found = mine(b, config)
                try:
                    result = rpc(args.url, "/blocks", found, token)
                    output({"height": result["height"], "hash": result["tip"]})
                    done += 1
                except Invalid as exc:
                    if "wrong parent" not in str(exc) and "wrong height" not in str(exc):
                        raise
                    print("Tip changed; rebuilding work", file=sys.stderr)


def main():
    try:
        run(parser().parse_args())
    except KeyboardInterrupt:
        return
    except (ValueError, OSError, KeyError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        sys.exit(1)
