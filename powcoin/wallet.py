"""Encrypted Ed25519 wallets. Private keys never go to a node."""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .consensus import address, canonical, chain_id, integer, hexstr


def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw).hex()


def create(path, password):
    if len(password) < 10:
        raise ValueError("Use a wallet password of at least 10 characters")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(password.encode()))
    # Never overwrite a wallet; restrictive mode on POSIX, inherited ACL on Windows.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
        f.flush()
        os.fsync(f.fileno())
    return address(public_hex(key))


def bundle_paths(path):
    wallet_path = Path(path)
    return (wallet_path,
            wallet_path.with_name(wallet_path.stem + "-password.txt"),
            wallet_path.with_name(wallet_path.stem + "-address.txt"))


def create_bundle(path, password):
    """Create a classroom wallet with an encrypted key and two text sidecars.

    The password sidecar is plaintext and must be kept private with the key.
    """
    key_path, password_path, address_path = bundle_paths(path)
    for item in (key_path, password_path, address_path):
        if item.exists():
            raise FileExistsError(f"Wallet bundle file already exists: {item}")
    created = []
    try:
        who = create(key_path, password)
        created.append(key_path)
        for item, value in ((password_path, password), (address_path, who)):
            fd = os.open(str(item), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(item)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(value + "\n")
                output.flush()
                os.fsync(output.fileno())
        return who
    except Exception:
        for item in reversed(created):
            item.unlink(missing_ok=True)
        raise


def load(path, password):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password.encode())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 wallet")
    return key


def sign(key, config, recipient, amount, fee, nonce):
    hexstr(recipient)
    integer(amount, 1)
    integer(fee)
    integer(nonce, 1)
    pub = public_hex(key)
    tx = {"chain": chain_id(config), "sender": address(pub), "public_key": pub,
          "recipient": recipient, "amount": amount, "fee": fee, "nonce": nonce}
    tx["signature"] = key.sign(canonical(tx)).hex()
    return tx
