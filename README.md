# PowCoin Student Starter

PowCoin is an educational proof-of-work cryptocurrency written in Python. The project demonstrates full-node validation, encrypted Ed25519 wallets, signed account transfers, CPU mining, SQLite persistence, a browser explorer, and peer synchronization. It is experimental software; do not use it for real funds or expose its HTTP API to the public Internet.

## What is here

| Path | Purpose |
| --- | --- |
| `powcoin/` | Consensus, ledger, wallet, networking, CLI, desktop app, and explorer source. |
| `tests/` | Automated consensus, wallet, desktop, network, and discovery tests. |
| `docs/PowCoin_Student_Manual.pdf` | Student manual with exercises, architecture, API, and security notes. |
| `docs/PROTOCOL.md` | Detailed protocol and implementation reference. |
| `pyproject.toml` | Python package metadata and dependency. |

[Read the student manual](docs/PowCoin_Student_Manual.pdf) before the first exercise.

## Quick start on Windows

Open PowerShell in this repository folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m powcoin init --out network.json --name StudentCoin --symbol STC --pow-bits 12
.\.venv\Scripts\python.exe -m powcoin node --config network.json --data data/student --host 127.0.0.1 --port 8844
```

Leave the node running. In a second PowerShell terminal, from the same folder:

```powershell
.\.venv\Scripts\python.exe -m powcoin status --url http://127.0.0.1:8844
```

Open `http://127.0.0.1:8844/` for the browser explorer. Use `Ctrl+C` to stop the node. For Linux or macOS, create a virtual environment with `python3 -m venv .venv`, use `.venv/bin/python`, and run the same `powcoin` commands.

The desktop app needs a configured token even for the classroom localhost exercise. The manual shows how to create that token and launch the app. Run `python -m powcoin --help` for the full command list.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Privacy and scope

This repository contains no instructor wallets, passwords, shared token, SSH key, or live node database. Running the exercises creates **new private files** on your machine. Keep wallet `.pem` files, `*-password.txt` sidecars, token files, and node data out of commits and shared archives. `.gitignore` helps with common paths but does not remove secrets already committed to Git history.

The implementation has fixed mining difficulty and is intended for learning, not production use. See the manual and protocol reference for its limits.

## License

See [LICENSE](LICENSE).
