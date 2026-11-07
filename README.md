# PowCoin

PowCoin is an academic teaching project for explaining blockchain concepts and security threats to students. Its Python proof-of-work cryptocurrency demonstrates full-node validation, encrypted Ed25519 wallets, signed account transfers, CPU mining, SQLite persistence, a browser explorer, and peer synchronization. It deliberately retains vulnerable design choices for security analysis in a controlled classroom setting. Do not use it for real funds or expose its HTTP API to the public Internet.

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

Run `python -m powcoin --help` for the full command list.

## Launch the wallet and mining interface

The desktop app needs a token file, even when the node runs only on your computer. First stop the node from the quick start with `Ctrl+C`. In that node terminal, create a token once and restart the **same** local chain with it:

```powershell
New-Item -ItemType Directory -Force .deploy | Out-Null
if (-not (Test-Path .deploy/shared_token)) {
    .\.venv\Scripts\python.exe -m powcoin token | Set-Content -NoNewline .deploy/shared_token
}
$env:POWCOIN_TOKEN = (Get-Content .deploy/shared_token -Raw).Trim()
.\.venv\Scripts\python.exe -m powcoin node --config network.json --data data/student --host 127.0.0.1 --port 8844
```

Leave the node running. In a second PowerShell terminal, from this repository folder, launch the interface:

```powershell
.\.venv\Scripts\python.exe -m powcoin.desktop --config network.json --node-url http://127.0.0.1:8844 --token-file .deploy/shared_token
```

The **PowCoin Wallet and Mining** window lets you create or open a wallet, view balances, send signed transfers, and mine blocks to a reward address. Tkinter must be available in your Python installation. Keep the generated token and any wallet PEM/password files private. The [student manual](docs/PowCoin_Student_Manual.pdf) walks through the interface and the underlying transactions.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Security learning purpose

PowCoin intentionally includes security weaknesses so students can study blockchain threats and evaluate defenses. Examples include a shared group API token, HTTP without built-in TLS, and fixed mining difficulty. Treat the project as a controlled lab exercise, not a secure cryptocurrency or production service. The [student manual](docs/PowCoin_Student_Manual.pdf) and [protocol reference](docs/PROTOCOL.md) explain the design and its limits.

## Privacy and scope

Running the exercises creates **new private files** on your machine. Keep wallet `.pem` files, `*-password.txt` sidecars, token files, and node data out of commits and shared archives. `.gitignore` helps with common paths but does not remove secrets already committed to Git history.

The implementation has fixed mining difficulty and is intended for learning, not production use. See the manual and protocol reference for its limits.

## License

See [LICENSE](LICENSE).
