"""Local PowCoin wallet and mining desktop application."""

import argparse
import os
import queue
import threading
import time
import tkinter as tk
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import wallet
from .consensus import COIN, Invalid, address, chain_id, hexstr, mine, validate_config
from .network import rpc


def units(value, allow_zero=False):
    try:
        amount = Decimal(value)
        result = amount * COIN
        if not amount.is_finite() or result != result.to_integral_value():
            raise ValueError("Use at most 8 decimal places")
        if result < (0 if allow_zero else 1):
            raise ValueError("Amount must be positive" if not allow_zero else "Fee cannot be negative")
        return int(result)
    except InvalidOperation as exc:
        raise ValueError("Enter a valid number") from exc


def coins(value):
    return f"{Decimal(value) / COIN:,.8f}"


@dataclass(frozen=True)
class OpenedWallet:
    """One unlocked wallet; keep its key in memory, never its password."""
    path: Path
    key: Ed25519PrivateKey = field(repr=False)

    @property
    def address(self):
        return address(wallet.public_hex(self.key))


class DemoClient:
    def __init__(self, config_path, node_url, token_file):
        import json
        self.config = validate_config(json.loads(Path(config_path).read_text(encoding="utf-8")))
        self.node_url = node_url
        token_path = Path(token_file)
        self.token = (token_path.read_text(encoding="utf-8").strip() if token_path.exists()
                      else os.environ.get("POWCOIN_TOKEN"))
        if not self.token:
            raise ValueError(f"Shared token not found: {token_path}")

    def call(self, path, body=None):
        return rpc(self.node_url, path, body, self.token)

    def status(self):
        result = self.call("/status")
        if result["chain_id"] != chain_id(self.config):
            raise ValueError("Node and local network.json use different chains")
        return result

    def open_wallet(self, path, password):
        key = wallet.load(path, password)
        return OpenedWallet(Path(path), key)

    def create_wallet(self, path, password):
        wallet.create_bundle(path, password)
        return self.open_wallet(path, password)

    def account(self, who):
        return self.call("/accounts/" + who)

    def send(self, opened_wallet, recipient, amount, fee):
        self.status()
        sender = opened_wallet.address
        account = self.account(sender)
        transaction = wallet.sign(opened_wallet.key, self.config, recipient, amount, fee,
                                  account["next_nonce"])
        return self.call("/transactions", transaction)["txid"]

    def transaction(self, txid):
        return self.call("/transactions/" + txid)

    def mine_blocks(self, reward_address, count, stop, emit):
        self.status()
        done = 0
        while done < count and not stop.is_set():
            block = self.call("/template?address=" + reward_address)
            started = time.monotonic()
            last_update = [0.0]

            def progress(attempts):
                now = time.monotonic()
                if now - last_update[0] >= 0.25:
                    last_update[0] = now
                    emit("progress", (block["height"], attempts,
                                      int(attempts / max(now - started, 0.001))))

            found = mine(block, self.config, stop.is_set, progress)
            if found is None:
                break
            try:
                result = self.call("/blocks", found)
            except Invalid as exc:
                if "wrong parent" in str(exc) or "wrong height" in str(exc):
                    emit("info", "Chain advanced; rebuilding candidate")
                    continue
                raise
            done += 1
            emit("mined", (done, result["height"], result["tip"]))
        return done


class PasswordDialog(tk.Toplevel):
    """Masked password prompt with explicit clipboard paste controls."""

    def __init__(self, parent, prompt, confirm=False):
        super().__init__(parent)
        self.result = None
        self.confirm = confirm
        self.title("Wallet password")
        self.transient(parent)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda _event: self.destroy())
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=prompt, wraplength=380).grid(row=0, column=0, columnspan=2, sticky="w")
        self.password_entry = self.add_entry(frame, 1)
        self.confirm_entry = None
        next_row = 2
        if confirm:
            ttk.Label(frame, text="Repeat password:").grid(row=2, column=0, columnspan=2, sticky="w", pady=(10, 0))
            self.confirm_entry = self.add_entry(frame, 3)
            next_row = 4
        self.visible = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Show password", variable=self.visible,
                        command=self.toggle_visibility).grid(row=next_row, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.error_text = tk.StringVar()
        ttk.Label(frame, textvariable=self.error_text, foreground="#b00020").grid(
            row=next_row + 1, column=0, columnspan=2, sticky="w")
        buttons = ttk.Frame(frame)
        buttons.grid(row=next_row + 2, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(buttons, text="OK", command=self.submit).pack(side="right", padx=(0, 8))
        self.password_entry.focus_set()
        self.grab_set()

    def add_entry(self, frame, row):
        entry = ttk.Entry(frame, show="*", width=42)
        entry.grid(row=row, column=0, sticky="ew", pady=(5, 0))
        ttk.Button(frame, text="Paste", command=lambda: self.paste(entry)).grid(
            row=row, column=1, padx=(8, 0), pady=(5, 0))
        menu = tk.Menu(entry, tearoff=False)
        menu.add_command(label="Paste", command=lambda: self.paste(entry))
        entry.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))
        for key in ("<Control-v>", "<Control-V>", "<Shift-Insert>"):
            entry.bind(key, lambda _event, target=entry: self.paste(target))
        entry.bind("<Return>", lambda _event: self.submit())
        return entry

    def paste(self, entry):
        try:
            value = self.clipboard_get()
        except tk.TclError:
            self.error_text.set("Clipboard is empty or unavailable.")
            return "break"
        if entry.selection_present():
            entry.delete("sel.first", "sel.last")
        entry.insert(tk.INSERT, value)
        self.error_text.set("")
        return "break"

    def toggle_visibility(self):
        mask = "" if self.visible.get() else "*"
        self.password_entry.configure(show=mask)
        if self.confirm_entry:
            self.confirm_entry.configure(show=mask)

    def submit(self):
        value = self.password_entry.get()
        if self.confirm:
            if len(value) < 10:
                self.error_text.set("Use at least 10 characters.")
                return
            if value != self.confirm_entry.get():
                self.error_text.set("Passwords do not match.")
                return
        self.result = value
        self.destroy()


class DemoApp:
    def __init__(self, root, client):
        self.root, self.client = root, client
        self.events = queue.Queue()
        self.sender_file = None
        self.sender_address = None
        self.sender_wallet = None
        self.opening_wallet = False
        self.transfer_pending = False
        self.refresh_generation = 0
        self.last_refresh_applied = 0
        self.opened_wallets = []
        self.last_txid = None
        self.mining_stop = None
        self.mining_thread = None

        root.title("PowCoin Wallet and Mining")
        root.geometry("960x850")
        root.minsize(800, 780)
        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="PowCoin Wallet and Mining", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        self.network_text = tk.StringVar(value="Connecting to local node...")
        ttk.Label(outer, textvariable=self.network_text).pack(anchor="w", pady=(2, 10))
        self.build_wallet_header(outer)
        tabs = ttk.Notebook(outer)
        tabs.pack(fill="both", expand=True)
        wallet_tab = ttk.Frame(tabs, padding=14)
        mining_tab = ttk.Frame(tabs, padding=14)
        tabs.add(wallet_tab, text="Wallet and transfer")
        tabs.add(mining_tab, text="Mining")
        self.build_wallet(wallet_tab)
        self.build_mining(mining_tab)
        self.notice = tk.StringVar(value="Ready")
        ttk.Label(outer, textvariable=self.notice, wraplength=720).pack(anchor="w", pady=(10, 0))
        root.after(100, self.drain_events)
        root.after(300, self.refresh)
        root.after(5000, self.periodic_refresh)
        root.protocol("WM_DELETE_WINDOW", self.close)

    def build_wallet_header(self, outer):
        panel = ttk.LabelFrame(outer, text="My wallet", padding=10)
        panel.pack(fill="x", pady=(0, 10))
        buttons = ttk.Frame(panel)
        buttons.pack(anchor="w")
        self.open_button = ttk.Button(buttons, text="Open wallet file (.pem)", command=self.open_sender)
        self.open_button.pack(side="left", padx=(0, 7))
        self.create_button = ttk.Button(buttons, text="Create wallet (3 files)", command=self.new_wallet)
        self.create_button.pack(side="left", padx=(0, 7))
        ttk.Button(buttons, text="Copy address", command=self.copy_sender_address).pack(side="left")
        self.wallet_file_text = tk.StringVar(value="Wallet file: none selected")
        ttk.Label(panel, textvariable=self.wallet_file_text, wraplength=760).pack(anchor="w", pady=(8, 4))
        ttk.Label(panel, text="Public wallet address (share this to receive coins):").pack(anchor="w")
        self.wallet_address_text = tk.StringVar(value="Open a wallet to show its address")
        ttk.Entry(panel, textvariable=self.wallet_address_text, state="readonly").pack(fill="x", pady=(3, 0))
        self.balance_text = tk.StringVar(value="Balance: open a wallet to see its funds")
        ttk.Label(panel, textvariable=self.balance_text, font=("Segoe UI", 11, "bold"),
                  wraplength=840).pack(anchor="w", pady=(8, 2))
        ttk.Label(panel, text="Opened wallets — select an address and press Ctrl+C, or use Copy:").pack(
            anchor="w", pady=(8, 2))
        self.opened_wallets_frame = ttk.Frame(panel)
        self.opened_wallets_frame.pack(fill="x")
        ttk.Label(panel, text="New wallets save the password as plain text beside the encrypted key. Keep all files private.",
                  wraplength=790).pack(anchor="w", pady=(5, 0))

    def build_wallet(self, frame):
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Signed transfer", font=("Segoe UI", 12, "bold")).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Recipient address").grid(row=3, column=0, sticky="w", pady=6)
        recipient_row = ttk.Frame(frame)
        recipient_row.grid(row=3, column=1, sticky="ew")
        recipient_row.columnconfigure(0, weight=1)
        self.recipient = tk.StringVar()
        ttk.Entry(recipient_row, textvariable=self.recipient).grid(row=0, column=0, sticky="ew")
        ttk.Button(recipient_row, text="Paste address", command=self.paste_recipient_address).grid(row=0, column=1, padx=(6, 0))
        ttk.Label(frame, text="Use the recipient's public address. Their wallet and password are not needed.",
                  wraplength=690).grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 7))
        ttk.Label(frame, text="Amount (PWN)").grid(row=5, column=0, sticky="w", pady=6)
        self.amount = tk.StringVar(value="1")
        ttk.Entry(frame, textvariable=self.amount).grid(row=5, column=1, sticky="ew")
        ttk.Label(frame, text="Fee (PWN)").grid(row=6, column=0, sticky="w", pady=6)
        self.fee = tk.StringVar(value="0.001")
        ttk.Entry(frame, textvariable=self.fee).grid(row=6, column=1, sticky="ew")
        self.send_button = ttk.Button(frame, text="Review and sign transfer", command=self.send, state="disabled")
        self.send_button.grid(row=7, column=0, columnspan=2, sticky="w", pady=(10, 8))
        self.tx_text = tk.StringVar(value="No transfer submitted")
        ttk.Label(frame, textvariable=self.tx_text, wraplength=690).grid(row=8, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="A submitted transfer is pending until a miner includes it in a block.",
                  wraplength=690).grid(row=9, column=0, columnspan=2, sticky="w", pady=(12, 0))

    def build_mining(self, frame):
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text="Mine blocks", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Reward address").grid(row=1, column=0, sticky="w", pady=9)
        self.reward = tk.StringVar()
        ttk.Entry(frame, textvariable=self.reward).grid(row=1, column=1, sticky="ew")
        ttk.Button(frame, text="Use sender wallet", command=self.use_sender_reward).grid(row=2, column=1, sticky="w")
        ttk.Label(frame, text="Blocks to mine").grid(row=3, column=0, sticky="w", pady=10)
        self.block_count = tk.StringVar(value="1")
        ttk.Spinbox(frame, from_=1, to=100, textvariable=self.block_count, width=7).grid(row=3, column=1, sticky="w")
        actions = ttk.Frame(frame)
        actions.grid(row=4, column=0, columnspan=2, sticky="w", pady=12)
        self.start_button = ttk.Button(actions, text="Start mining", command=self.start_mining)
        self.start_button.pack(side="left", padx=(0, 8))
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop_mining, state="disabled")
        self.stop_button.pack(side="left")
        self.mining_text = tk.StringVar(value="Idle")
        ttk.Label(frame, textvariable=self.mining_text, wraplength=690).grid(row=5, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Mining runs on this computer's CPU. Rewards mature after the network's configured number of blocks.",
                  wraplength=690).grid(row=6, column=0, columnspan=2, sticky="w", pady=(15, 0))

    def work(self, action, success, failure=None):
        def runner():
            try:
                result = action()
                self.events.put(("callback", success, result))
            except Exception as exc:
                self.events.put(("error", str(exc), failure))
        threading.Thread(target=runner, daemon=True).start()

    def drain_events(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            kind = event[0]
            if kind == "callback":
                event[1](event[2])
            elif kind == "error":
                self.notice.set("Error: " + event[1])
                if event[2]:
                    event[2]()
            elif kind == "progress":
                height, attempts, rate = event[1]
                self.mining_text.set(f"Candidate #{height}: {attempts:,} hashes, about {rate:,} H/s")
            elif kind == "mined":
                done, height, block_hash = event[1]
                self.mining_text.set(f"Mined {done} block(s). Latest: #{height} {block_hash[:20]}...")
                self.refresh()
            elif kind == "info":
                self.mining_text.set(event[1])
            elif kind == "mining_done":
                self.mining_stop = None
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.notice.set(f"Mining stopped after {event[1]} block(s).")
            elif kind == "mining_error":
                self.mining_stop = None
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.notice.set("Mining error: " + event[1])
        self.root.after(100, self.drain_events)

    def ask_password(self, prompt, confirm=False):
        dialog = PasswordDialog(self.root, prompt, confirm)
        self.root.wait_window(dialog)
        return dialog.result

    def open_sender(self):
        if self.opening_wallet:
            return
        wallet_dir = Path("wallets").resolve()
        path = filedialog.askopenfilename(title="Choose wallet .pem file", initialdir=wallet_dir,
                                          filetypes=[("PEM wallets", "*.pem")], parent=self.root)
        if not path:
            return
        password = self.ask_password("Unlock this wallet for transfers:")
        if password is None:
            return
        self.load_sender(lambda: self.client.open_wallet(path, password), "Wallet opened. Ready to sign transfers.")

    def load_sender(self, action, message):
        self.opening_wallet = True
        self.open_button.configure(state="disabled")
        self.create_button.configure(state="disabled")
        self.send_button.configure(state="disabled")
        self.notice.set("Opening wallet...")
        def finished():
            self.opening_wallet = False
            self.open_button.configure(state="normal")
            self.create_button.configure(state="normal")
            self.send_button.configure(state="normal" if self.sender_wallet and not self.transfer_pending else "disabled")
        def opened(session):
            self.set_sender(session)
            finished()
            self.notice.set(message)
        self.work(action, opened, finished)

    def set_sender(self, session):
        path, who = str(session.path), session.address
        self.sender_wallet = session
        self.sender_file, self.sender_address = path, who
        self.balance_text.set("Balance: loading...")
        self.wallet_file_text.set(f"Wallet file: {path}")
        self.wallet_address_text.set(who)
        self.opened_wallets = [(p, a) for p, a in self.opened_wallets if p != path]
        self.opened_wallets.insert(0, (path, who))
        self.opened_wallets = self.opened_wallets[:4]
        self.render_opened_wallets()
        self.reward.set(who)
        self.refresh()

    def render_opened_wallets(self):
        for child in self.opened_wallets_frame.winfo_children():
            child.destroy()
        for path, who in self.opened_wallets:
            row = ttk.Frame(self.opened_wallets_frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=Path(path).name, width=18).pack(side="left")
            entry = ttk.Entry(row)
            entry.insert(0, who)
            entry.configure(state="readonly")
            entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
            menu = tk.Menu(entry, tearoff=False)
            menu.add_command(label="Copy address", command=lambda value=who: self.copy_address(value))
            entry.bind("<Button-3>", lambda event, popup=menu: popup.tk_popup(event.x_root, event.y_root))
            ttk.Button(row, text="Copy", command=lambda value=who: self.copy_address(value)).pack(side="left", padx=(0, 6))
            ttk.Button(row, text="Use as recipient", command=lambda value=who: self.recipient.set(value)).pack(side="left")

    def copy_address(self, who):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(who)
            self.notice.set("Wallet address copied. Share only this address to receive coins.")
        except tk.TclError:
            self.notice.set("Clipboard unavailable. Select the address and press Ctrl+C.")

    def copy_sender_address(self):
        if not self.sender_address:
            messagebox.showerror("Wallet address", "Open a wallet first.", parent=self.root)
            return
        self.copy_address(self.sender_address)

    def paste_recipient_address(self):
        try:
            recipient = self.root.clipboard_get().strip().lower()
            hexstr(recipient)
        except tk.TclError:
            messagebox.showerror("Clipboard", "No address is available on the clipboard.", parent=self.root)
            return
        except Invalid:
            messagebox.showerror("Recipient address", "Paste a 64-character PowCoin address.", parent=self.root)
            return
        self.recipient.set(recipient)

    def new_wallet(self):
        if self.opening_wallet:
            return
        path = filedialog.asksaveasfilename(title="Create encrypted wallet", initialdir=Path("wallets").resolve(),
                                            defaultextension=".pem",
                                            filetypes=[("PEM wallets", "*.pem")], parent=self.root)
        if not path:
            return
        if any(item.exists() for item in wallet.bundle_paths(path)):
            messagebox.showerror("Wallet exists", "A wallet, password, or address file already exists with that name. Choose a new filename.", parent=self.root)
            return
        password = self.ask_password("Create a password of at least 10 characters:", confirm=True)
        if password is None:
            return
        self.load_sender(lambda: self.client.create_wallet(path, password),
                         f"Created {Path(path).name}, {Path(path).stem}-password.txt, and {Path(path).stem}-address.txt. Wallet ready to use.")

    def refresh(self):
        self.refresh_generation += 1
        generation = self.refresh_generation
        sender = self.sender_address
        txid = self.last_txid
        def fetch():
            status = self.client.status()
            account = self.client.account(sender) if sender else None
            transaction = self.client.transaction(txid) if txid else None
            return status, account, transaction
        def show(result):
            if sender != self.sender_address or generation < self.last_refresh_applied:
                return
            self.last_refresh_applied = generation
            status, account, transaction = result
            reachable = sum(bool(p.get("reachable")) for p in status.get("peer_status", []))
            self.network_text.set(f"Height {status['height']}  |  Available nodes {1 + reachable}  |  Pending {status['pending']}")
            if account:
                symbol = self.client.config["symbol"]
                self.balance_text.set(f"Balance: {coins(account['balance'])} {symbol} spendable  |  Immature rewards: {coins(account['immature'])} {symbol}")
            if transaction and txid == self.last_txid:
                self.tx_text.set(f"TX {txid}  |  {transaction['status']}  |  {transaction['confirmations']} confirmation(s)")
        def failed():
            if sender != self.sender_address or generation < self.last_refresh_applied:
                return
            self.last_refresh_applied = generation
            self.network_text.set("Node unavailable; check VPN and node")
            if sender:
                self.balance_text.set("Balance unavailable: reconnect to the node to refresh")
        self.work(fetch, show, failed)

    def periodic_refresh(self):
        self.refresh()
        self.root.after(5000, self.periodic_refresh)

    def send(self):
        if self.transfer_pending or self.opening_wallet:
            return
        if not self.sender_wallet:
            messagebox.showerror("Sender wallet", "Open a sender wallet first.", parent=self.root)
            return
        session = self.sender_wallet
        try:
            recipient = self.recipient.get().strip().lower()
            hexstr(recipient)
            amount = units(self.amount.get())
            fee = units(self.fee.get(), allow_zero=True)
        except (ValueError, Invalid) as exc:
            messagebox.showerror("Transfer", str(exc), parent=self.root)
            return
        if not messagebox.askyesno("Review transfer",
                                   f"From: {session.address}\nSend {coins(amount)} PWN\nTo: {recipient}\nFee: {coins(fee)} PWN\n\nSign and submit?",
                                   parent=self.root):
            return
        if self.sender_wallet is not session:
            self.notice.set("Selected wallet changed. Review the transfer again.")
            return
        self.transfer_pending = True
        self.send_button.configure(state="disabled")
        self.notice.set("Signing locally and submitting transfer...")
        def done(txid):
            finished()
            self.last_txid = txid
            self.notice.set("Transfer submitted. It is pending until a block includes it.")
            self.refresh()
        def finished():
            self.transfer_pending = False
            self.send_button.configure(state="disabled" if self.opening_wallet else "normal")
        self.work(lambda: self.client.send(session, recipient, amount, fee), done, finished)

    def use_sender_reward(self):
        if self.sender_address:
            self.reward.set(self.sender_address)

    def start_mining(self):
        if self.mining_stop is not None:
            return
        try:
            reward_address = self.reward.get().strip().lower()
            hexstr(reward_address)
            count = int(self.block_count.get())
            if not 1 <= count <= 100:
                raise ValueError("Choose 1 to 100 blocks")
        except (ValueError, Invalid) as exc:
            messagebox.showerror("Mining", str(exc), parent=self.root)
            return
        stop = threading.Event()
        self.mining_stop = stop
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.mining_text.set("Preparing candidate block...")
        def runner():
            try:
                done = self.client.mine_blocks(
                    reward_address, count, stop,
                    lambda kind, payload: self.events.put((kind, payload)))
                self.events.put(("mining_done", done))
            except Exception as exc:
                self.events.put(("mining_error", str(exc)))
        self.mining_thread = threading.Thread(target=runner, daemon=True)
        self.mining_thread.start()

    def stop_mining(self):
        if self.mining_stop:
            self.mining_stop.set()
            self.mining_text.set("Stopping after the current hash batch...")

    def close(self):
        self.stop_mining()
        self.sender_wallet = None
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="PowCoin Wallet and Mining")
    parser.add_argument("--config", default="network.json")
    parser.add_argument("--node-url", default="http://127.0.0.1:8844")
    parser.add_argument("--token-file", default=".deploy/shared_token")
    args = parser.parse_args()
    root = tk.Tk()
    try:
        client = DemoClient(args.config, args.node_url, args.token_file)
    except Exception as exc:
        messagebox.showerror("PowCoin setup", str(exc), parent=root)
        root.destroy()
        return
    DemoApp(root, client)
    root.mainloop()


if __name__ == "__main__":
    main()
