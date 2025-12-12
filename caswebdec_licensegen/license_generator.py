"""
Standalone License Generator for CASWebFinal
- Produces license tokens compatible with routes/license_utils.py
  (supports RSA signature mode or HMAC fallback using pbkdf2_hmac('sha256', ..., iterations=1))
- Small Tk GUI to generate licenses, include optional machine binding (hw_id),
  and keep a local generation history.

Notes:
- For asymmetric signing you need the vendor PRIVATE KEY (PEM). The app that validates
  will require the vendor PUBLIC KEY (LICENSE_PUBLIC_KEY_PEM or LICENSE_PUBLIC_KEY_PATH).
- For HMAC mode the validator expects LICENSE_SECRET_KEY to match the same secret.
- This tool stores a local license_history.json in the working directory.
- Install cryptography if you want RSA signing: pip install cryptography
"""
import json
import base64
import os
import hashlib
import hmac as _hmac
from datetime import datetime, timedelta, date
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import uuid
import platform
import logging

# Try import cryptography for asymmetric signing support
CRYPTO_AVAILABLE = False
try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# Default history filename (alongside this script)
HISTORY_FILE = "license_history.json"


def compute_machine_fingerprint():
    """
    Compute a conservative machine fingerprint which can be embedded in license hw_id.
    Matches the approach used by license_utils._compute_machine_fingerprint().
    Returns hex sha256 string.
    """
    parts = []
    try:
        mac = uuid.getnode()
        parts.append(str(mac))
    except Exception:
        pass
    try:
        parts.append(platform.node() or '')
    except Exception:
        pass
    try:
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id", "r") as f:
                parts.append(f.read().strip())
    except Exception:
        pass
    try:
        parts.append(os.environ.get("HOSTNAME", ""))
    except Exception:
        pass

    s = "|".join(p for p in parts if p)
    if not s:
        s = "unknown-machine"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _serialize_license_data(payload: dict) -> bytes:
    """Deterministic JSON bytes for signing/verifying (sorted keys, compact separators)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_with_hmac_pbkdf2(data_bytes: bytes, secret: str) -> bytes:
    """
    Produce signature using pbkdf2_hmac('sha256', data_bytes, secret, iterations=1)
    This matches the fallback expected by license_utils.py.
    """
    return hashlib.pbkdf2_hmac("sha256", data_bytes, secret.encode("utf-8"), 1)


def sign_with_rsa_private_key(data_bytes: bytes, private_key_pem: bytes, password: bytes = None) -> bytes:
    """
    Sign data_bytes with RSA private key (PKCS#1 v1.5 + SHA256).
    private_key_pem: PEM bytes of the private key (PEM-encoded)
    password: optional password bytes for encrypted key
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography is not available (pip install cryptography)")

    priv = serialization.load_pem_private_key(private_key_pem, password=password, backend=default_backend())
    sig = priv.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return sig


class LicenseGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CASWeb License Generator")
        self.root.geometry("980x720")
        self.root.resizable(True, True)

        self.history_file = HISTORY_FILE
        self.history = []
        self.load_history()

        # Optional: attempt to auto-generate keys directory on vendor machine.
        # We do NOT auto-generate by default; user must click "Generate Keys".
        self.setup_ui()

    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
            except Exception:
                self.history = []
        else:
            self.history = []

    def save_history(self):
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.exception("Failed to save history: %s", e)

    def ensure_keypair(self, keys_dir=None, private_name="vendor_private_key.pem",
                       public_name="vendor_public_key.pem", key_size=2048, prompt_encrypt=True):
        """
        Ensure an RSA keypair exists in keys_dir. If not present, generate it.

        Returns (private_path, public_path) or (None, None) on cancel/error.
        """
        if keys_dir is None:
            keys_dir = os.path.join(os.path.expanduser("~"), ".casweb_keys")
        try:
            os.makedirs(keys_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("IO Error", f"Failed to create keys directory {keys_dir}: {e}")
            return None, None

        private_path = os.path.join(keys_dir, private_name)
        public_path = os.path.join(keys_dir, public_name)

        # If both files already exist, just return paths
        if os.path.exists(private_path) and os.path.exists(public_path):
            return private_path, public_path

        if not CRYPTO_AVAILABLE:
            messagebox.showerror(
                "Missing Dependency",
                "cryptography library not available. Install it (pip install cryptography) to auto-generate RSA keys."
            )
            return None, None

        # Ask user for optional passphrase
        encrypt = False
        passphrase = None
        if prompt_encrypt:
            resp = simpledialog.askstring(
                "Encrypt Private Key?",
                "Enter a passphrase to protect the private key, or leave blank to keep unencrypted.\n\nCancel to abort key generation.",
                show="*",
                parent=self.root
            )
            if resp is None:
                return None, None
            resp = resp.strip()
            if resp != "":
                encrypt = True
                passphrase = resp

        # Generate RSA keypair
        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        except Exception as e:
            messagebox.showerror("Keygen Error", f"RSA key generation failed: {e}")
            return None, None

        try:
            if encrypt and passphrase:
                encryption_algo = BestAvailableEncryption(passphrase.encode("utf-8"))
            else:
                encryption_algo = NoEncryption()

            priv_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algo
            )

            pub_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            with open(private_path, "wb") as f:
                f.write(priv_pem)
            try:
                os.chmod(private_path, 0o600)
            except Exception:
                pass

            with open(public_path, "wb") as f:
                f.write(pub_pem)

            messagebox.showinfo("Keypair Created",
                                f"RSA keypair created:\n\nPrivate: {private_path}\nPublic:  {public_path}\n\n"
                                "Keep the private key secure. Distribute only the public key to client web apps.")
            return private_path, public_path

        except Exception as e:
            messagebox.showerror("Write Error", f"Failed to write key files: {e}")
            return None, None

    def setup_ui(self):
        # Top frame for generation controls
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.BOTH, expand=False)

        title = ttk.Label(top_frame, text="🔐 CASWeb License Generator", font=("Segoe UI", 16, "bold"))
        title.grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 8))

        # Client & company
        ttk.Label(top_frame, text="Client Name:").grid(row=1, column=0, sticky="e")
        self.client_entry = ttk.Entry(top_frame, width=30)
        self.client_entry.grid(row=1, column=1, sticky="w", padx=6)

        ttk.Label(top_frame, text="Company Name:").grid(row=1, column=2, sticky="e")
        self.company_entry = ttk.Entry(top_frame, width=30)
        self.company_entry.grid(row=1, column=3, sticky="w", padx=6)

        # Validity days
        ttk.Label(top_frame, text="Validity (days):").grid(row=2, column=0, sticky="e", pady=6)
        self.validity_spin = ttk.Spinbox(top_frame, from_=1, to=3650, width=10)
        self.validity_spin.set(365)
        self.validity_spin.grid(row=2, column=1, sticky="w", pady=6)

        # hw_id binding: compute or paste
        self.bind_hw_var = tk.BooleanVar(value=False)
        self.hw_check = ttk.Checkbutton(top_frame, text="Bind to Machine (include hw_id)", variable=self.bind_hw_var, command=self.on_hw_check)
        self.hw_check.grid(row=2, column=2, sticky="w", pady=6)

        self.hw_entry = ttk.Entry(top_frame, width=40)
        self.hw_entry.grid(row=2, column=3, sticky="w", padx=6)
        self.hw_entry.insert(0, "")  # empty by default

        hw_btn = ttk.Button(top_frame, text="Compute Local HW ID", command=self.compute_and_fill_hw)
        hw_btn.grid(row=3, column=3, sticky="e", padx=6)

        # Signature mode: RSA or HMAC
        ttk.Label(top_frame, text="Signature Mode:").grid(row=3, column=0, sticky="e")
        self.sig_mode = tk.StringVar(value="rsa" if CRYPTO_AVAILABLE else "hmac")
        self.rsa_radio = ttk.Radiobutton(top_frame, text="RSA (preferred)", variable=self.sig_mode, value="rsa", state=("normal" if CRYPTO_AVAILABLE else "disabled"))
        self.hmac_radio = ttk.Radiobutton(top_frame, text="HMAC (pbkdf2 fallback)", variable=self.sig_mode, value="hmac")
        self.rsa_radio.grid(row=3, column=1, sticky="w")
        self.hmac_radio.grid(row=3, column=2, sticky="w")

        # RSA key selection
        ttk.Label(top_frame, text="Private Key (PEM) path:").grid(row=4, column=0, sticky="e", pady=6)
        self.privkey_path = ttk.Entry(top_frame, width=40)
        self.privkey_path.grid(row=4, column=1, columnspan=2, sticky="w", padx=6)
        pk_btn = ttk.Button(top_frame, text="Browse...", command=self.browse_privkey)
        pk_btn.grid(row=4, column=3, sticky="w", padx=6)

        # Generate Keys button (new)
        gen_keys_btn = ttk.Button(top_frame, text="Generate Keys", command=self.generate_keys)
        gen_keys_btn.grid(row=4, column=4, sticky="w", padx=(8,0))

        # HMAC secret
        ttk.Label(top_frame, text="HMAC Secret (if using HMAC):").grid(row=5, column=0, sticky="e")
        self.hmac_secret = ttk.Entry(top_frame, width=40, show="*")
        self.hmac_secret.grid(row=5, column=1, columnspan=2, sticky="w", padx=6)
        # checkbox to show secret
        self.show_secret_var = tk.BooleanVar(value=False)
        show_secret_cb = ttk.Checkbutton(top_frame, text="Show", variable=self.show_secret_var, command=self.on_toggle_show_secret)
        show_secret_cb.grid(row=5, column=3, sticky="w")

        # Notes
        ttk.Label(top_frame, text="Notes (optional):").grid(row=6, column=0, sticky="ne")
        self.notes_text = tk.Text(top_frame, width=60, height=4)
        self.notes_text.grid(row=6, column=1, columnspan=3, sticky="w", pady=6)

        # Buttons
        btn_frame = ttk.Frame(top_frame)
        btn_frame.grid(row=7, column=0, columnspan=5, pady=(6, 12))

        generate_btn = ttk.Button(btn_frame, text="🔑 Generate License", command=self.generate_license)
        generate_btn.pack(side=tk.LEFT, padx=6)

        copy_btn = ttk.Button(btn_frame, text="📋 Copy License", command=self.copy_license_to_clipboard)
        copy_btn.pack(side=tk.LEFT, padx=6)

        clear_btn = ttk.Button(btn_frame, text="🧹 Clear Fields", command=self.clear_fields)
        clear_btn.pack(side=tk.LEFT, padx=6)

        # Middle: license output and details
        middle_frame = ttk.Frame(self.root, padding=10)
        middle_frame.pack(fill=tk.BOTH, expand=False)

        ttk.Label(middle_frame, text="Generated License Key:").pack(anchor="w")
        self.license_display = scrolledtext.ScrolledText(middle_frame, width=110, height=6, wrap=tk.WORD)
        self.license_display.pack(fill=tk.BOTH, expand=True, pady=6)

        # History panel
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.pack(fill=tk.BOTH, expand=True)

        history_label = ttk.Label(bottom_frame, text="License History")
        history_label.pack(anchor="w")

        columns = ("client", "company", "expires", "mode", "hwbound")
        self.history_tree = ttk.Treeview(bottom_frame, columns=columns, show="headings", height=10)
        for col, title in zip(columns, ("Client", "Company", "Expires", "Mode", "HW bound")):
            self.history_tree.heading(col, text=title)
            self.history_tree.column(col, width=140)
        self.history_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        vsb = ttk.Scrollbar(bottom_frame, orient="vertical", command=self.history_tree.yview)
        vsb.pack(side=tk.LEFT, fill=tk.Y)
        self.history_tree.configure(yscrollcommand=vsb.set)

        history_controls = ttk.Frame(bottom_frame)
        history_controls.pack(side=tk.LEFT, fill=tk.Y, padx=8)

        refresh_btn = ttk.Button(history_controls, text="🔄 Refresh", command=self.refresh_history)
        refresh_btn.pack(fill=tk.X, pady=4)
        save_btn = ttk.Button(history_controls, text="💾 Save History", command=self.save_history)
        save_btn.pack(fill=tk.X, pady=4)
        export_btn = ttk.Button(history_controls, text="📤 Export Selected", command=self.export_selected)
        export_btn.pack(fill=tk.X, pady=4)

        self.refresh_history()

    def generate_keys(self):
        """Handler for Generate Keys button - generate keypair and prefill private path."""
        # Ask user where to store keys (default to ~/.casweb_keys)
        default_dir = os.path.join(os.path.expanduser("~"), ".casweb_keys")
        target = filedialog.askdirectory(title="Select directory to create keys (will create ~/.casweb_keys if you choose Cancel)", initialdir=default_dir)
        if not target:
            target = default_dir
        priv, pub = self.ensure_keypair(keys_dir=target)
        if priv and pub:
            try:
                self.privkey_path.delete(0, tk.END)
                self.privkey_path.insert(0, priv)
                # switch to RSA mode if cryptography available
                if CRYPTO_AVAILABLE:
                    self.sig_mode.set("rsa")
                messagebox.showinfo("Keys Generated", f"Keys generated.\n\nPrivate: {priv}\nPublic: {pub}\n\nRemember: distribute only the public key to clients.")
            except Exception:
                pass

    def on_hw_check(self):
        if self.bind_hw_var.get():
            # If enabled and hw entry empty, compute local fingerprint for convenience
            if not self.hw_entry.get().strip():
                self.hw_entry.delete(0, tk.END)
                self.hw_entry.insert(0, compute_machine_fingerprint())
        else:
            # do not clear automatically; leave value so vendor may reuse
            pass

    def compute_and_fill_hw(self):
        fp = compute_machine_fingerprint()
        self.hw_entry.delete(0, tk.END)
        self.hw_entry.insert(0, fp)
        messagebox.showinfo("HW ID", f"Computed HW ID:\n{fp}\n\nYou can include this in the license to bind it to this machine.")

    def browse_privkey(self):
        p = filedialog.askopenfilename(title="Select Private Key PEM", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if p:
            self.privkey_path.delete(0, tk.END)
            self.privkey_path.insert(0, p)

    def on_toggle_show_secret(self):
        if self.show_secret_var.get():
            self.hmac_secret.config(show="")
        else:
            self.hmac_secret.config(show="*")

    def clear_fields(self):
        self.client_entry.delete(0, tk.END)
        self.company_entry.delete(0, tk.END)
        self.validity_spin.set(365)
        self.hw_entry.delete(0, tk.END)
        self.notes_text.delete("1.0", tk.END)
        self.license_display.delete("1.0", tk.END)
        self.hmac_secret.delete(0, tk.END)
        # do not clear priv key path

    def generate_license(self):
        client = self.client_entry.get().strip()
        company = self.company_entry.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        try:
            validity_days = int(self.validity_spin.get())
        except Exception:
            messagebox.showerror("Invalid Input", "Validity must be a number of days.")
            return

        if not client or not company:
            messagebox.showerror("Missing fields", "Client and Company are required.")
            return

        expires_date = (datetime.utcnow().date() + timedelta(days=validity_days)).isoformat()
        issued = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        payload = {
            "id": f"LIC-{int(datetime.utcnow().timestamp())}",
            "client": client,
            "company": company,
            "expires": expires_date,
            "issued": issued,
            "notes": notes
        }

        # optional hw binding
        hw_id = self.hw_entry.get().strip()
        if self.bind_hw_var.get() and hw_id:
            payload["hw_id"] = hw_id

        data_bytes = _serialize_license_data(payload)

        mode = self.sig_mode.get()
        signature = None

        try:
            if mode == "rsa":
                if not CRYPTO_AVAILABLE:
                    messagebox.showerror("Cryptography missing", "RSA mode requires the 'cryptography' package.")
                    return
                priv_path = self.privkey_path.get().strip()
                if not priv_path or not os.path.exists(priv_path):
                    messagebox.showerror("Missing private key", "Please select a valid PEM private key file.")
                    return
                # attempt to read private key; if encrypted, prompt for password
                with open(priv_path, "rb") as f:
                    pem = f.read()
                # try load without password
                try:
                    signature = sign_with_rsa_private_key(data_bytes, pem, password=None)
                except ValueError:
                    # Encrypted key; prompt for password
                    pw = self.ask_password("Private Key Password", "Enter password for private key (leave blank to cancel):")
                    if pw is None:
                        return
                    try:
                        signature = sign_with_rsa_private_key(data_bytes, pem, password=pw.encode("utf-8") if pw else None)
                    except Exception as e:
                        messagebox.showerror("Signing error", f"Failed to sign with private key: {e}")
                        return
            else:
                # HMAC fallback using pbkdf2_hmac iteration=1 to match license_utils
                secret = self.hmac_secret.get().strip()
                if not secret:
                    # as convenience, check env var
                    secret = os.environ.get("LICENSE_SECRET_KEY", "")
                if not secret:
                    messagebox.showerror("Missing secret", "HMAC secret required for HMAC mode (enter or set LICENSE_SECRET_KEY env var).")
                    return
                signature = sign_with_hmac_pbkdf2(data_bytes, secret)

        except Exception as e:
            logging.exception("Signing failed: %s", e)
            messagebox.showerror("Signing failed", f"An error occurred while signing: {e}")
            return

        package = base64.b64encode(data_bytes + b"::" + signature).decode("utf-8")

        # display and save to history
        self.license_display.delete("1.0", tk.END)
        self.license_display.insert("1.0", package)

        hist_entry = {
            "id": payload["id"],
            "client": client,
            "company": company,
            "expires": payload["expires"],
            "issued": payload["issued"],
            "mode": mode,
            "hw_bound": bool(payload.get("hw_id")),
            "notes": notes,
            "license_key": package,
            "created_at": datetime.utcnow().isoformat()
        }
        self.history.append(hist_entry)
        self.save_history()
        self.refresh_history()

        messagebox.showinfo("Success", f"License created. Expires: {payload['expires']}")

    def ask_password(self, title, prompt):
        """Simple password dialog (modal). Returns string or None if cancelled."""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text=prompt).pack(padx=12, pady=(12, 6))
        pw_var = tk.StringVar()
        entry = ttk.Entry(win, textvariable=pw_var, show="*")
        entry.pack(padx=12, pady=6)
        entry.focus_set()

        result = {"value": None}

        def on_ok():
            result["value"] = pw_var.get()
            win.destroy()

        def on_cancel():
            result["value"] = None
            win.destroy()

        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=(6, 12))
        ttk.Button(btn_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=6)

        self.root.wait_window(win)
        return result["value"]

    def copy_license_to_clipboard(self):
        token = self.license_display.get("1.0", tk.END).strip()
        if not token:
            messagebox.showwarning("No token", "No license to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(token)
        messagebox.showinfo("Copied", "License copied to clipboard.")

    def refresh_history(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        # show newest first
        for entry in reversed(self.history):
            hw = "Yes" if entry.get("hw_bound") else "No"
            mode = entry.get("mode", "hmac")
            self.history_tree.insert("", tk.END, values=(entry.get("client"), entry.get("company"), entry.get("expires"), mode, hw))

    def export_selected(self):
        sel = self.history_tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Please select a history row to export.")
            return
        idx = self.history_tree.index(sel[0])
        # reversed order mapping
        entry = list(reversed(self.history))[idx]
        # ask where to save
        path = filedialog.asksaveasfilename(title="Save License", defaultextension=".txt", filetypes=[("Text", ".txt"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(entry.get("license_key", ""))
            messagebox.showinfo("Exported", f"License exported to {path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = LicenseGeneratorApp(root)
    root.mainloop()