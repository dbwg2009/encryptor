import tkinter as tk
import hashlib
import hmac
import secrets
import sys
import math


sys.excepthook = lambda *a: None

# ── Palette
BG      = "#1a1a2e"
SURFACE = "#252540"
ACCENT  = "#6c63ff"
ACCENT2 = "#43c9a0"
WARN    = "#e05c5c"
FG      = "#e8e8f0"
FG_DIM  = "#7a7a99"

FONT    = ("Consolas", 11)
FONT_LG = ("Consolas", 13)
FONT_SM = ("Consolas", 10)


def _btn(parent, text, cmd, color=ACCENT, fg=FG, width=12, pad=6):
    return tk.Button(
        parent, text=text, command=cmd,
        bg=color, fg=fg, activebackground=color, activeforeground=fg,
        font=FONT, relief="flat", bd=0,
        padx=10, pady=pad, cursor="hand2", width=width
    )

def _lbl(parent, text, color=FG_DIM, size=10, bg=BG):
    return tk.Label(parent, text=text, bg=bg, fg=color, font=("Consolas", size))


# ── Core crypto
SALT_LEN   = 16
ITERATIONS = 200_000
KEY_LEN    = 32
DIGEST     = "sha256"

def _derive_keys(password: str, salt: bytes):
    km = hashlib.pbkdf2_hmac(DIGEST, password.encode(), salt, ITERATIONS, dklen=KEY_LEN * 2)
    return km[:KEY_LEN], km[KEY_LEN:]

def _keystream(enc_key: bytes, salt: bytes, length: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        stream += hashlib.sha256(enc_key + salt + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(stream[:length])

def encrypt(plaintext: str, password: str) -> str:
    try:
        data = plaintext.encode("utf-8")
        salt = secrets.token_bytes(SALT_LEN)
        enc_key, mac_key = _derive_keys(password, salt)
        ct  = bytes(b ^ k for b, k in zip(data, _keystream(enc_key, salt, len(data))))
        tag = hmac.new(mac_key, salt + ct, DIGEST).digest()
        return ":".join([salt.hex(), ct.hex(), tag.hex()])
    except Exception:
        return ""

def decrypt(token: str, password: str) -> str:
    try:
        parts = token.strip().split(":")
        if len(parts) != 3:
            return "[error: invalid format]"
        salt = bytes.fromhex(parts[0])
        ct   = bytes.fromhex(parts[1])
        tag  = bytes.fromhex(parts[2])
        enc_key, mac_key = _derive_keys(password, salt)
        if not hmac.compare_digest(tag, hmac.new(mac_key, salt + ct, DIGEST).digest()):
            return "[error: wrong key or message was tampered with]"
        return bytes(b ^ k for b, k in zip(ct, _keystream(enc_key, salt, len(ct)))).decode("utf-8", errors="replace")
    except Exception:
        return "[error: decryption failed]"


# ── Main Application
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.report_callback_exception = lambda *a: None

        try:
            self.title("ASCII Cipher — Secure")
            self.configure(bg=BG)
            self.resizable(True, True)
            self.minsize(600, 560)

            self._build()

            w, h = 780, 660
            x = (self.winfo_screenwidth()  - w) // 2
            y = (self.winfo_screenheight() - h) // 2
            self.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            pass

    def _build(self):
        try:
            # Title bar
            bar = tk.Frame(self, bg=SURFACE)
            bar.pack(fill="x")
            tk.Label(bar, text="  ASCII Cipher", bg=SURFACE, fg=FG,
                     font=("Consolas", 14, "bold")).pack(side="left", pady=8)
            tk.Label(bar, text="PBKDF2 · HMAC-SHA256  ",
                     bg=SURFACE, fg=FG_DIM, font=FONT_SM).pack(side="right")

            right = tk.Frame(self, bg=BG)
            right.pack(fill="both", expand=True)

            tk.Frame(right, bg=BG, height=14).pack()

            # Key row
            kr = tk.Frame(right, bg=BG)
            kr.pack(fill="x", padx=20, pady=(4, 0))
            _lbl(kr, "Key").pack(side="left", padx=(0, 8))
            self.key_var = tk.StringVar()
            self._key_entry = tk.Entry(
                kr, textvariable=self.key_var,
                bg=SURFACE, fg=FG, insertbackground=FG,
                font=FONT_LG, relief="flat", show="*"
            )
            self._key_entry.pack(side="left", fill="x", expand=True)
            self._show_key = False
            tk.Button(kr, text="show", command=self._toggle_key,
                      bg=SURFACE, fg=FG_DIM, relief="flat",
                      cursor="hand2").pack(side="left", padx=4)
            # ── NEW: copy key button
            tk.Button(kr, text="copy", command=self._copy_key,
                      bg=SURFACE, fg=FG_DIM, relief="flat",
                      cursor="hand2").pack(side="left", padx=(0, 4))

            # Entropy meter
            mr = tk.Frame(right, bg=BG)
            mr.pack(fill="x", padx=20, pady=(4, 0))
            _lbl(mr, "Key strength:").pack(side="left")
            self.strength_var = tk.StringVar(value="—")
            self.strength_lbl = tk.Label(mr, textvariable=self.strength_var,
                                         bg=BG, fg=FG_DIM, font=FONT_SM)
            self.strength_lbl.pack(side="left", padx=6)
            self.key_var.trace_add("write", self._update_strength)

            tk.Frame(right, bg=BG, height=12).pack()

            # Input
            _lbl(right, "Input").pack(anchor="w", padx=20)
            iw, self.input_txt = self._textbox(right, 5)
            iw.pack(fill="both", expand=True, padx=20)

            tk.Frame(right, bg=BG, height=8).pack()

            # Action buttons
            br = tk.Frame(right, bg=BG)
            br.pack(padx=20, fill="x")
            _btn(br, "Encrypt", self._encrypt).pack(side="left", padx=4)
            _btn(br, "Decrypt", self._decrypt, color=ACCENT2).pack(side="left", padx=4)
            _btn(br, "Swap",    self._swap,    color=SURFACE, width=8).pack(side="left", padx=4)
            _btn(br, "Clear",   self._clear,   color=SURFACE, width=8).pack(side="left", padx=4)
            self.status_var = tk.StringVar(value="")
            self.status_lbl = tk.Label(br, textvariable=self.status_var,
                                       bg=BG, fg=ACCENT2, font=FONT_SM)
            self.status_lbl.pack(side="right")

            tk.Frame(right, bg=BG, height=8).pack()

            # Output
            _lbl(right, "Output").pack(anchor="w", padx=20)
            ow, self.output_txt = self._textbox(right, 5)
            ow.pack(fill="both", expand=True, padx=20)

            tk.Frame(right, bg=BG, height=8).pack()
            _btn(right, "Copy output", self._copy, color=SURFACE, width=12)\
                .pack(anchor="w", padx=20, pady=(0, 10))
        except Exception:
            pass

    # ── Helpers

    def _textbox(self, parent, height=5):
        frame = tk.Frame(parent, bg=SURFACE, padx=2, pady=2)
        txt = tk.Text(frame, height=height, bg=SURFACE, fg=FG,
                      insertbackground=FG, font=FONT_LG,
                      relief="flat", wrap="word",
                      selectbackground=ACCENT, selectforeground=FG)
        sb = tk.Scrollbar(frame, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        return frame, txt

    def _update_strength(self, *_):
        try:
            pw = self.key_var.get()
            if not pw:
                self.strength_var.set("—"); self.strength_lbl.configure(fg=FG_DIM); return
            h_lo = any(c.islower() for c in pw)
            h_up = any(c.isupper() for c in pw)
            h_di = any(c.isdigit() for c in pw)
            h_sy = any(not c.isalnum() for c in pw)
            pool = max(sum([26*h_lo, 26*h_up, 10*h_di, 32*h_sy]), 26)
            bits = len(pw) * math.log2(pool)
            if bits < 40:    label, color = f"Weak ({bits:.0f} bits)",   WARN
            elif bits < 72:  label, color = f"Fair ({bits:.0f} bits)",   "#e0a030"
            elif bits < 100: label, color = f"Good ({bits:.0f} bits)",   ACCENT2
            else:            label, color = f"Strong ({bits:.0f} bits)", ACCENT2
            self.strength_var.set(label); self.strength_lbl.configure(fg=color)
        except Exception:
            pass

    def _read(self, w):
        try:    return w.get("1.0", "end-1c")
        except: return ""

    def _write(self, w, text):
        try:    w.delete("1.0", "end"); w.insert("1.0", text)
        except: pass

    def _set_status(self, text, color=ACCENT2):
        try:    self.status_var.set(text); self.status_lbl.configure(fg=color)
        except: pass

    def _get_key(self):
        try:    k = self.key_var.get().strip(); return k if k else None
        except: return None

    def _toggle_key(self):
        try:
            self._show_key = not self._show_key
            self._key_entry.configure(show="" if self._show_key else "*")
        except: pass

    # ── NEW: copy key to clipboard
    def _copy_key(self):
        try:
            key = self.key_var.get()
            if key:
                self.clipboard_clear()
                self.clipboard_append(key)
                self._set_status("key copied ✓")
            else:
                self._set_status("no key to copy", WARN)
        except: pass

    # ── Cipher actions

    def _encrypt(self):
        try:
            key = self._get_key()
            if not key: self._set_status("enter a key first", WARN); return
            self._set_status("encrypting…", FG_DIM); self.update_idletasks()
            self._write(self.output_txt, encrypt(self._read(self.input_txt), key))
            self._set_status("encrypted ✓")
        except: pass

    def _decrypt(self):
        try:
            key = self._get_key()
            if not key: self._set_status("enter a key first", WARN); return
            self._set_status("decrypting…", FG_DIM); self.update_idletasks()
            result = decrypt(self._read(self.input_txt), key)
            if result.startswith("[error:"):
                self._write(self.output_txt, ""); self._set_status(result, WARN)
            else:
                self._write(self.output_txt, result); self._set_status("decrypted ✓")
        except: pass

    def _swap(self):
        try:
            i, o = self._read(self.input_txt), self._read(self.output_txt)
            self._write(self.input_txt, o); self._write(self.output_txt, i)
            self._set_status("swapped")
        except: pass

    def _clear(self):
        try:
            self._write(self.input_txt, ""); self._write(self.output_txt, "")
            self._set_status("")
        except: pass

    def _copy(self):
        try:
            text = self._read(self.output_txt)
            if text:
                self.clipboard_clear(); self.clipboard_append(text)
                self._set_status("copied ✓")
        except: pass


# ── Entry point
if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception:
        pass
