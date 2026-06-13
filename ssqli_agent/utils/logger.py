"""
utils/logger.py — Hacker-style structured console logger for SQLSlayer

Neon-green terminal aesthetic with symbol-prefixed log levels:
    [*] info   [+] success   [!] warning   [-] error
    [X] critical   [>] scan    [!!] finding   [~] debug
"""
import sys
import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Survive a legacy Windows (cp1252) console so box-drawing chars don't crash.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── palette ──────────────────────────────────────────────────────────────────
G   = Fore.GREEN
GB  = Fore.GREEN + Style.BRIGHT
C   = Fore.CYAN
CB  = Fore.CYAN + Style.BRIGHT
Y   = Fore.YELLOW
YB  = Fore.YELLOW + Style.BRIGHT
R   = Fore.RED
RB  = Fore.RED + Style.BRIGHT
W   = Fore.WHITE
DIM = Style.DIM
RST = Style.RESET_ALL

# level → (colour, symbol)
LEVEL_STYLE = {
    "INFO":     (C,  "[*]"),
    "SUCCESS":  (GB, "[+]"),
    "WARNING":  (YB, "[!]"),
    "ERROR":    (R,  "[-]"),
    "CRITICAL": (RB, "[X]"),
    "SCAN":     (Fore.MAGENTA + Style.BRIGHT, "[>]"),
    "FINDING":  (RB, "[!!]"),
    "DEBUG":    (DIM + W, "[~]"),
}

_WIDTH = 74


class Logger:
    def __init__(self, name: str = "sqlslayer", verbose: bool = True):
        self.name = name
        self.verbose = verbose

    def _log(self, level: str, msg: str):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        color, sym = LEVEL_STYLE.get(level, (W, "[*]"))
        # e.g.  ┌ 18:42:01 [+] message
        print(f"{G}{DIM}┌{RST}{DIM}{ts}{RST} {color}{sym}{RST} {color}{msg}{RST}")
        sys.stdout.flush()

    def info(self, msg):     self._log("INFO", msg)
    def success(self, msg):  self._log("SUCCESS", msg)
    def warning(self, msg):  self._log("WARNING", msg)
    def error(self, msg):    self._log("ERROR", msg)
    def critical(self, msg): self._log("CRITICAL", msg)
    def scan(self, msg):     self._log("SCAN", msg)
    def finding(self, msg):  self._log("FINDING", msg)
    def debug(self, msg):
        if self.verbose:
            self._log("DEBUG", msg)

    # ── decorative blocks ─────────────────────────────────────────────────────
    def banner(self, title: str):
        top = "╔" + "═" * (_WIDTH - 2) + "╗"
        bot = "╚" + "═" * (_WIDTH - 2) + "╝"
        mid = "║ " + title.ljust(_WIDTH - 4) + " ║"
        print(f"\n{GB}{top}")
        print(mid)
        print(f"{bot}{RST}")

    def section(self, title: str):
        bar = "─" * (_WIDTH - len(title) - 5)
        print(f"\n{CB}┌──[{RST}{W}{title}{RST}{CB}]{bar}{RST}")

    def kv(self, key: str, value: str, ok: bool = True):
        """Aligned key : value status line."""
        mark = f"{GB}●{RST}" if ok else f"{R}○{RST}"
        print(f"  {mark} {DIM}{key:<20}{RST}{G}{value}{RST}")

    def raw(self, text: str):
        print(text)


logger = Logger()
