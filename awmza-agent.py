#!/usr/bin/env python3
"""AWMZA Security endpoint agent - Windows, macOS, Linux.

Only the Python standard library (Python 3.8+). Run as Administrator / root.

  install --token TOKEN [--server URL]   register this computer and start the service
  run                                    the monitoring loop (the service runs this)
  service                                re-create the service after an update (keeps the device)
  status                                 show what the agent knows
  isolate | release                      cut / restore the network by hand (emergency use)
  uninstall                              stop, release isolation, remove canary files and the service

What it watches (no file content ever leaves the computer):
  - processes: ransomware precursors (shadow copy / backup deletion, recovery disabled),
    reverse shells, crypto miners, script-based droppers
  - files in the users' Documents, Desktop, Pictures, Downloads: decoy "canary" files,
    mass changes, files that turned into encrypted-looking data, ransomware extensions, ransom notes
  - new executables in Downloads / Desktop / temp: MD5 + SHA-256 compared with the
    ClamAV malware hash list on the AWMZA server (only the hash and size are sent)
  - privilege changes: new members of the administrators / sudo / wheel groups
  - inventory: OS, firewall, disk encryption, antivirus, listening ports
Isolation uses the OS firewall (nftables/iptables, pf, Windows Firewall); only the AWMZA server stays reachable.
"""
from __future__ import annotations

import argparse, glob, hashlib, http.client, ipaddress, json, math, os, platform, re, secrets
import shutil, socket, ssl, subprocess, sys, time, urllib.parse

VERSION = "1.1.0"
DEFAULT_SERVER = "https://security.awmza.com"
SYSTEM = platform.system().lower()  # linux | darwin | windows
IS_WIN, IS_MAC = SYSTEM == "windows", SYSTEM == "darwin"

if IS_WIN:
    HOME_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "AWMZA")
elif IS_MAC:
    HOME_DIR = "/Library/Application Support/AWMZA"
else:
    HOME_DIR = "/opt/awmza-agent"
STATE = os.path.join(HOME_DIR, "state.json")
LOG = os.path.join(HOME_DIR, "agent.log")
INSTALLED_SCRIPT = os.path.join(HOME_DIR, "awmza-agent.py")
# FROZEN: built with PyInstaller (Windows setup .exe, macOS / Linux binary) - no Python needed.
# On Windows the setup puts it in Program Files; elsewhere it copies itself to HOME_DIR.
FROZEN = bool(getattr(sys, "frozen", False))
INSTALLED_BIN = sys.executable if IS_WIN else os.path.join(HOME_DIR, "awmza-agent")

HEARTBEAT_EVERY = 60
PROC_EVERY = 15 if IS_WIN else 10
FILE_EVERY = 30
INVENTORY_EVERY = 900
MAX_FILES = 40000
MAX_DEPTH = 7
CANARY_NAMES = ["!AWMZA-canary-do-not-open.docx", "zz-AWMZA-canary-do-not-open.xlsx"]
USER_DIRS = ["Documents", "Desktop", "Pictures", "Downloads"]

RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".crypted", ".cry", ".lockbit", ".ryk", ".ryuk", ".conti",
              ".akira", ".blackcat", ".royal", ".basta", ".hive", ".phobos", ".dharma", ".wncry", ".wnry",
              ".wcry", ".cerber", ".locky", ".zepto", ".stop", ".djvu", ".makop", ".medusa", ".rhysida",
              ".play", ".8base", ".clop", ".cl0p", ".babuk", ".mallox", ".enc1", ".lockfile", ".pay2key"}
RANSOM_NOTE = re.compile(r"(readme.*(decrypt|restore|recover|lock)|how[_\- ]?to[_\- ]?(decrypt|restore|recover|back)|"
                         r"decrypt[_\- ]?(files|instructions|info)|restore[_\- ]?(my[_\- ]?)?files|recover[_\- ]?files|"
                         r"_readme\.txt$|!!!.*(read|files).*\.(txt|html?)$|your[_\- ]?files[_\- ]?are[_\- ]?encrypted|"
                         r"ransom|\.hta$)", re.I)
MAGIC = {".pdf": [b"%PDF"], ".docx": [b"PK"], ".xlsx": [b"PK"], ".pptx": [b"PK"], ".zip": [b"PK"], ".odt": [b"PK"],
         ".png": [b"\x89PNG"], ".jpg": [b"\xff\xd8"], ".jpeg": [b"\xff\xd8"], ".gif": [b"GIF8"],
         ".doc": [b"\xd0\xcf\x11\xe0"], ".xls": [b"\xd0\xcf\x11\xe0"], ".ppt": [b"\xd0\xcf\x11\xe0"],
         ".mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"], ".bmp": [b"BM"], ".rtf": [b"{\\rtf"],
         ".psd": [b"8BPS"], ".sqlite": [b"SQLite format 3"], ".db": [b"SQLite format 3"]}
COMPRESSED = {".zip", ".gz", ".7z", ".rar", ".xz", ".bz2", ".zst", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4",
              ".mkv", ".mov", ".avi", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".heic", ".docx", ".xlsx", ".pptx",
              ".odt", ".ods", ".pdf", ".jar", ".apk", ".dmg", ".iso", ".pkg", ".msi", ".gpg", ".pgp", ".age", ".kdbx",
              ".enc", ".aes", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".crdownload", ".part", ".tmp"}
EXEC_EXT = {".exe", ".dll", ".scr", ".msi", ".com", ".pif", ".cpl", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".sh", ".py", ".elf", ".bin", ".run", ".app", ".dmg",
            ".pkg", ".command", ".iso", ".img", ".docm", ".xlsm", ".one"}
EXEC_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"#!")

PRECURSOR = [
    (re.compile(r"vssadmin(\.exe)?\s+.*delete\s+shadows", re.I), "Deletes Windows shadow copies (vssadmin)"),
    (re.compile(r"vssadmin(\.exe)?\s+.*resize\s+shadowstorage", re.I), "Shrinks shadow copy storage (vssadmin)"),
    (re.compile(r"wmic(\.exe)?\s+.*shadowcopy\s+.*delete", re.I), "Deletes shadow copies (wmic)"),
    (re.compile(r"win32_shadowcopy.*(delete|remove)", re.I), "Deletes shadow copies (PowerShell/WMI)"),
    (re.compile(r"wbadmin(\.exe)?\s+.*delete\s+(catalog|systemstatebackup|backup)", re.I), "Deletes the Windows backup catalog (wbadmin)"),
    (re.compile(r"bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.I), "Disables Windows recovery (bcdedit)"),
    (re.compile(r"diskshadow.*delete\s+shadows", re.I), "Deletes shadow copies (diskshadow)"),
    (re.compile(r"cipher(\.exe)?\s+/w:", re.I), "Wipes free disk space (cipher /w)"),
    (re.compile(r"set-mppreference\s+.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection)\s+\$?true", re.I), "Turns off Microsoft Defender protection"),
    (re.compile(r"tmutil\s+(delete|disable)", re.I), "Deletes or disables Time Machine backups (tmutil)"),
    (re.compile(r"(btrfs\s+subvolume\s+delete|zfs\s+destroy|lvremove).*snap", re.I), "Deletes filesystem snapshots"),
]
SUSPICIOUS = [
    (re.compile(r"(powershell|pwsh)(\.exe)?\s.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{80,}", re.I), "PowerShell running a long encoded command"),
    (re.compile(r"(powershell|pwsh)(\.exe)?\s.*(iex|invoke-expression).*(downloadstring|invoke-webrequest|iwr|net\.webclient)", re.I), "PowerShell downloading and running code"),
    (re.compile(r"mshta(\.exe)?\s+.*(https?:|javascript:|vbscript:)", re.I), "mshta running remote / inline script"),
    (re.compile(r"regsvr32(\.exe)?\s+.*/i:\s*https?:", re.I), "regsvr32 loading a remote scriptlet"),
    (re.compile(r"certutil(\.exe)?\s+.*-urlcache.*https?:", re.I), "certutil used to download a file"),
    (re.compile(r"rundll32(\.exe)?\s+.*javascript:", re.I), "rundll32 running JavaScript"),
    (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.I), "Reverse shell (bash /dev/tcp)"),
    (re.compile(r"\b(nc|ncat|netcat)\b.*\s-e\s+/bin/(ba)?sh", re.I), "Reverse shell (netcat -e)"),
    (re.compile(r"python[0-9.]*\s+-c\s+.*socket.*(pty\.spawn|subprocess|os\.dup2)", re.I), "Reverse shell (python)"),
    (re.compile(r"socat\s+.*exec:.*(sh|bash)", re.I), "Reverse shell (socat)"),
    (re.compile(r"(xmrig|minerd|cpuminer|xmr-stak|nbminer|t-rex|lolminer)|stratum\+(tcp|ssl)://|--donate-level", re.I), "Cryptocurrency miner"),
    (re.compile(r"(curl|wget)\s+[^|;]*https?://\d{1,3}(\.\d{1,3}){3}[^|;]*\|\s*(ba)?sh", re.I), "Script piped to shell from a raw IP address"),
    (re.compile(r"^/(dev/shm|tmp|var/tmp)/\.[^/\s]+", re.I), "Program running from a hidden file in a temp folder"),
    (re.compile(r"(mimikatz|sekurlsa::|lsadump::|procdump(64)?(\.exe)?\s+.*lsass|comsvcs\.dll.*minidump)", re.I), "Credential dumping"),
    (re.compile(r"(vssadmin|ntdsutil)(\.exe)?\s+.*(create\s+shadow|ifm).*", re.I), "Copying the Active Directory / SAM database"),
]


# ------------------------------------------------------------------ helpers
def log(msg: str) -> None:
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > 5_000_000:
            os.replace(LOG, LOG + ".1")
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    if sys.stdout and sys.stdout.isatty():
        print(line)


def sh(cmd, timeout: int = 30) -> tuple[int, str]:
    try:
        kw = {"creationflags": 0x08000000} if IS_WIN else {}
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", **kw)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def load_state() -> dict:
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(st: dict) -> None:
    os.makedirs(HOME_DIR, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    if not IS_WIN:
        os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)


def lock_down_home() -> None:
    """Only root / SYSTEM + Administrators may read the device key."""
    os.makedirs(HOME_DIR, exist_ok=True)
    if IS_WIN:
        sh(["icacls", HOME_DIR, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
    else:
        os.chmod(HOME_DIR, 0o700)


def is_admin() -> bool:
    if IS_WIN:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


# ------------------------------------------------------------------ server API (IP pinned, so it works while isolated)
class Api:
    def __init__(self, st: dict):
        self.st = st
        u = urllib.parse.urlparse(st.get("server") or DEFAULT_SERVER)
        if u.scheme != "https":
            raise SystemExit("server must use https")
        self.host, self.port = u.hostname, u.port or 443
        self.ctx = ssl.create_default_context()

    def server_ips(self, refresh: bool = False) -> list:
        if refresh or not self.st.get("server_ips"):
            try:
                ips = sorted({a[4][0] for a in socket.getaddrinfo(self.host, self.port, proto=socket.IPPROTO_TCP)})
                if ips:
                    self.st["server_ips"] = ips
            except OSError:
                pass
        return self.st.get("server_ips") or []

    def call(self, path: str, body=None, auth: bool = True, timeout: int = 30) -> dict:
        headers = {"Content-Type": "application/json", "User-Agent": "awmza-agent/" + VERSION, "Host": self.host}
        if auth:
            headers["X-Device-Id"] = self.st["device_id"]
            headers["X-Device-Key"] = self.st["device_key"]
        data = json.dumps(body if body is not None else {}).encode()
        last = None
        # normal DNS first, then the pinned addresses; while isolated DNS is blocked, so pinned only
        targets = self.server_ips() if self.st.get("isolated") else [None] + self.server_ips()
        for ip in targets:
            try:
                conn = http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.ctx)
                if ip:
                    sock = socket.create_connection((ip, self.port), timeout)
                    conn.sock = self.ctx.wrap_socket(sock, server_hostname=self.host)
                conn.request("POST", path, body=data, headers=headers)
                r = conn.getresponse()
                raw = r.read(2_000_000)
                conn.close()
                out = json.loads(raw or b"{}")
                if r.status >= 400:
                    raise ApiError(r.status, out.get("detail", "") if isinstance(out, dict) else "")
                return out
            except ApiError:
                raise
            except (OSError, ValueError, http.client.HTTPException) as e:
                last = e
        raise ConnectionError(str(last))


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(f"{status} {detail}")
        self.status, self.detail = status, detail


# ------------------------------------------------------------------ inventory
def admins() -> list:
    out = set()
    if IS_WIN:
        rc, txt = sh(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }"])
        if rc == 0:
            out |= {l.strip() for l in txt.splitlines() if l.strip()}
        else:
            rc, txt = sh(["net", "localgroup", "Administrators"])
            lines = txt.splitlines()
            try:
                start = next(i for i, l in enumerate(lines) if l.startswith("---")) + 1
                out |= {l.strip() for l in lines[start:] if l.strip() and not l.lower().startswith("the command")}
            except StopIteration:
                pass
    elif IS_MAC:
        rc, txt = sh(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        out |= set(txt.replace("GroupMembership:", "").split())
    else:
        try:
            with open("/etc/group", encoding="utf-8") as f:
                for line in f:
                    p = line.strip().split(":")
                    if len(p) >= 4 and p[0] in ("sudo", "wheel", "admin") and p[3]:
                        out |= set(p[3].split(","))
            with open("/etc/passwd", encoding="utf-8") as f:
                for line in f:
                    p = line.split(":")
                    if len(p) > 3 and p[2] == "0":
                        out.add(p[0])
        except OSError:
            pass
        for path in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s+ALL\s*=", line)
                        if m and m.group(1) not in ("root", "Defaults"):
                            out.add(m.group(1))
            except OSError:
                pass
    return sorted(out)[:100]


def listening_ports() -> list:
    ports = set()
    if SYSTEM == "linux":
        for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(fn) as f:
                    next(f)
                    for line in f:
                        p = line.split()
                        addr, port = p[1].rsplit(":", 1)
                        if p[3] == "0A" and addr not in ("0100007F", "00000000000000000000000001000000"):
                            ports.add(int(port, 16))
            except (OSError, StopIteration, ValueError, IndexError):
                pass
    else:
        rc, txt = sh(["netstat", "-ano", "-p", "TCP"] if IS_WIN else ["netstat", "-an", "-p", "tcp"])
        for line in txt.splitlines():
            parts = line.split()
            if "LISTEN" not in line.upper() or len(parts) < 4:
                continue
            local = parts[1] if IS_WIN else parts[3]
            m = re.search(r"[.:](\d+)$", local)
            if m and not local.startswith(("127.", "[::1]", "::1")):
                ports.add(int(m.group(1)))
    return ["tcp/" + str(p) for p in sorted(ports)][:60]


def firewall() -> dict:
    if IS_WIN:
        rc, txt = sh(["netsh", "advfirewall", "show", "allprofiles", "state"])
        on = [l for l in txt.splitlines() if re.search(r"^\s*State\s+ON", l, re.I)]
        off = [l for l in txt.splitlines() if re.search(r"^\s*State\s+OFF", l, re.I)]
        return {"enabled": bool(on) and not off, "detail": f"{len(on)} profile(s) on, {len(off)} off"}
    if IS_MAC:
        rc, txt = sh(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        return {"enabled": "enabled" in txt.lower(), "detail": txt.strip()[:120]}
    if shutil.which("ufw"):
        rc, txt = sh(["ufw", "status"])
        if "active" in txt.lower():
            return {"enabled": "inactive" not in txt.lower(), "detail": "ufw " + txt.splitlines()[0][:80] if txt else "ufw"}
    if shutil.which("firewall-cmd"):
        rc, txt = sh(["firewall-cmd", "--state"])
        return {"enabled": txt.strip() == "running", "detail": "firewalld " + txt.strip()[:40]}
    if shutil.which("nft"):
        rc, txt = sh(["nft", "list", "ruleset"])
        return {"enabled": "hook input" in txt and ("policy drop" in txt or " drop" in txt), "detail": "nftables"}
    if shutil.which("iptables"):
        rc, txt = sh(["iptables", "-S", "INPUT"])
        return {"enabled": "-P INPUT DROP" in txt or "-j DROP" in txt or "-j REJECT" in txt, "detail": "iptables"}
    return {"enabled": False, "detail": "no firewall tool found"}


def disk_encryption() -> dict:
    if IS_WIN:
        rc, txt = sh(["manage-bde", "-status", os.environ.get("SystemDrive", "C:")])
        on = bool(re.search(r"Protection Status:\s*Protection On", txt, re.I))
        return {"enabled": on, "detail": "BitLocker " + ("on" if on else "off or unknown")}
    if IS_MAC:
        rc, txt = sh(["fdesetup", "status"])
        return {"enabled": "is on" in txt.lower(), "detail": txt.strip()[:80]}
    rc, txt = sh(["lsblk", "-o", "TYPE,MOUNTPOINT", "-n", "-l"])
    crypt = "crypt" in txt
    return {"enabled": crypt, "detail": "LUKS/dm-crypt " + ("found" if crypt else "not found")}


def antivirus() -> dict:
    if IS_WIN:
        rc, txt = sh(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json"])
        try:
            d = json.loads(txt)
            return {"enabled": bool(d.get("AntivirusEnabled") and d.get("RealTimeProtectionEnabled")),
                    "detail": f"Microsoft Defender, signatures {d.get('AntivirusSignatureAge')} day(s) old"}
        except ValueError:
            rc, txt = sh(["powershell", "-NoProfile", "-Command",
                          "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName"])
            names = [l.strip() for l in txt.splitlines() if l.strip()]
            return {"enabled": bool(names), "detail": ", ".join(names)[:120] or "none reported"}
    if IS_MAC:
        rc, txt = sh(["spctl", "--status"])
        return {"enabled": "enabled" in txt, "detail": "Gatekeeper " + txt.strip()[:40] + " / XProtect built in"}
    found = [n for n in ("clamd", "clamscan", "freshclam", "mdatp", "sophos", "falcon-sensor") if shutil.which(n)]
    return {"enabled": bool(found), "detail": ", ".join(found) or "no antivirus found"}


def inventory(st: dict) -> dict:
    boot = None
    try:
        if SYSTEM == "linux":
            with open("/proc/uptime") as f:
                boot = int(time.time() - float(f.read().split()[0]))
    except OSError:
        pass
    return {"hostname": socket.gethostname()[:120], "os": SYSTEM, "os_version": platform.platform()[:200],
            "arch": platform.machine(), "python": platform.python_version(), "boot_time": boot,
            "admins": admins(), "listening": listening_ports(), "firewall": firewall(),
            "disk_encryption": disk_encryption(), "antivirus": antivirus(),
            "watched_dirs": len(watch_roots()), "canaries": len(st.get("canaries", [])),
            "collected_at": int(time.time())}


# ------------------------------------------------------------------ processes
def processes() -> list:
    out = []
    if SYSTEM == "linux":
        for d in os.listdir("/proc"):
            if d.isdigit():
                try:
                    with open(f"/proc/{d}/cmdline", "rb") as f:
                        cmd = f.read(4000).replace(b"\0", b" ").decode("utf-8", "replace").strip()
                    if cmd:
                        out.append((int(d), cmd))
                except OSError:
                    pass
    elif IS_MAC:
        rc, txt = sh(["ps", "-axww", "-o", "pid=,command="])
        for line in txt.splitlines():
            p = line.strip().split(None, 1)
            if len(p) == 2 and p[0].isdigit():
                out.append((int(p[0]), p[1][:4000]))
    else:
        rc, txt = sh(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"], timeout=40)
        try:
            for p in json.loads(txt or "[]"):
                if p.get("CommandLine"):
                    out.append((int(p["ProcessId"]), p["CommandLine"][:4000]))
        except (ValueError, TypeError):
            pass
    return out


def check_processes(seen: dict) -> list:
    events, now = [], time.time()
    me = os.getpid()
    for pid, cmd in processes():
        if pid == me or "awmza-agent" in cmd:
            continue
        for rules, kind, sev in ((PRECURSOR, "ransomware_precursor", "critical"), (SUSPICIOUS, "suspicious_process", "high")):
            for rx, why in rules:
                if rx.search(cmd):
                    key = f"{pid}:{why}"
                    if key not in seen:
                        seen[key] = now
                        events.append({"kind": kind, "severity": sev, "detail": f"{why}. PID {pid}: {cmd[:600]}", "files": []})
                    break
            else:
                continue
            break
    for k in [k for k, t in seen.items() if now - t > 86400]:
        seen.pop(k, None)
    return events


# ------------------------------------------------------------------ files
def user_homes() -> list:
    if IS_WIN:
        base = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "Users")
        skip = {"public", "default", "default user", "all users"}
    elif IS_MAC:
        base, skip = "/Users", {"shared", "guest"}
    else:
        base, skip = "/home", set()
    homes = []
    try:
        for n in os.listdir(base):
            p = os.path.join(base, n)
            if n.lower() not in skip and not n.startswith(".") and os.path.isdir(p):
                homes.append(p)
    except OSError:
        pass
    if not IS_WIN and os.path.isdir("/root"):
        homes.append("/root")
    return homes


def watch_roots() -> list:
    roots = []
    for h in user_homes():
        for d in USER_DIRS:
            p = os.path.join(h, d)
            if os.path.isdir(p):
                roots.append(p)
        od = glob.glob(os.path.join(h, "OneDrive*"))
        roots += [p for p in od if os.path.isdir(p)][:2]
    return roots[:40]


def temp_roots() -> list:
    if IS_WIN:
        r = [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")]
        r += [os.path.join(h, "AppData", "Local", "Temp") for h in user_homes()]
    else:
        r = ["/tmp", "/var/tmp", "/dev/shm"]
    return [p for p in r if os.path.isdir(p)]


def snapshot(roots: list, depth: int = MAX_DEPTH, limit: int = MAX_FILES) -> dict:
    snap, stack = {}, [(r, 0) for r in roots]
    while stack and len(snap) < limit:
        d, lvl = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir():
                            if lvl < depth and not e.name.startswith((".", "node_modules", "$")) and e.name not in ("AppData", "Library"):
                                stack.append((e.path, lvl + 1))
                        elif e.is_file():
                            s = e.stat()
                            snap[e.path] = (int(s.st_mtime), s.st_size)
                            if len(snap) >= limit:
                                break
                    except OSError:
                        continue
        except OSError:
            continue
    return snap


def looks_encrypted(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
    except OSError:
        return False
    if len(head) < 1024:
        return False
    if ext in MAGIC:
        if any(head.startswith(m) for m in MAGIC[ext]):
            return False
        return entropy(head[:16384]) > 7.2
    if ext in COMPRESSED:
        return False
    return entropy(head[:16384]) > 7.6


def file_hashes(path: str):
    try:
        if os.path.getsize(path) > 60_000_000:
            return None
        md5, sha1, sha = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha.update(chunk)
        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha.hexdigest(),
                "size": os.path.getsize(path), "path": path[:400]}
    except OSError:
        return None


def ransom_named(path: str) -> bool:
    """file.locked, or a document that got a random extra extension (report.docx.a7f3k2)."""
    stem, ext = os.path.splitext(path.lower())
    if ext in RANSOM_EXT:
        return True
    inner = os.path.splitext(stem)[1]
    return inner in MAGIC and bool(re.fullmatch(r"\.[a-z0-9_\-]{5,12}", ext)) and ext not in MAGIC and ext not in COMPRESSED


def is_executable(path: str) -> bool:
    if os.path.splitext(path)[1].lower() in EXEC_EXT:
        return True
    try:
        with open(path, "rb") as f:
            return f.read(4).startswith(EXEC_MAGIC)
    except OSError:
        return False


def plant_canaries(st: dict) -> None:
    out = []
    for root in watch_roots():
        if os.path.basename(root) == "Downloads":
            continue
        for name in CANARY_NAMES:
            p = os.path.join(root, name)
            try:
                if not os.path.exists(p):
                    # a real (tiny) zip header so it looks like an office file, then random data
                    with open(p, "wb") as f:
                        f.write(b"PK\x03\x04" + b"AWMZA canary - deleting or changing this file raises a ransomware alert. "
                                + secrets.token_bytes(4096))
                with open(p, "rb") as f:
                    out.append({"path": p, "sha256": hashlib.sha256(f.read()).hexdigest()})
                if IS_WIN:
                    sh(["attrib", "+R", p])
            except OSError:
                continue
    st["canaries"] = out


def remove_canaries(st: dict) -> None:
    for c in st.get("canaries", []):
        try:
            if IS_WIN:
                sh(["attrib", "-R", c["path"]])
            os.remove(c["path"])
        except OSError:
            pass
    st["canaries"] = []


class FileWatch:
    def __init__(self, st: dict):
        self.st = st
        self.roots = watch_roots()
        self.exec_roots = [r for r in self.roots if os.path.basename(r) in ("Downloads", "Desktop")] + temp_roots()
        self.prev = snapshot(self.roots)
        self.prev_exec = snapshot(self.exec_roots, depth=2, limit=8000)
        self.hashed = set()

    def canary_events(self) -> list:
        hit = []
        for c in self.st.get("canaries", []):
            try:
                with open(c["path"], "rb") as f:
                    ok = hashlib.sha256(f.read()).hexdigest() == c["sha256"]
            except OSError:
                ok = False
            if not ok:
                hit.append(c["path"])
        if not hit:
            return []
        return [{"kind": "canary_touched", "severity": "critical", "files": hit[:50],
                 "detail": f"{len(hit)} decoy file(s) were changed, renamed or deleted. Ransomware usually does this first."}]

    def tick(self) -> tuple[list, list]:
        events = self.canary_events()
        if events:
            plant_canaries(self.st)  # re-arm, the alert is already raised
            save_state(self.st)
        cur = snapshot(self.roots)
        canary_paths = {c["path"] for c in self.st.get("canaries", [])}
        new = [p for p in cur if p not in self.prev]
        changed = [p for p in cur if p in self.prev and cur[p] != self.prev[p]]
        gone = [p for p in self.prev if p not in cur and p not in canary_paths]
        touched = [p for p in new + changed if p not in canary_paths]
        notes = [p for p in new if RANSOM_NOTE.search(os.path.basename(p))]
        ransom_ext = [p for p in new if ransom_named(p)]
        enc = []
        if len(touched) >= 10:
            sample = touched[:40]
            enc = [p for p in sample if looks_encrypted(p)]
        if notes:
            events.append({"kind": "ransomware_suspected", "severity": "critical", "files": notes[:50],
                           "detail": f"{len(notes)} file(s) that look like a ransom note appeared."})
        if len(ransom_ext) >= 5:
            events.append({"kind": "ransomware_suspected", "severity": "critical", "files": ransom_ext[:200],
                           "detail": f"{len(ransom_ext)} new files carry a known ransomware extension."})
        if len(enc) >= 8:
            events.append({"kind": "ransomware_suspected", "severity": "critical", "files": enc[:200],
                           "detail": f"{len(touched)} files changed in {FILE_EVERY}s; {len(enc)} of {min(40, len(touched))} sampled now look encrypted (header gone, random data)."})
        elif len(touched) + len(gone) >= 300:
            events.append({"kind": "mass_change", "severity": "medium", "files": (touched + gone)[:100],
                           "detail": f"{len(touched)} files changed/created and {len(gone)} removed in {FILE_EVERY}s (no encryption seen)."})
        self.prev = cur
        # executables
        ecur = snapshot(self.exec_roots, depth=2, limit=8000)
        cand = [p for p in ecur if (p not in self.prev_exec or ecur[p] != self.prev_exec[p]) and p not in self.hashed]
        self.prev_exec = ecur
        hashes = []
        for p in cand[:60]:
            if is_executable(p):
                h = file_hashes(p)
                if h:
                    hashes.append(h)
                    self.hashed.add(p)
        if len(self.hashed) > 20000:
            self.hashed.clear()
        return events, hashes

    def initial_hashes(self) -> list:
        out = []
        for p in list(self.prev_exec)[:400]:
            if is_executable(p):
                h = file_hashes(p)
                if h:
                    out.append(h)
                    self.hashed.add(p)
        return out


# ------------------------------------------------------------------ isolation
def _ip_ranges_except(keep: list) -> str:
    """IPv4 ranges covering everything except the kept addresses, loopback and broadcast (for Windows Firewall)."""
    holes = sorted({int(ipaddress.IPv4Address(i)) for i in keep if ":" not in i} | {0xFFFFFFFF})
    lo_a, lo_b = 0x7F000000, 0x7FFFFFFF
    out, start = [], 0

    def add(a: int, b: int) -> None:
        for x, y in ((a, min(b, lo_a - 1)), (max(a, lo_b + 1), b)):
            if x <= y:
                out.append(f"{ipaddress.IPv4Address(x)}-{ipaddress.IPv4Address(y)}")
    for h in holes:
        if start <= h - 1:
            add(start, h - 1)
        start = h + 1
    return ",".join(out)


def isolate(api: Api) -> tuple[bool, str]:
    ips = api.server_ips(refresh=True)
    v4 = [i for i in ips if ":" not in i]
    v6 = [i for i in ips if ":" in i]
    if not ips:
        return False, "could not resolve the AWMZA server address"
    if IS_WIN:
        rng = _ip_ranges_except(v4)
        cmds = [["netsh", "advfirewall", "set", "allprofiles", "state", "on"]]
        for d in ("out", "in"):
            cmds.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=AWMZA-ISOLATE-{d.upper()}"])
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule", f"name=AWMZA-ISOLATE-{d.upper()}", f"dir={d}",
                         "action=block", "profile=any", "enable=yes", f"remoteip={rng}"])
            cmds.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=AWMZA-ISOLATE-{d.upper()}6"])
            cmds.append(["netsh", "advfirewall", "firewall", "add", "rule", f"name=AWMZA-ISOLATE-{d.upper()}6", f"dir={d}",
                         "action=block", "profile=any", "enable=yes", "remoteip=::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff,fec0::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"])
        for c in cmds:
            rc, txt = sh(c)
            if rc != 0 and "delete" not in c:
                return False, "netsh: " + txt.strip()[:300]
        return True, f"Windows Firewall block rules on; only {', '.join(v4)} reachable"
    if IS_MAC:
        rules = ["pass out quick on lo0 all", "pass in quick on lo0 all",
                 "pass out quick proto tcp from any to { %s } port 443 keep state" % ", ".join(ips),
                 "pass out quick proto udp from any port 68 to any port 67 keep state",
                 "block drop quick all"]
        path = os.path.join(HOME_DIR, "pf-isolate.conf")
        with open(path, "w") as f:
            f.write("\n".join(rules) + "\n")
        rc, txt = sh(["pfctl", "-a", "com.apple/awmza.isolate", "-f", path])
        if rc != 0:
            return False, "pfctl: " + txt.strip()[:300]
        rc, txt = sh(["pfctl", "-E"])
        m = re.search(r"Token\s*:\s*(\d+)", txt)
        st = api.st
        st["pf_token"] = m.group(1) if m else ""
        return True, f"pf anchor com.apple/awmza.isolate loaded; only {', '.join(ips)} reachable"
    if shutil.which("nft"):
        sv4 = ("ip daddr { %s } tcp dport %d accept;" % (", ".join(v4), api.port)) if v4 else ""
        sv6 = ("ip6 daddr { %s } tcp dport %d accept;" % (", ".join(v6), api.port)) if v6 else ""
        ruleset = ("table inet awmza_isolate {\n"
                   " chain out { type filter hook output priority -50; policy drop; oif lo accept; "
                   f"{sv4} {sv6} udp sport 68 udp dport 67 accept; udp dport 547 accept; }}\n"
                   " chain inp { type filter hook input priority -50; policy drop; iif lo accept; ct state established,related accept; "
                   "udp sport 67 udp dport 68 accept; udp sport 547 accept; }\n}\n")
        sh(["nft", "delete", "table", "inet", "awmza_isolate"])
        try:
            p = subprocess.run(["nft", "-f", "-"], input=ruleset, capture_output=True, text=True, timeout=20)
            if p.returncode == 0:
                return True, f"nftables table awmza_isolate; only {', '.join(ips)} reachable"
            err = p.stderr
        except (OSError, subprocess.SubprocessError) as e:
            err = str(e)
        if not shutil.which("iptables"):
            return False, "nft: " + err.strip()[:300]
    if shutil.which("iptables"):
        _iptables_release()
        for tool, addrs in (("iptables", v4), ("ip6tables", v6)):
            if not shutil.which(tool):
                continue
            base = [["-N", "AWMZA_ISO_OUT"], ["-N", "AWMZA_ISO_IN"],
                    ["-A", "AWMZA_ISO_OUT", "-o", "lo", "-j", "ACCEPT"],
                    ["-A", "AWMZA_ISO_IN", "-i", "lo", "-j", "ACCEPT"],
                    ["-A", "AWMZA_ISO_IN", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]]
            base += [["-A", "AWMZA_ISO_OUT", "-d", a, "-p", "tcp", "--dport", str(api.port), "-j", "ACCEPT"] for a in addrs]
            if tool == "iptables":
                base += [["-A", "AWMZA_ISO_OUT", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
                         ["-A", "AWMZA_ISO_IN", "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"]]
            base += [["-A", "AWMZA_ISO_OUT", "-j", "DROP"], ["-A", "AWMZA_ISO_IN", "-j", "DROP"],
                     ["-I", "OUTPUT", "1", "-j", "AWMZA_ISO_OUT"], ["-I", "INPUT", "1", "-j", "AWMZA_ISO_IN"]]
            for b in base:
                rc, txt = sh([tool, "-w"] + b)
                if rc != 0:
                    return False, f"{tool}: " + txt.strip()[:300]
        return True, f"iptables chains AWMZA_ISO_*; only {', '.join(ips)} reachable"
    return False, "no supported firewall tool (nft / iptables) found"


def _iptables_release() -> None:
    for tool in ("iptables", "ip6tables"):
        if not shutil.which(tool):
            continue
        for chain, parent in (("AWMZA_ISO_OUT", "OUTPUT"), ("AWMZA_ISO_IN", "INPUT")):
            for _ in range(5):
                if sh([tool, "-w", "-D", parent, "-j", chain])[0] != 0:
                    break
            sh([tool, "-w", "-F", chain])
            sh([tool, "-w", "-X", chain])


def release(api: Api) -> tuple[bool, str]:
    if IS_WIN:
        for n in ("OUT", "IN", "OUT6", "IN6"):
            sh(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=AWMZA-ISOLATE-{n}"])
        rc, txt = sh(["netsh", "advfirewall", "firewall", "show", "rule", "name=AWMZA-ISOLATE-OUT"])
        ok = "No rules match" in txt or rc != 0
        return ok, "block rules removed (Windows Firewall stays on)" if ok else txt[:300]
    if IS_MAC:
        sh(["pfctl", "-a", "com.apple/awmza.isolate", "-F", "all"])
        tok = api.st.pop("pf_token", "")
        if tok:
            sh(["pfctl", "-X", tok])
        return True, "pf anchor flushed"
    if shutil.which("nft"):
        sh(["nft", "delete", "table", "inet", "awmza_isolate"])
    _iptables_release()
    return True, "isolation rules removed"


# ------------------------------------------------------------------ service
def install_service() -> str:
    exe = sys.executable
    if IS_WIN and not FROZEN:
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        exe = pyw if os.path.exists(pyw) else exe
    args = [INSTALLED_BIN, "run"] if FROZEN else [exe, INSTALLED_SCRIPT, "run"]
    if IS_WIN:
        tr = " ".join(f'"{x}"' for x in args[:-1]) + " run"
        rc, txt = sh(["schtasks", "/Create", "/TN", "AWMZA Security Agent", "/TR", tr, "/SC", "ONSTART",
                      "/RU", "SYSTEM", "/RL", "HIGHEST", "/F"])
        if rc != 0:
            raise SystemExit("schtasks failed: " + txt)
        sh(["schtasks", "/Run", "/TN", "AWMZA Security Agent"])
        return "Windows scheduled task 'AWMZA Security Agent' (SYSTEM, at startup)"
    if IS_MAC:
        plist = "/Library/LaunchDaemons/com.awmza.agent.plist"
        with open(plist, "w") as f:
            f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.awmza.agent</string>
<key>ProgramArguments</key><array>{"".join(f"<string>{x}</string>" for x in args)}</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
""")
        os.chmod(plist, 0o644)
        sh(["launchctl", "unload", plist])
        sh(["launchctl", "load", "-w", plist])
        return f"launchd daemon com.awmza.agent (give {os.path.basename(args[0])} Full Disk Access in System Settings > Privacy & Security so it can watch Documents and Desktop)"
    if os.path.isdir("/run/systemd/system"):
        with open("/etc/systemd/system/awmza-agent.service", "w") as f:
            f.write(f"""[Unit]
Description=AWMZA Security endpoint agent
After=network-online.target

[Service]
ExecStart={" ".join(args)}
Restart=always
RestartSec=10
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
""")
        sh(["systemctl", "daemon-reload"])
        sh(["systemctl", "enable", "--now", "awmza-agent.service"])
        return "systemd service awmza-agent"
    with open("/etc/cron.d/awmza-agent", "w") as f:
        f.write(f"@reboot root {' '.join(args)} >/dev/null 2>&1\n")
    subprocess.Popen(args, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "cron @reboot + started now (no systemd found)"


def remove_service() -> None:
    if IS_WIN:
        sh(["schtasks", "/End", "/TN", "AWMZA Security Agent"])
        sh(["schtasks", "/Delete", "/TN", "AWMZA Security Agent", "/F"])
    elif IS_MAC:
        plist = "/Library/LaunchDaemons/com.awmza.agent.plist"
        sh(["launchctl", "unload", plist])
        try:
            os.remove(plist)
        except OSError:
            pass
    else:
        sh(["systemctl", "disable", "--now", "awmza-agent.service"])
        for p in ("/etc/systemd/system/awmza-agent.service", "/etc/cron.d/awmza-agent"):
            try:
                os.remove(p)
            except OSError:
                pass
        sh(["systemctl", "daemon-reload"])


def in_program_files(path: str) -> bool:
    path = os.path.normcase(os.path.abspath(path))
    for v in ("ProgramFiles", "ProgramW6432"):
        pf = os.environ.get(v)
        if pf and path.startswith(os.path.normcase(os.path.abspath(pf)) + os.sep):
            return True
    return False


def copy_self() -> None:
    if not FROZEN:
        src = os.path.abspath(__file__)
        if os.path.abspath(INSTALLED_SCRIPT) != src:
            shutil.copyfile(src, INSTALLED_SCRIPT)
    elif not IS_WIN and os.path.abspath(sys.executable) != INSTALLED_BIN:
        remove_service()  # a running copy would keep the old binary busy
        tmp = INSTALLED_BIN + ".new"
        shutil.copyfile(sys.executable, tmp)
        os.chmod(tmp, 0o700)
        os.replace(tmp, INSTALLED_BIN)


# ------------------------------------------------------------------ commands
def cmd_install(a) -> None:
    if not is_admin():
        raise SystemExit("Run as Administrator (Windows) or with sudo (macOS / Linux).")
    if FROZEN and IS_WIN and not in_program_files(sys.executable):
        # the SYSTEM task must start a file that only administrators can change
        raise SystemExit("Install with AWMZA-Security-Setup.exe (the agent must live in Program Files).")
    lock_down_home()
    st = load_state()
    st["server"] = a.server.rstrip("/")
    api = Api(st)
    try:
        r = api.call("/api/endpoint/agent/register", {"token": a.token, "hostname": socket.gethostname()[:120],
                                                      "os": SYSTEM, "os_version": platform.platform()[:200],
                                                      "agent_version": VERSION}, auth=False)
    except ApiError as e:
        raise SystemExit({"invalid_or_expired_token": "The install token is wrong or expired. Make a new one in the dashboard.",
                          "device_limit_reached": "Your plan's device limit is reached."}.get(e.detail, f"Registration failed: {e}"))
    st.update({"device_id": r["device_id"], "device_key": r["device_key"], "isolated": False})
    api.server_ips(refresh=True)
    plant_canaries(st)
    save_state(st)
    copy_self()
    how = install_service()
    print(f"AWMZA agent installed: device {r['device_id']}, {len(st['canaries'])} canary file(s), service: {how}")
    print("The computer appears in your dashboard within a minute: https://security.awmza.com/dashboard/#endpoints")


def cmd_run(a) -> None:
    st = load_state()
    if not st.get("device_id"):
        raise SystemExit("Not installed. Run: install --token TOKEN")
    if st.get("removed"):
        raise SystemExit("This computer was removed in the dashboard. Install again with a new token.")
    api = Api(st)
    queue: list = [{"kind": "agent_started", "severity": "info", "detail": f"agent {VERSION} started", "files": []}]
    hashes: list = []
    seen: dict = {}
    fw = FileWatch(st)
    hashes += fw.initial_hashes()
    inv, inv_at = None, 0.0
    last_admins = set(st.get("admins") or [])
    auto_isolate = bool(st.get("auto_isolate"))
    t_proc = t_file = t_beat = 0.0
    log(f"run: device {st['device_id']}, watching {len(fw.roots)} folder(s)")
    while True:
        now = time.time()
        try:
            if now - t_proc >= PROC_EVERY:
                t_proc = now
                queue += check_processes(seen)
            if now - t_file >= FILE_EVERY:
                t_file = now
                ev, hs = fw.tick()
                queue += ev
                hashes += hs
            if now - inv_at >= INVENTORY_EVERY or inv is None:
                inv_at = now
                inv = inventory(st)
                cur = set(inv.get("admins") or [])
                added = cur - last_admins if last_admins else set()
                if added:
                    queue.append({"kind": "privilege_change", "severity": "high", "files": [],
                                  "detail": "New administrator account(s): " + ", ".join(sorted(added))[:500]})
                if cur != last_admins:
                    st["admins"] = sorted(cur)
                    save_state(st)
                    last_admins = cur
            danger = [e for e in queue if e["kind"] in ("ransomware_suspected", "canary_touched", "ransomware_precursor")]
            if danger and auto_isolate and not st.get("isolated"):
                ok, why = isolate(api)
                st["isolated"] = ok
                save_state(st)
                queue.append({"kind": "isolated" if ok else "isolation_failed", "severity": "high", "files": [],
                              "detail": "Automatic isolation: " + why})
            if queue:
                batch, queue = queue[:20], queue[20:]
                try:
                    r = api.call("/api/endpoint/agent/events", {"events": batch})
                    if r.get("isolate_now") and not st.get("isolated"):
                        ok, why = isolate(api)
                        st["isolated"] = ok
                        save_state(st)
                        queue.append({"kind": "isolated" if ok else "isolation_failed", "severity": "high",
                                      "files": [], "detail": "Automatic isolation: " + why})
                except (ConnectionError, ApiError) as e:
                    queue = (batch + queue)[:300]
                    log("events not sent: " + str(e))
            if hashes:
                batch, hashes = hashes[:200], hashes[200:]
                try:
                    r = api.call("/api/endpoint/agent/hashcheck", {"files": batch})
                    for m in r.get("matches", []):
                        queue.append({"kind": "malware_detected", "severity": "critical", "files": [m["path"]],
                                      "detail": f"Known malware: {m['name']} (sha256 {m['sha256']}). Delete the file and run a full antivirus scan."})
                except (ConnectionError, ApiError) as e:
                    hashes = (batch + hashes)[:2000]
                    log("hashcheck not sent: " + str(e))
            if now - t_beat >= HEARTBEAT_EVERY:
                t_beat = now
                try:
                    r = api.call("/api/endpoint/agent/heartbeat", {"inventory": inv or {}, "isolated": bool(st.get("isolated")),
                                                                   "agent_version": VERSION})
                    if bool(r.get("auto_isolate")) != auto_isolate:
                        auto_isolate = st["auto_isolate"] = bool(r.get("auto_isolate"))
                        save_state(st)
                    for c in r.get("commands", []):
                        if c["action"] == "isolate":
                            ok, why = isolate(api)
                        elif c["action"] == "release":
                            ok, why = release(api)
                        else:
                            ok, why = False, "unknown command"
                        if ok:
                            st["isolated"] = c["action"] == "isolate"
                            save_state(st)
                            queue.append({"kind": "isolated" if st["isolated"] else "released", "severity": "info",
                                          "files": [], "detail": why})
                        api.call("/api/endpoint/agent/ack", {"command_id": c["id"], "ok": ok, "detail": why[:500]})
                        log(f"command {c['action']}: {ok} {why}")
                except ApiError as e:
                    if e.status == 410:
                        log("device removed in the dashboard - releasing isolation, removing the service, stopping")
                        release(api)
                        remove_canaries(st)
                        st["isolated"] = False
                        st["removed"] = True
                        save_state(st)
                        remove_service()
                        return
                    log("heartbeat: " + str(e))
                except ConnectionError as e:
                    log("heartbeat: " + str(e))
        except Exception as e:  # never die silently: keep watching
            log(f"loop error: {type(e).__name__}: {e}")
        time.sleep(2)


def cmd_service(a) -> None:
    if not is_admin():
        raise SystemExit("Run as Administrator / sudo.")
    if not load_state().get("device_id"):
        raise SystemExit("Not installed. Run: install --token TOKEN")
    copy_self()
    print("AWMZA agent service: " + install_service())


def cmd_status(a) -> None:
    st = load_state()
    safe = {k: v for k, v in st.items() if k != "device_key"}
    safe["version"] = VERSION
    print(json.dumps(safe, indent=2))


def cmd_isolate(a) -> None:
    st = load_state()
    ok, why = isolate(Api(st))
    st["isolated"] = ok or st.get("isolated", False)
    save_state(st)
    print(("OK: " if ok else "FAILED: ") + why)


def cmd_release(a) -> None:
    st = load_state()
    ok, why = release(Api(st))
    if ok:
        st["isolated"] = False
        save_state(st)
    print(("OK: " if ok else "FAILED: ") + why)


def cmd_uninstall(a) -> None:
    if not is_admin():
        raise SystemExit("Run as Administrator / sudo.")
    st = load_state()
    if st:
        release(Api(st))
        remove_canaries(st)
        try:
            Api(st).call("/api/endpoint/agent/events", {"events": [{"kind": "agent_stopped", "severity": "high", "files": [],
                                                                     "detail": "agent uninstalled on the computer"}]})
        except Exception:
            pass
    remove_service()
    for p in (STATE, INSTALLED_SCRIPT, LOG, LOG + ".1", os.path.join(HOME_DIR, "pf-isolate.conf"),
              None if IS_WIN else INSTALLED_BIN):
        if p is None:
            continue
        try:
            os.remove(p)
        except OSError:
            pass
    print("AWMZA agent removed. Remove the device in the dashboard too.")


def main() -> None:
    p = argparse.ArgumentParser(description="AWMZA Security endpoint agent " + VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("install")
    i.add_argument("--token", required=True)
    i.add_argument("--server", default=DEFAULT_SERVER)
    for n in ("run", "service", "status", "isolate", "release", "uninstall"):
        sub.add_parser(n)
    a = p.parse_args()
    {"install": cmd_install, "run": cmd_run, "service": cmd_service, "status": cmd_status, "isolate": cmd_isolate,
     "release": cmd_release, "uninstall": cmd_uninstall}[a.cmd](a)


if __name__ == "__main__":
    main()
