"""
find_ids.py — scan every Minecraft Education world on this PC and list
every player's PlatformOnlineId, XUID, ConnectionId, and PlayerName.

Use the printed IDs in watchdog.py's ALWAYS_OP list to force-op players.
"""
import os
import struct
import zlib
import ctypes

CANDIDATE_DIRS = [
    r"%LOCALAPPDATA%\Packages\Microsoft.MinecraftEducationEdition_8wekyb3d8bbwe\LocalState\games\com.mojang\minecraftWorlds",
    r"%APPDATA%\Minecraft Education Edition\games\com.mojang\minecraftWorlds",
]

PLAYER_PREFIXES = (b"player", b"~local_player")
BLOCK = 32768


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
#  VARINT
# =========================================================
def varint(buf, pos):
    result = shift = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


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


def is_op(p):
    ab = p.get("abilities", (10, {}))[1]
    return (p.get("playerPermissionsLevel", (3, 0))[1] == 2 and
            ab.get("op", (1, 0))[1] == 1)


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


# =========================================================
#  MAIN
# =========================================================
def main():
    worlds_dir = find_worlds_dir()
    if not worlds_dir:
        print("[-] Couldn't find Minecraft Education worlds folder.")
        return

    worlds = [w for w in sorted(os.listdir(worlds_dir))
              if os.path.isdir(os.path.join(worlds_dir, w, "db"))]

    if not worlds:
        print("[-] No worlds found.")
        return

    print(f"[*] Scanning {len(worlds)} world(s) in:")
    print(f"    {worlds_dir}\n")

    by_id = {}

    for w in worlds:
        db_dir = os.path.join(worlds_dir, w, "db")
        wname  = world_name(os.path.join(worlds_dir, w))

        try:
            entries, _ = load_db(db_dir)
        except Exception as e:
            print(f"  [!] {wname}: {e}")
            continue

        for key, raw in entries.items():
            try:
                _, _, p = nbt_load(raw)
            except Exception:
                continue

            pid  = p.get("PlatformOnlineId", (8, ""))[1]
            xuid = p.get("XUID",             (8, ""))[1]
            conn = p.get("ConnectionId",     (8, ""))[1]
            name = p.get("PlayerName",       (8, ""))[1]
            op   = is_op(p)

            stable = pid or xuid
            if not stable and key.startswith(b"player_"):
                stable = key[len(b"player_"):].decode("utf-8", "ignore")
            if not stable and key == b"~local_player":
                stable = "(local host)"

            if not stable:
                continue

            rec = by_id.setdefault(stable, {
                "names": set(), "xuids": set(), "conns": set(),
                "worlds": set(), "op_worlds": set(), "keys": set(),
                "local": False,
            })
            if name: rec["names"].add(name)
            if xuid: rec["xuids"].add(xuid)
            if conn: rec["conns"].add(conn)
            rec["worlds"].add(wname)
            if op: rec["op_worlds"].add(wname)
            rec["keys"].add(key.decode("utf-8", "ignore"))
            if key == b"~local_player":
                rec["local"] = True

        print(f"  [{len(entries)} records] {wname} ({w})")

    print()
    print("=" * 72)
    print(f"Found {len(by_id)} unique player identifier(s)")
    print("=" * 72)
    print()

    for stable, rec in sorted(by_id.items(),
                              key=lambda kv: (not kv[1]["local"], kv[0])):
        tag = " [LOCAL HOST]" if rec["local"] else ""
        print(f"ID:    {stable}{tag}")
        if rec["names"]:
            print(f"  Name(s):      {', '.join(sorted(rec['names']))}")
        if rec["xuids"]:
            print(f"  XUID(s):      {', '.join(sorted(rec['xuids']))}")
        if rec["conns"]:
            print(f"  ConnID(s):    {', '.join(sorted(rec['conns']))}")
        print(f"  Worlds:       {len(rec['worlds'])}  ({', '.join(sorted(rec['worlds']))})")
        print(f"  OP in:        {len(rec['op_worlds'])}  "
              f"({', '.join(sorted(rec['op_worlds'])) or 'none'})")
        print(f"  DB keys:      {', '.join(sorted(rec['keys']))}")
        print()

    print("=" * 72)
    print("Ready-to-paste ALWAYS_OP list (paste into watchdog.py):")
    print("=" * 72)
    print()
    print("ALWAYS_OP = [")
    for stable in sorted(by_id.keys()):
        if stable.startswith("(") and stable.endswith(")"):
            continue
        print(f'    "{stable}",')
    print("]")
    print()
    print("Use the 'ID' field (PlatformOnlineId or XUID). Those are stable")
    print("across sessions. ConnectionId changes every restart.")


if __name__ == "__main__":
    main()
