import struct

BASE = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe"
launcher = open(BASE + r"\InsaniquariumDeluxe.exe", "rb").read()

def le32(v):
    return struct.pack("<I", v)

targets = {
    "payload_len(2176320)": 2176320,
    "pe_disk(2170880)": 2170880,
    "modloader_len(2181782)": 2181782,
    "payload_off(1606050=0x1881a2)": 1606050,
}

print("=== 在启动器里搜索关键数值(小端 4 字节) ===")
for name, val in targets.items():
    pat = le32(val)
    idx = -1
    hits = []
    while True:
        idx = launcher.find(pat, idx + 1)
        if idx == -1:
            break
        hits.append(idx)
    print(f"\n[{name}] = {hex(val)}  命中 {len(hits)} 处:")
    for h in hits:
        # 上下文：前后各 24 字节
        lo = max(0, h - 24)
        hi = min(len(launcher), h + len(pat) + 24)
        ctx = launcher[lo:hi]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
        print(f"  @{hex(h)}  hex: {ctx.hex()}")
        print(f"           asc: {asc}")

print("\n=== payload 头(0x1881a2)前 32 字节(看有无长度前缀) ===")
p = 0x1881a2
pre = launcher[p-32:p]
print(f"  @{hex(p-32)}  hex: {pre.hex()}")
print(f"           asc: {''.join(chr(b) if 32<=b<127 else '.' for b in pre)}")
print(f"  紧邻 MZ 前的 4 字节(若作长度前缀): {launcher[p-4:p].hex()} = {struct.unpack('<I', launcher[p-4:p])[0]}")

print("\n=== 启动器结尾 64 字节(看尾巴结构/签名) ===")
tail = launcher[-64:]
print(f"  @EOF-64  hex: {tail.hex()}")
print(f"           asc: {''.join(chr(b) if 32<=b<127 else '.' for b in tail)}")
