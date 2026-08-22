import struct

BASE = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe"
data = open(BASE + r"\InsaniquariumDeluxe.exe", "rb").read()
fsize = len(data)

payload_off = 0x1881a2          # 内嵌 Game.exe PE 起点
canonical = 2176320            # DRM 解压的规范大小
cert_start = 0x39b6f8          # 启动器证书起点(安全目录 VA)
canonical_end = payload_off + canonical

def hexasc(lo, hi):
    seg = data[lo:hi]
    hx = seg.hex()
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in seg)
    return hx, asc

print(f"payload_off={hex(payload_off)} canonical_end={hex(canonical_end)} cert_start={hex(cert_start)}")
print(f"gap = cert_start - canonical_end = {cert_start - canonical_end} 字节\n")

print("=== 规范 payload 末尾 → 证书头  (canonical_end-16 .. cert_start+32) ===")
lo = canonical_end - 16
hi = cert_start + 32
hx, asc = hexasc(lo, hi)
print(f"  @{hex(lo)}")
print(f"  hex: {hx}")
print(f"  asc: {asc}")

print("\n=== 证书头(cert_start 起 32 字节, 应=WIN_CERTIFICATE: dwLength,wRevision=0x0200,wCertType) ===")
hx, asc = hexasc(cert_start, cert_start + 32)
print(f"  @{hex(cert_start)}")
print(f"  hex: {hx}")
print(f"  asc: {asc}")
dwlen, wrev, wtype = struct.unpack_from("<IHH", data, cert_start)
print(f"  -> dwLength={hex(dwlen)} ({dwlen})  wRevision={hex(wrev)}  wCertificateType={hex(wtype)}")

print("\n=== 检查 cert_start 前若干 4 字节是否像长度字段 ===")
for back in [4, 8, 12, 16, 22, 24]:
    p = cert_start - back
    v = struct.unpack_from("<I", data, p)[0]
    print(f"  cert_start-{back} (@{hex(p)}) = {v} (0x{v:08x})")

print("\n=== 启动器资源目录里是否引用 payload？(搜 0x1881a2 相关) ===")
# 0x1881a2 的小端/大端
for pat_name, pat in [("0x1881a2 LE","a2 81 18 00".replace(" ","").encode()),
                       ("2176320 LE","20 21 40 00".replace(" ","").encode()),
                       ("2176320-ish","00 21 40 00".replace(" ","").encode())]:
    idx = data.find(pat)
    print(f"  搜 {pat_name}: {'@'+hex(idx) if idx>=0 else '未找到'}")
