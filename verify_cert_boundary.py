import struct, hashlib

BASE = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe"
data = open(BASE + r"\InsaniquariumDeluxe.exe", "rb").read()
fsize = len(data)

def parse_pe(data, base):
    e_lfanew = struct.unpack_from("<I", data, base+0x3C)[0]
    off = base + e_lfanew
    machine, nsec, ts, p2, n2, optsize, ch = struct.unpack_from("<HHIIIHH", data, off+4)
    opos = off + 4 + 20
    magic = struct.unpack_from("<H", data, opos)[0]
    # data directories start at opos + 96 for PE32
    dd = []
    for i in range(16):
        va, sz = struct.unpack_from("<II", data, opos + 96 + i*8)
        dd.append((va, sz))
    return dict(base=base, e_lfanew=e_lfanew, magic=magic, nsec=nsec, dd=dd)

print(f"launcher file size = {fsize} ({hex(fsize)})")

la = parse_pe(data, 0)
print(f"\nlauncher PE @0x0: e_lfanew={hex(la['e_lfanew'])} magic={hex(la['magic'])}")
names = ["Export","Import","Resource","Exception","Security","BaseReloc","Debug",
         "Architecture","GlobalPtr","TLS","LoadConfig","BoundImport","IAT",
         "DelayImport","CLR","Reserved"]
print("  DataDirectory:")
for i,(va,sz) in enumerate(la['dd']):
    mark = ""
    if i==4 and sz:
        mark = "  <-- Security(cert)"
    print(f"   [{i:2}] {names[i]:14} VA={hex(va)} Size={sz} {mark}")

# 假设：启动器被签名，证书占据文件末尾 [cert_va, cert_va+cert_sz)，payload 在其之前结束
sec_va, sec_sz = la['dd'][4]
if sec_sz:
    cert_start = sec_va  # 安全目录的 VA 实为文件偏移
    cert_end = cert_start + sec_sz
    print(f"\n证书表: start={hex(cert_start)} size={sec_sz} end={hex(cert_end)}")
    print(f"  cert_end == file_size ? {cert_end == fsize}")
    payload_off = 0x1881a2
    payload_len = cert_start - payload_off
    print(f"  若 payload 起点=0x1881a2，则 payload 长度 = {payload_len} ({hex(payload_len)})")
    print(f"  该长度 == 规范 2176320 ? {payload_len == 2176320}")
    if payload_len == 2176320:
        seg = data[payload_off:payload_off+payload_len]
        print(f"  切片 SHA256: {hashlib.sha256(seg).hexdigest()}")
        print(f"  == 规范 Game.exe(312021e9...) ? {hashlib.sha256(seg).hexdigest().startswith('312021e9')}")
        # 看证书开头 16 字节是否符合 WIN_CERTIFICATE
        c = data[cert_start:cert_start+16]
        dwlen, wrev, wtype = struct.unpack_from("<IHH", c, 0)
        print(f"  证书头: dwLength={hex(dwlen)} wRevision={hex(wrev)} wCertificateType={hex(wtype)}")
        print(f"    dwLength == sec_sz ? {dwlen == sec_sz}  (wRevision 应=0x0200)")
else:
    print("\n启动器无安全目录(未签名) —— 证书边界假设不成立，需另寻边界。")
