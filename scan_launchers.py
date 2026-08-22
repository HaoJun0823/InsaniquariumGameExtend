import struct, os

BASE = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe"
CANDIDATES = [
    "insaniquariumdeluxe.exe",
    "Insaniquarium.exe",
    "old_cn_patch/InsaniquariumDeluxe.exe",
]
CANON = 2176320  # 规范 Game.exe 大小

def pe_offsets(data):
    offs = []
    n = len(data)
    i = 0
    while i + 0x40 < n:
        if data[i] == 0x4D and data[i+1] == 0x5A:
            e = struct.unpack_from('<I', data, i+0x3C)[0]
            if i + e + 4 <= n and data[i+e:i+e+4] == b'PE\x00\x00':
                offs.append(i)
        i += 1
    return offs

def pe_disk_size(data, base):
    e = struct.unpack_from('<I', data, base+0x3C)[0]
    off = base + e
    nsec = struct.unpack_from('<H', data, off+4+2)[0]
    opos = off + 4 + 20
    optsize = struct.unpack_from('<H', data, off+4+16)[0]
    fa = struct.unpack_from('<I', data, opos+36)[0]
    sec = opos + optsize
    maxraw = 0
    for k in range(nsec):
        rawptr = struct.unpack_from('<I', data, sec+k*40+20)[0]
        rawsize = struct.unpack_from('<I', data, sec+k*40+16)[0]
        maxraw = max(maxraw, rawptr + rawsize)
    return ((maxraw + fa - 1)//fa)*fa if fa else maxraw

def secdir(data, base):
    e = struct.unpack_from('<I', data, base+0x3C)[0]
    off = base + e
    opos = off + 4 + 20
    va, sz = struct.unpack_from('<II', data, opos + 96 + 4*8)  # DataDirectory[4] = Security
    return va, sz

for name in CANDIDATES:
    path = os.path.join(BASE, name)
    if not os.path.exists(path):
        print(f"\n### {name}: 不存在\n"); continue
    data = open(path, "rb").read()
    fsize = len(data)
    offs = pe_offsets(data)
    print(f"\n### {name}")
    print(f"  大小={fsize} ({hex(fsize)})  PE头数={len(offs)}  位置={[hex(o) for o in offs]}")
    if not offs:
        continue
    payload = offs[-1]  # 最后一个 PE = 内嵌 Game.exe
    pds = pe_disk_size(data, payload)
    print(f"  内嵌 payload @ {hex(payload)}  节表磁盘大小={pds}")
    # 用启动器自身(第一个 PE)的安全目录判断证书边界
    if len(offs) >= 1:
        va, sz = secdir(data, offs[0])
        if sz:
            cert_end = va + sz
            print(f"  启动器证书: VA={hex(va)} Size={sz} end={hex(cert_end)}  end==文件尾? {cert_end==fsize}")
            plen = va - payload
            print(f"  证书边界算出的 payload 长度 = {plen}  与规范 {CANON} 差 {plen-CANON}")
        else:
            print(f"  启动器无安全目录(未签名)")
    # 校验：从该 payload 切 CANON 字节，看是否等于规范 Game.exe
    if fsize - payload >= CANON:
        seg = data[payload:payload+CANON]
        print(f"  payload 起切 {CANON} 字节: MZ? {seg[:2]==b'MZ'}  末4节表? (略)")
