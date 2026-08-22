import struct, hashlib, os

BASE = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe"

def read_all(path):
    with open(path, 'rb') as f:
        return f.read()

def pe_offsets(data):
    offs = []
    n = len(data)
    i = 0
    while i + 0x40 < n:
        if data[i] == 0x4D and data[i+1] == 0x5A:  # MZ
            e_lfanew = struct.unpack_from('<I', data, i+0x3C)[0]
            if i + e_lfanew + 4 <= n and data[i+e_lfanew:i+e_lfanew+4] == b'PE\x00\x00':
                offs.append(i)
        i += 1
    return offs

def align(x, a):
    return (x + (a-1)) // a * a if a else x

def parse_pe_at(data, base):
    if base + 0x40 > len(data):
        return None
    if data[base:base+2] != b'MZ':
        return None
    e_lfanew = struct.unpack_from('<I', data, base+0x3C)[0]
    off = base + e_lfanew
    if off + 4 > len(data) or data[off:off+4] != b'PE\x00\x00':
        return None
    machine, nsec, ts, ptr2sym, n2sym, optsize, ch = struct.unpack_from('<HHIIIHH', data, off+4)
    opos = off + 4 + 20
    magic = struct.unpack_from('<H', data, opos)[0]
    if magic != 0x10b:
        return None
    SizeOfImage = struct.unpack_from('<I', data, opos+56)[0]
    SizeOfHeaders = struct.unpack_from('<I', data, opos+60)[0]
    FileAlignment = struct.unpack_from('<I', data, opos+36)[0]
    SectionAlignment = struct.unpack_from('<I', data, opos+32)[0]
    ImageBase = struct.unpack_from('<I', data, opos+28)[0]
    EntryPoint = struct.unpack_from('<I', data, opos+16)[0]
    secstart = opos + optsize
    maxraw = 0
    secs = []
    for k in range(nsec):
        so = secstart + k*40
        name = data[so:so+8].split(b'\x00')[0].decode('latin1', 'replace')
        vsize = struct.unpack_from('<I', data, so+8)[0]
        vaddr = struct.unpack_from('<I', data, so+12)[0]
        rawsize = struct.unpack_from('<I', data, so+16)[0]
        rawptr = struct.unpack_from('<I', data, so+20)[0]
        secs.append((name, vaddr, vsize, rawptr, rawsize))
        end = rawptr + rawsize
        if end > maxraw:
            maxraw = end
    disk_aligned = align(maxraw, FileAlignment)
    return dict(base=base, machine=machine, nsec=nsec, SizeOfImage=SizeOfImage,
                SizeOfHeaders=SizeOfHeaders, FileAlignment=FileAlignment,
                SectionAlignment=SectionAlignment, ImageBase=ImageBase,
                EntryPoint=EntryPoint, maxraw=maxraw, disk_aligned=disk_aligned,
                sections=secs)

orig = read_all(os.path.join(BASE, "Game_original.exe"))
mod  = read_all(os.path.join(BASE, "Game.exe"))
launcher = read_all(os.path.join(BASE, "InsaniquariumDeluxe.exe"))

print("=== 文件大小 ===")
print(f"  Game_original.exe : {len(orig)}")
print(f"  Game.exe          : {len(mod)}  (多 {len(mod)-len(orig)} 字节)")
print(f"  InsaniquariumDeluxe.exe : {len(launcher)}")

po = parse_pe_at(orig, 0)
pm = parse_pe_at(mod, 0)
print("\n=== Game_original.exe 的 PE 解析 ===")
print(f"  nsec={po['nsec']} SizeOfImage={po['SizeOfImage']} SizeOfHeaders={po['SizeOfHeaders']}")
print(f"  磁盘真实大小(maxraw)={po['maxraw']} 对齐后(disk_aligned)={po['disk_aligned']}")

print("\n=== Game.exe 的 PE 解析（PE 头在偏移 0）===")
print(f"  nsec={pm['nsec']} SizeOfImage={pm['SizeOfImage']} SizeOfHeaders={pm['SizeOfHeaders']}")
print(f"  磁盘真实大小(maxraw)={pm['maxraw']} 对齐后(disk_aligned)={pm['disk_aligned']}")

N = len(orig)
print("\n=== 逐字节对比（Game.exe 前 N 字节 vs Game_original.exe）===")
print(f"  N = {N}")
print(f"  Game_original SHA256 : {hashlib.sha256(orig).hexdigest()}")
print(f"  Game.exe[:N]  SHA256 : {hashlib.sha256(mod[:N]).hexdigest()}")
print(f"  前 {N} 字节完全一致 : {orig == mod[:N]}")
if len(mod) > N:
    tail = mod[N:]
    print(f"  Game.exe 尾部多余 {len(tail)} 字节，前16字节(hex): {tail[:16].hex()}")

print("\n=== 启动器内所有合法 PE 头位置 ===")
offs = pe_offsets(launcher)
print(f"  共 {len(offs)} 个: {[hex(o) for o in offs]}")
for o in offs:
    p = parse_pe_at(launcher, o)
    if p:
        end = o + p['disk_aligned']
        extra = len(launcher) - end
        print(f"  @{hex(o)} nsec={p['nsec']} SizeOfImage={p['SizeOfImage']} "
              f"payload_disk={p['disk_aligned']} -> 结束@{hex(end)} 之后还剩{extra}字节")

# 验证：从每个 PE 头切出 disk_aligned 字节，是否等于真品 Game_original
print("\n=== 哪个启动器内 PE 切出来等于真品？ ===")
for o in offs:
    p = parse_pe_at(launcher, o)
    if not p:
        continue
    seg = launcher[o:o+p['disk_aligned']]
    if len(seg) == len(orig) and seg == orig:
        print(f"  @{hex(o)} 切 {p['disk_aligned']} 字节 == Game_original  ✔")
    else:
        print(f"  @{hex(o)} 切 {p['disk_aligned']} 字节 不等于真品 (len_seg={len(seg)}, sha={hashlib.sha256(seg).hexdigest()[:12]})")
