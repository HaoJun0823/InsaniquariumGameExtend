# -*- coding: utf-8 -*-
import struct

patched_path = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\old_cn_patch\patch_cn\怪怪水族箱.exe"
with open(patched_path, 'rb') as f:
    b = f.read()

def ctx(off, before=120, after=400, label=''):
    s = b[max(0,off-before):off+after]
    print(f"\n--- {label} @ {off} ---")
    print(repr(s))

# 1) 关键字符串上下文
for m, lbl in [(b'default.xml', 'default.xml'),
               (b'patch_cn', 'patch_cn'),
               (b'HaoJun0823', 'HaoJun0823')]:
    i = b.find(m)
    if i != -1:
        ctx(i, 80, 500, lbl)

# 2) 找 patched 里最大的“可读文本块”(>=1000 连续可打印)，定位嵌入 XML 主体
print("\n=== 最大可读文本块扫描 ===")
best = []
cur_start = -1
cur_len = 0
for i, byte in enumerate(b):
    if 32 <= byte < 127 or byte in (9, 10, 13):
        if cur_start == -1:
            cur_start = i
        cur_len += 1
    else:
        if cur_len >= 1000:
            best.append((cur_start, cur_len))
        cur_start = -1
        cur_len = 0
if cur_len >= 1000:
    best.append((cur_start, cur_len))
best.sort(key=lambda x: -x[1])
print(f"找到 {len(best)} 个 >=1KB 可读块，最大前 5:")
for off, ln in best[:5]:
    print(f"  @ {off}  长度 {ln} B ({(ln/1024):.1f} KB)")
    # 抽样开头
    print("   样本:", repr(b[off:off+300]))

# 3) konsi1 节内容（新节，64KB）
def pe_sections(b):
    e_lfanew = struct.unpack_from('<I', b, 0x3c)[0]
    pe = e_lfanew + 4
    nsec = struct.unpack_from('<H', b, pe + 2)[0]
    opt_hdr_size = struct.unpack_from('<H', b, pe + 16)[0]
    nt = pe + 20 + opt_hdr_size
    secs = []
    for i in range(nsec):
        off = nt + i*40
        name = b[off:off+8].split(b'\x00')[0].decode('latin1','replace')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', b, off+8)
        secs.append((name, vsize, vaddr, rawsize, rawptr))
    return secs

print("\n=== konsi1 新节内容抽样 ===")
for name, vsize, vaddr, rawsize, rawptr in pe_sections(b):
    if name == 'konsi1':
        print(f"  rawptr={rawptr} rawsize={rawsize}")
        print("  前256字节:", repr(b[rawptr:rawptr+256]))
        # 看是否含常见代码特征
        print("  含 'patch_cn'? ", b'patch_cn' in b[rawptr:rawptr+rawsize])
        print("  含 'default.xml'? ", b'default.xml' in b[rawptr:rawptr+rawsize])

# 4) 各节零字节占比（看是不是大量填充）
print("\n=== patched 各节零字节占比 ===")
for name, vsize, vaddr, rawsize, rawptr in pe_sections(b):
    seg = b[rawptr:rawptr+rawsize]
    zeros = seg.count(b'\x00')
    print(f"  {name:<8} rawsize={rawsize:>8}  零字节={zeros:>8} ({zeros*100//rawsize}%)")
