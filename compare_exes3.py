# -*- coding: utf-8 -*-
import struct

clean_path   = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\Game.exe"
patched_path = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\old_cn_patch\patch_cn\怪怪水族箱.exe"
clean   = open(clean_path, 'rb').read()
patched = open(patched_path, 'rb').read()

def find_utf16(b, s):
    # s 为 ascii 关键字，在 b 里按 UTF-16LE 查找
    pat = ''.join(ch + '\x00' for ch in s).encode('latin1')
    return b.find(pat)

print("=== UTF-16 关键字查找（patched）===")
for s in ['<?xml', '<Properties', 'default.xml', 'patch_cn', 'HaoJun0823', 'properties']:
    i = find_utf16(patched, s)
    print(f"  UTF16 '{s}': patched@{i}")

print("\n=== CJK(中文) UTF-16 字节统计（patched）===")
# UTF-16LE 中文：高字节(奇数索引)在 0x4E..0x9F，低字节(偶数索引)任意 0x00..0xFF
cjk_runs = []
i = 1
run_start = -1
while i < len(patched) - 1:
    hi = patched[i]
    if 0x4E <= hi <= 0x9F:
        if run_start == -1:
            run_start = i - 1
    else:
        if run_start != -1:
            cjk_runs.append((run_start, i - run_start))
            run_start = -1
    i += 2
if run_start != -1:
    cjk_runs.append((run_start, len(patched) - run_start))
total_cjk = sum(r[1] for r in cjk_runs)
cjk_runs.sort(key=lambda x: -x[1])
print(f"  CJK 总字节(UTF-16 计) = {total_cjk} B ({(total_cjk/1024):.1f} KB)，运行块数={len(cjk_runs)}")
print(f"  最大前3块: {[(hex(o), ln) for o,ln in cjk_runs[:3]]}")
if cjk_runs:
    o, ln = cjk_runs[0]
    # 解码最大块的前 200 字符
    seg = patched[o:o+ln]
    txt = seg.decode('utf-16-le', 'replace')
    print("  最大块样本(前300字符):", txt[:300])

print("\n=== 文件级最长公共前缀（clean vs patched）===")
n = min(len(clean), len(patched))
prefix = 0
while prefix < n and clean[prefix] == patched[prefix]:
    prefix += 1
print(f"  公共前缀长度 = {prefix} B ({(prefix/1024):.1f} KB)")
print(f"  此后 clean[{prefix}]={clean[prefix]:#04x}  patched[{prefix}]={patched[prefix]:#04x}")

print("\n=== .text 节内：patched 比 clean 多出的部分定位 ===")
def sec(b, name):
    e = struct.unpack_from('<I', b, 0x3c)[0]
    pe = e + 4
    nsec = struct.unpack_from('<H', b, pe+2)[0]
    ohs = struct.unpack_from('<H', b, pe+16)[0]
    nt = pe + 20 + ohs
    for i in range(nsec):
        off = nt + i*40
        nm = b[off:off+8].split(b'\x00')[0].decode('latin1','replace')
        vs, va, rs, rp = struct.unpack_from('<IIII', b, off+8)
        if nm == name:
            return rp, rs
    return None, None

crp, crs = sec(clean, '.text')
prp, prs = sec(patched, '.text')
print(f"  clean .text: rawptr={crp} rawsize={crs}")
print(f"  patched .text: rawptr={prp} rawsize={prs}")
# 比较共同长度内的重叠
common = min(crs, prs)
j = 0
while j < common and clean[crp+j] == patched[prp+j]:
    j += 1
print(f"  .text 内公共前缀 = {j} B；clean .text 总长 {crs}，patched .text 总长 {prs}")
print(f"  若 patched .text = clean .text 前缀 + 追加：追加量 = {prs - j} B")
# 看 patched .text 末尾区域是否为 CJK/XML
tail = patched[prp+prs-2000:prp+prs]
cjk_tail = sum(1 for k in range(1, len(tail)-1, 2) if 0x4E <= tail[k] <= 0x9F)
print(f"  patched .text 末尾2KB 内 CJK 高字节出现 {cjk_tail} 次")
