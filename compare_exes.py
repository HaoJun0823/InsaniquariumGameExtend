# -*- coding: utf-8 -*-
import hashlib, struct, os

clean_path   = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\Game.exe"
patched_path = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\old_cn_patch\patch_cn\怪怪水族箱.exe"

def read(p):
    with open(p, 'rb') as f:
        return f.read()

def sha(b):
    return hashlib.sha256(b).hexdigest()

def pe_sections(b):
    e_lfanew = struct.unpack_from('<I', b, 0x3c)[0]
    pe = e_lfanew + 4
    # COFF header
    machine, nsec = struct.unpack_from('<HH', b, pe)
    opt_hdr_size = struct.unpack_from('<H', b, pe + 16)[0]
    opt_hdr = pe + 20
    magic = struct.unpack_from('<H', b, opt_hdr)[0]  # 0x10b=32bit
    nt_hdr_size = opt_hdr + opt_hdr_size
    secs = []
    for i in range(nsec):
        off = nt_hdr_size + i * 40
        name = b[off:off+8].split(b'\x00')[0].decode('latin1', 'replace')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', b, off + 8)
        secs.append((name, vsize, vaddr, rawsize, rawptr))
    return machine, magic, nsec, secs

clean   = read(clean_path)
patched = read(patched_path)

print("=== 基本信息 ===")
print(f"clean   : {len(clean):>10} B  sha={sha(clean)[:16]}...")
print(f"patched : {len(patched):>10} B  sha={sha(patched)[:16]}...")
print(f"差值     : {len(patched)-len(clean):>10} B  ({ (len(patched)-len(clean))/1024/1024:.2f} MB)")

print("\n=== PE 节表对比 ===")
mc, mg, nc, sc = pe_sections(clean)
mp, mgp, np, sp = pe_sections(patched)
print(f"clean   machine={hex(mc)} magic={hex(mg)} nsec={nc}")
for s in sc:
    print(f"   {s[0]:<8} vsize={s[1]:>8} vaddr={s[2]:>8} rawsize={s[3]:>8} rawptr={s[4]:>8}")
print(f"patched machine={hex(mp)} magic={hex(mgp)} nsec={np}")
for s in sp:
    print(f"   {s[0]:<8} vsize={s[1]:>8} vaddr={s[2]:>8} rawsize={s[3]:>8} rawptr={s[4]:>8}")

print("\n=== 关键字符串定位 (clean@ / patched@) ===")
markers = [b'patch_cn', b'default.xml', b'partner.xml', b'resources.xml',
           b'HaoJun0823', b'<?xml', b'<Properties', b'<property',
           b'properties\\', b'properties/', b'.InsaniquariumDeluxe']
for m in markers:
    c = clean.find(m)
    p = patched.find(m)
    print(f"  {m.decode('latin1'):<22} clean={c:>9}  patched={p:>9}")

print("\n=== 嵌入 XML 量估算（patched 内）===")
# 在 patched 里找 default.xml 起止，量出大致 blob
i = patched.find(b'<?xml')
j = patched.find(b'default.xml')
k = patched.find(b'<Properties')
print(f"  <?xml @ {i}, <Properties @ {k}, default.xml @ {j}")
if k != -1:
    # 从 <Properties 往后找结束标记 </Properties>
    end = patched.find(b'</Properties>', k)
    if end != -1:
        blob = patched[k:end+len(b'</Properties>')]
        print(f"  <Properties> blob 大小 = {len(blob)} B ({(len(blob)/1024):.1f} KB)")
        # 抽样
        sample = blob[:400]
        try:
            print("  抽样(前400字节):", sample.decode('utf-8', 'replace')[:400])
        except Exception as e:
            print("  抽样失败", e)

# 统计 patched 比 clean 多出来的“可读文本”规模：扫描 patched 中 ascii 连续>=4 的片段总字节
def ascii_text_bytes(b):
    total = 0
    cur = 0
    for byte in b:
        if 32 <= byte < 127:
            cur += 1
        else:
            if cur >= 4:
                total += cur
            cur = 0
    if cur >= 4:
        total += cur
    return total

print(f"\n=== 可读 ASCII 文本总量 ===")
print(f"  clean   : {ascii_text_bytes(clean)/1024:.1f} KB")
print(f"  patched : {ascii_text_bytes(patched)/1024:.1f} KB")
print(f"  差值     : {(ascii_text_bytes(patched)-ascii_text_bytes(clean))/1024:.1f} KB")
