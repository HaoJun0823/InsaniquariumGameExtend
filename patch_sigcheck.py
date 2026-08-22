#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_sigcheck.py — 一次性“禁用 Game.exe 对 properties 文件的 .sig 签名校验”的磁盘补丁

背景（已用 IDA 反汇编 + 运行时日志双重验证）：
  Game.exe 在 sub_486DF0 里加载 partner.xml / resources.xml 等 .properties 文件，
  并调用虚函数 sub_493820 做 .sig 签名校验；校验失败时走到：
      0x486E7E   0F 85 A8 01 00 00   jnz 0x48702C   ; AL!=0(成功) 才跳走
      0x486E84   68 EC FA 5B 00      push "Signature check failed on "
  只要把这条 jnz 改成【无条件 jmp】，报错分支就永远不可达 —— 签名校验被彻底禁用，
  被改的 partner.xml 等也能正常加载。
  "Signature check failed on " 全局仅有这 1 处引用，所以这是唯一要改的指令。

为什么用“磁盘补丁”而不是 DLL 注入：
  DLL 注入（InsaniquariumGameExtend.dll + ModLoader）在逻辑上正确，但依赖“游戏必须经
  ModLoader 启动、且注入发生在签名校验之前”。一旦用户直接双击 Game.exe / 走 DRM 启动器
  （会把 Game.exe 解压到临时目录另起进程），注入就不会发生或太晚，于是弹窗照旧出现。
  磁盘补丁直接改 Game.exe 本体，与启动方式无关，100% 可靠。

安全性：
  1) 改前自动备份为 Game.exe.orig（已存在则跳过备份）；
  2) 版本指纹校验：必须先是 0F 85 A8 01 00 00，否则拒绝改写（防止改错版本）；
  3) 只改这 6 字节，不影响任何函数布局 / 地址，不会破坏其它 hook 基准；
  4) 想恢复：把 Game.exe.orig 复制回 Game.exe 即可。

用法：
  python3 patch_sigcheck.py            # 默认处理脚本同目录的 Game.exe
  python3 patch_sigcheck.py "D:/path/to/Game.exe"
"""
import os
import sys
import struct
import shutil

# 要改的指令位置（RVA，已扣掉 ImageBase 0x400000）
TARGET_RVA = 0x86E7E
# 原版字节：jnz rel32（兼作版本指纹）
ORIG_BYTES = bytes([0x0F, 0x85, 0xA8, 0x01, 0x00, 0x00])
# 补丁后字节：jmp rel32(rel+1) + nop，保持 6 字节、跳转目标不变
PATCH_BYTES = bytes([0xE9, 0xA9, 0x01, 0x00, 0x00, 0x90])


def rva_to_file_offset(rva, sections):
    """根据 PE 节表把 RVA 换算成文件偏移。"""
    for (name, va, vsize, raw, rawsize) in sections:
        # 节在内存里占 max(vsize, rawsize)
        span = max(vsize, rawsize)
        if va <= rva < va + span:
            return raw + (rva - va)
    return None


def parse_sections(data):
    """返回 [(name, VirtualAddress, VirtualSize, PointerToRawData, SizeOfRawData), ...]"""
    if data[:2] != b"MZ":
        raise ValueError("不是合法的 MZ 文件")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("找不到 PE 头")
    # COFF 头：NumberOfSections 在 e_lfanew+4+2
    num_sec = struct.unpack_from("<H", data, e_lfanew + 4 + 2)[0]
    # Optional header size在 e_lfanew+4+16
    opt_size = struct.unpack_from("<H", data, e_lfanew + 4 + 16)[0]
    sec_tbl_off = e_lfanew + 4 + 20 + opt_size
    sections = []
    for i in range(num_sec):
        off = sec_tbl_off + i * 40
        name = data[off:off + 8].split(b"\x00")[0].decode("latin1", "replace")
        vsize = struct.unpack_from("<I", data, off + 8)[0]
        va = struct.unpack_from("<I", data, off + 12)[0]
        rawsize = struct.unpack_from("<I", data, off + 16)[0]
        raw = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((name, va, vsize, raw, rawsize))
    return sections


def main():
    if len(sys.argv) > 1:
        game_path = sys.argv[1]
    else:
        game_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Game.exe")

    if not os.path.isfile(game_path):
        print(f"[错误] 找不到 Game.exe：{game_path}")
        return 2

    bak = game_path + ".orig"
    if not os.path.isfile(bak):
        shutil.copy2(game_path, bak)
        print(f"[备份] 已备份原版到 {bak}")
    else:
        print(f"[信息] 备份已存在，跳过：{bak}")

    with open(game_path, "rb") as f:
        data = bytearray(f.read())

    sections = parse_sections(data)
    off = rva_to_file_offset(TARGET_RVA, sections)
    if off is None:
        print(f"[错误] 无法把 RVA 0x{TARGET_RVA:X} 映射到文件偏移（节表异常？）")
        return 2

    current = bytes(data[off:off + 6])
    print(f"[检查] RVA=0x{TARGET_RVA:X} -> 文件偏移=0x{off:X}  当前字节="
          f"{' '.join(f'{b:02X}' for b in current)}")

    if current == PATCH_BYTES:
        print("[信息] 已经打过补丁（已是 jmp），无需重复操作。")
        return 0

    if current != ORIG_BYTES:
        print("[错误] 字节不是预期的 0F 85 A8 01 00 00（版本/文件不匹配），拒绝改写以防改错。")
        print("        请确认这是未做其它修改的原版 Game.exe；若已用其它方式改过，请先恢复。")
        return 2

    data[off:off + 6] = PATCH_BYTES
    with open(game_path, "wb") as f:
        f.write(data)

    # 验证：重新读回
    with open(game_path, "rb") as f:
        chk = f.read()
    if bytes(chk[off:off + 6]) == PATCH_BYTES:
        print(f"[成功] 已将 jnz -> jmp（{off:#X} 处）。签名校验已禁用，被改的 partner.xml 可正常加载。")
        print("[提示] 恢复方法：把 Game.exe.orig 复制回 Game.exe。")
        return 0
    else:
        print("[错误] 写入后校验失败，请检查磁盘权限。")
        return 2


if __name__ == "__main__":
    sys.exit(main())
