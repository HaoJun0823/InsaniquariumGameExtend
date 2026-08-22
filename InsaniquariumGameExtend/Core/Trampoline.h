#pragma once
#include <cstdint>
#include <cstring>
#include <windows.h>

// 跳板式 inline hook（x86, 32 位；被偷指令含 ECX(this)，__thiscall 安全）。
//
// 工作原理：
//   1. 偷走目标函数入口前 N 字节（N >= 5 且停在指令边界）；
//   2. 分配一块可执行内存（跳板），把偷走的字节复制进去，
//      末尾追加 JMP rel32 跳回 原函数+N（= 原函数偷走指令之后的位置）；
//   3. 把目标函数入口改写为 JMP rel32 -> hookFn；
//   4. hookFn 可通过 trampoline 指针调用原函数（执行被偷指令后跳回）。
//
// stolen 字节数必须实测（dump 本地 exe 前导字节），误判会切断指令导致
// DLL 内恒定偏移崩溃。

struct InlineHook {
    uintptr_t target;     // 原函数入口 VA（运行时）
    uintptr_t hookFn;     // 我们的 hook 函数（通常是 __declspec(naked) 中继）
    uintptr_t trampoline; // 跳板：执行被偷指令后跳回原函数
    unsigned char saved[32];
    int stolen;           // 偷走的字节数（须 >= 5 且停在指令边界）
};

// 安装跳板 hook。成功后 h.trampoline 可作为"调用原函数"的函数指针。
// 失败返回 false（VirtualAlloc 或 VirtualProtect 失败）。
bool MakeTrampoline(InlineHook& h);
