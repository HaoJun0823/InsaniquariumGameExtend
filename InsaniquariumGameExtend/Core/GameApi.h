// GameApi.h
// ===================================================================
// 所有从 Game.exe 导入/钩入的游戏函数地址与类型统一集中声明于此，
// 便于维护与扩展。任何 Feature 不得自行散落声明游戏函数指针/地址，
// 一律走本文件。
//
// 使用方式：
//   1. 在 Feature 的 OnInstall 里先调用 gameapi::Init(ver.GetBaseAddress());
//      （可重复调用，幂等）
//   2. 之后用 gameapi::Va(0xXXXXXX) 获取运行时地址，
//      或用 gameapi::VaToRva(0xXXXXXX) 获取 RVA。
//
// 新增一个游戏函数地址（以后要 hook / call 更多游戏函数时照此办理）：
//   1. 在下方 addr:: 命名空间补 VA 常量（基址 0x400000 下的地址）；
//   2. 如需函数指针类型，在 "函数指针" 区补 typedef；
//   3. 如需 Init 自动绑定，在 GameApi.cpp 的 s_bindings 加一行。
// ===================================================================
#pragma once
#include <cstdint>

// IDA 风格整型别名（非标准 C++，这里补齐定义；与 IDA 反编译伪代码一致）
typedef unsigned int  _DWORD;
typedef unsigned char _BYTE;

namespace gameapi {

// 运行时镜像基址（由 Init 设置；游戏无 ASLR，通常恒为 0x400000）
extern uintptr_t g_imageBase;

// 用实际基址初始化（可重复调用）
void Init(uintptr_t imageBase);

// VA（0x400000 基址下的地址）-> 运行时地址
template <typename T = void*>
inline T Va(uintptr_t va) {
    return (T)(g_imageBase + (va - 0x400000));
}

// VA -> RVA（相对虚拟地址）
inline uintptr_t VaToRva(uintptr_t va) { return va - 0x400000; }

// ---- 关键地址（0x400000 基址下的 VA）----
namespace addr {
    // ---- 签名校验 ----
    // sub_486DF0 内的 jnz：校验失败 -> 弹 FATAL ERROR 的条件跳转
    constexpr uintptr_t SigFailJnz   = 0x486E7E;
    constexpr int       SigFailJnzRel = 0x1A8;  // 原始 rel32，兼作"版本指纹"

    // sub_493820 = .sig 签名校验器（vtable 槽 +0x168）
    constexpr uintptr_t SigCheckFunc  = 0x493820;

    // ---- 商店扩展 hook 目标 ----
    // sub_5409B0: 通用按钮工厂（30+ 调用者），slot>=7 越界崩溃
    constexpr uintptr_t Sub5409B0 = 0x5409B0;
    // sub_541200: 商店按关初始化（门控+分槽）
    constexpr uintptr_t Sub541200 = 0x541200;
    // sub_538090: 当前道具按钮指针闸门（购买/点击总闸门）
    constexpr uintptr_t Sub538090 = 0x538090;
}

// ---- 函数指针类型（签名来自 IDA 反编译实证）----
// sub_5409B0: __thiscall(self, a2=itemIdx, a3=visible) -> 按钮指针
typedef _DWORD* (__thiscall* Fn5409B0)(_DWORD* self, int a2, int a3);
// sub_541200: __thiscall(self) -> int（商店按关初始化）
typedef int     (__thiscall* Fn541200)(_DWORD* self);
// sub_538090: __thiscall(self, a2=itemIdx) -> 按钮指针（购买闸门）
typedef _DWORD* (__thiscall* Fn538090)(_DWORD* self, int a2);

} // namespace gameapi
