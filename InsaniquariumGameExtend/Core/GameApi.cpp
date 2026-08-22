// GameApi.cpp
// 游戏函数指针的绑定表：所有从 Game.exe 导入的函数在此统一解析地址。
// 新增函数：在 s_bindings 加一行 { RVA, (void**)&指针 } 即可。
#include "pch.h"
#include "GameApi.h"

namespace gameapi {

uintptr_t g_imageBase = 0x400000;

namespace {
// RVA（相对 0x400000）-> 函数指针槽位；Init 时按实际基址统一填充。
struct Binding {
    uintptr_t rva;
    void** ppFn;
};

// 当前 Insaniquarium 无需直接绑定的游戏函数指针
// （hook 函数通过 Trampoline 的 trampoline 字段调用原函数，
//  不需要 GameApi 维护 extern 指针）。
// 保留一个占位元素 + nullptr 守卫，避免零长度数组（C2466）；
// 未来若需直接 call 游戏函数，在此追加 { rva, (void**)&SomeFunc }。
Binding s_bindings[] = {
    { 0, nullptr },
};

} // namespace

void Init(uintptr_t imageBase) {
    g_imageBase = imageBase;
    for (auto& b : s_bindings) {
        if (b.ppFn)
            *b.ppFn = reinterpret_cast<void*>(imageBase + b.rva);
    }
}

} // namespace gameapi
