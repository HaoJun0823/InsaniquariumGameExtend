#include "pch.h"
#include "Trampoline.h"
#include "Logger.h"

namespace {
const char* kCategory = "[Trampoline]";
} // namespace

bool MakeTrampoline(InlineHook& h) {
    unsigned char* t = (unsigned char*)h.target;
    memcpy(h.saved, t, h.stolen);

    // 跳板内存：stolen 字节 + JMP rel32(5)
    h.trampoline = (uintptr_t)VirtualAlloc(NULL, h.stolen + 5,
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!h.trampoline) {
        LOG_ERROR(kCategory, "VirtualAlloc failed for trampoline (stolen=%d)", h.stolen);
        return false;
    }
    unsigned char* tr = (unsigned char*)h.trampoline;
    memcpy(tr, h.saved, h.stolen);
    intptr_t rel = (intptr_t)(h.target + h.stolen) - (intptr_t)(tr + h.stolen + 5);
    tr[h.stolen] = 0xE9;
    *(int*)(tr + h.stolen + 1) = (int)rel;

    // 改写 target 入口为 JMP rel32 -> hookFn；多余字节填 NOP
    DWORD op;
    if (!VirtualProtect(t, h.stolen, PAGE_EXECUTE_READWRITE, &op)) {
        LOG_ERROR(kCategory, "VirtualProtect failed at target 0x%X (stolen=%d)", (unsigned)h.target, h.stolen);
        return false;
    }
    rel = (intptr_t)h.hookFn - (intptr_t)(t + 5);
    t[0] = 0xE9;
    *(int*)(t + 1) = (int)rel;
    for (int i = 5; i < h.stolen; i++) t[i] = 0x90;
    VirtualProtect(t, h.stolen, op, &op);
    FlushInstructionCache(GetCurrentProcess(), t, h.stolen);
    return true;
}
