#include "pch.h"
#include "Patch.h"
#include "Logger.h"
#include <cstring>
#include <cstdio>

namespace {

const char* kCategory = "[Patch]";

bool ProtectAndWrite(uintptr_t addr, const uint8_t* data, size_t size) {
    if (addr == 0 || size == 0) return false;
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(addr), size,
                        PAGE_EXECUTE_READWRITE, &old)) {
        LOG_ERROR(kCategory, "VirtualProtect failed at 0x%X (err=%lu)", (unsigned)addr, GetLastError());
        return false;
    }
    memcpy(reinterpret_cast<void*>(addr), data, size);
    // 刷新指令缓存，避免 CPU 仍执行旧指令
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), size);
    // 恢复原始页保护
    DWORD tmp = 0;
    VirtualProtect(reinterpret_cast<LPVOID>(addr), size, old, &tmp);
    return true;
}

} // namespace

namespace Patch {

bool WriteJmp(uintptr_t target, uintptr_t cave, int nopCount) {
    if (target == 0 || cave == 0) return false;
    int32_t rel = static_cast<int32_t>(cave - (target + 5));
    // E9 + rel32，rel32 = cave - (target + 5)
    // 5 字节 jmp + 最多 16 字节 NOP 填充
    uint8_t buf[5 + 16];
    buf[0] = 0xE9;
    memcpy(&buf[1], &rel, 4);
    int nops = nopCount > 0 ? nopCount : 0;
    if (nops > 16) nops = 16;
    for (int i = 0; i < nops; ++i) buf[5 + i] = 0x90;
    LOG_DEBUG(kCategory, "WriteJmp target=0x%X cave=0x%X nop=%d", (unsigned)target, (unsigned)cave, nops);
    return ProtectAndWrite(target, buf, static_cast<size_t>(5 + nops));
}

bool WriteBytes(uintptr_t addr, const uint8_t* data, size_t size) {
    return ProtectAndWrite(addr, data, size);
}

bool WriteU8(uintptr_t addr, uint8_t v) {
    return ProtectAndWrite(addr, &v, 1);
}

bool WriteU32(uintptr_t addr, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF),
                     (uint8_t)((v >> 16) & 0xFF), (uint8_t)((v >> 24) & 0xFF) };
    return ProtectAndWrite(addr, b, 4);
}

bool WritePointer(uintptr_t addr, uintptr_t ptr) {
    // 32 位进程：指针本身是 4 字节
    return WriteU32(addr, static_cast<uint32_t>(ptr));
}

std::vector<uint8_t> ReadBytes(uintptr_t addr, size_t size) {
    std::vector<uint8_t> out;
    if (addr == 0 || size == 0) return out;
    out.resize(size);
    memcpy(out.data(), reinterpret_cast<const void*>(addr), size);
    return out;
}

bool ReadMemory(uintptr_t addr, void* out, size_t size) {
    if (addr == 0 || !out || size == 0) return false;
    __try {
        memcpy(out, reinterpret_cast<const void*>(addr), size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR(kCategory, "ReadMemory fault at 0x%X", (unsigned)addr);
        return false;
    }
}

bool WriteMemory(uintptr_t addr, const void* data, size_t size) {
    return ProtectAndWrite(addr, static_cast<const uint8_t*>(data), size);
}

bool EnsureWritable(uintptr_t addr, size_t size) {
    if (addr == 0 || size == 0) return false;
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(addr), size,
                        PAGE_EXECUTE_READWRITE, &old)) {
        LOG_ERROR(kCategory, "EnsureWritable VirtualProtect failed at 0x%X", (unsigned)addr);
        return false;
    }
    return true;
}

bool JnzToJmp(uintptr_t addr, int expectRel, std::string& detail) {
    // 先用 ReadProcessMemory 安全试读（地址非法时它只会返回失败，不会让进程崩溃）
    unsigned char orig[6] = {};
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, orig, 6, &got)
        || got != 6) {
        detail = "target address unreadable (wrong base/version?)";
        return false;
    }

    char hex[64];
    snprintf(hex, sizeof(hex), "%02X %02X %02X %02X %02X %02X",
             orig[0], orig[1], orig[2], orig[3], orig[4], orig[5]);
    detail = std::string("orig bytes = ") + hex;

    if (orig[0] != 0x0F || orig[1] != 0x85) {
        detail += " (expected 0F 85 = jnz rel32, mismatch)";
        return false;
    }
    int rel = *(int*)(orig + 2);
    if (rel != expectRel) {
        char b[96];
        snprintf(b, sizeof(b), " (rel32 expected 0x%X, actual 0x%X, version mismatch)",
                 expectRel, rel);
        detail += b;
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect((void*)addr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        detail += " (VirtualProtect failed)";
        return false;
    }
    unsigned char* p = (unsigned char*)addr;
    p[0] = 0xE9;                // jmp rel32
    *(int*)(p + 1) = rel + 1;   // 目标不变：基准从 addr+6 变为 addr+5
    p[5] = 0x90;                // nop，保持总长度 6 字节
    VirtualProtect((void*)addr, 6, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, 6);
    return true;
}

bool PlausiblePtr(const void* p) {
    uintptr_t v = (uintptr_t)p;
    return v >= 0x10000 && v <= 0x7FFEFFFF;
}

std::string Hex(uintptr_t v) {
    char b[24];
    snprintf(b, sizeof(b), "0x%08X", (unsigned int)v);
    return std::string(b);
}

} // namespace Patch
