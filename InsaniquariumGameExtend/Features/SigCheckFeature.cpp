// SigCheckFeature.cpp
// ===================================================================
// [SigCheck]
// 禁用 .sig 签名校验，让被修改的 partner.xml 等资源文件能正常加载。
//
// 背景（逆向结论）：
//   Game.exe 在加载 partner.xml 等资源时会做 .sig 签名校验（sub_493820），
//   校验失败则弹 FATAL ERROR 并终止。本项目需要改资源文件（汉化等），
//   故必须绕过此校验。
//
// 两种禁用方式（INI [SigCheck] Method 选择）：
//   Method = 1（默认）= 分支补丁：改 sub_486DF0 里的 jnz -> jmp，
//     报错分支永不可达。这是弹窗的唯一来源（"Signature check failed on "
//     全局仅 1 处引用）。不依赖调用约定、不需要 naked 汇编 stub。
//   Method = 2 = 函数替换：把 sub_493820（.sig 校验器）整体换成
//     永远返回成功(1)的 stub（mov al,1 / ret 8，平衡 __thiscall 栈）。
//
// 默认启用（Enabled = 1）。INI 仅作为恢复原版的逃生口。
//
// 配置（InsaniquariumGameExtend.ini）：
//   [SigCheck]
//   Enabled = 1        ; 1 = 禁用签名校验（默认）；0 = 恢复原版
//   Method  = 1        ; 1 = 分支补丁（默认）；2 = 函数替换
// ===================================================================
#include "pch.h"
#include "Core/Feature.h"
#include "Core/IniConfig.h"
#include "Core/GameVersion.h"
#include "Core/Patch.h"
#include "Core/Logger.h"
#include "Core/GameApi.h"

namespace fe_sigcheck {

const char* kName = "SigCheck";
const char* kCat  = "[SigCheck]";

// 签名校验 stub：与被替换的 sub_493820 保持同一调用约定 ——
//   char __thiscall(void* this, int a2, int a3)
// 我们直接让"校验结果"= 成功（AL=1），并用 `ret 8` 清掉 2 个 4 字节的
// 栈参数(a2,a3)，与 __thiscall 约定一致（this 在 ECX，stub 里不碰它）。
__declspec(naked) void SigCheckStub() {
    __asm {
        mov al, 1      ; 返回"校验成功"
        ret 8          ; 清掉 2 个栈参数（__thiscall 调用约定）
    }
}

class SigCheckFeature : public Feature {
public:
    const char* GetName() const override { return kName; }
    GameTarget  GetTarget() const override { return GameTarget::Game; }

    bool OnInstall(IniConfig& cfg, GameVersion& ver) override {
        gameapi::Init(ver.GetBaseAddress());
        uintptr_t base = ver.GetBaseAddress();

        LOG_INFO(kCat, "Game.exe base = %s (link base = 0x400000)",
                 Patch::Hex(base).c_str());

        int method = cfg.GetInt(kName, "Method", 1);
        LOG_INFO(kCat, "Method = %d", method);

        if (method == 2) {
            return InstallMethod2(base);
        }
        return InstallMethod1(base);
    }

private:
    // ---- 方式 1（默认）：分支补丁 ----
    // 把 sub_486DF0 内的 jnz(0F 85) 改写成 jmp(E9)，报错分支永不可达。
    bool InstallMethod1(uintptr_t base) {
        uintptr_t jnzAddr = gameapi::Va<uintptr_t>(gameapi::addr::SigFailJnz);
        LOG_INFO(kCat, "[Method1] target = jnz in sub_486DF0  VA=%s  RVA=%s  runtime=%s",
                 Patch::Hex(gameapi::addr::SigFailJnz).c_str(),
                 Patch::Hex(gameapi::VaToRva(gameapi::addr::SigFailJnz)).c_str(),
                 Patch::Hex(jnzAddr).c_str());

        std::string detail;
        if (!Patch::JnzToJmp(jnzAddr, gameapi::addr::SigFailJnzRel, detail)) {
            LOG_ERROR(kCat, "patch failed: %s", detail.c_str());
            LOG_ERROR(kCat, "Please verify you are using the unmodified original Game.exe; "
                     "or try Method=2 in INI.");
            return false;
        }
        LOG_INFO(kCat, "[Method1] %s", detail.c_str());

        // 写入后读回验证
        unsigned char after[6] = {};
        Patch::ReadMemory(jnzAddr, after, 6);
        char hx[64];
        snprintf(hx, sizeof(hx), "%02X %02X %02X %02X %02X %02X",
                 after[0], after[1], after[2], after[3], after[4], after[5]);
        if (after[0] == 0xE9 && after[5] == 0x90)
            LOG_INFO(kCat, "[OK] SigCheck disabled (Method1: jnz -> jmp). patched bytes = %s", hx);
        else
            LOG_WARN(kCat, "[WARN] patch written but readback unexpected, bytes = %s", hx);
        return true;
    }

    // ---- 方式 2（备选）：函数替换 ----
    // 把 sub_493820（.sig 校验器）整体换成永远返回成功的 stub。
    bool InstallMethod2(uintptr_t base) {
        uintptr_t target = gameapi::Va<uintptr_t>(gameapi::addr::SigCheckFunc);
        LOG_INFO(kCat, "[Method2] target = sub_493820  VA=%s  RVA=%s  runtime=%s",
                 Patch::Hex(gameapi::addr::SigCheckFunc).c_str(),
                 Patch::Hex(gameapi::VaToRva(gameapi::addr::SigCheckFunc)).c_str(),
                 Patch::Hex(target).c_str());

        // 探测入口前 2 字节（原版应为 6A FF = push -1）
        unsigned char probe[2] = {};
        if (!Patch::ReadMemory(target, probe, 2)) {
            LOG_ERROR(kCat, "target address unreadable (need unmodified original Game.exe).");
            return false;
        }
        char hx[16];
        snprintf(hx, sizeof(hx), "%02X %02X", probe[0], probe[1]);
        LOG_INFO(kCat, "[Method2] first 2 bytes = %s (original should be 6A FF = push -1)", hx);

        if (!Patch::WriteJmp(target, (uintptr_t)&SigCheckStub, 0)) {
            LOG_ERROR(kCat, "hook install failed (VirtualProtect/write).");
            return false;
        }

        // 写入验证
        unsigned char verify = 0;
        Patch::ReadMemory(target, &verify, 1);
        if (verify == 0xE9)
            LOG_INFO(kCat, "[OK] SigCheck disabled (Method2: .sig checker always returns success).");
        else
            LOG_WARN(kCat, "[WARN] write returned success but first byte is not JMP(0xE9).");
        return true;
    }
};

REGISTER_FEATURE(SigCheckFeature)

} // namespace fe_sigcheck
