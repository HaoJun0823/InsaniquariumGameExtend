// dllmain.cpp : Insaniquarium mod DLL 入口
// ---------------------------------------------------------------------------
// 本 DLL 由 InsaniquariumModLoader 通过 CreateRemoteThread(LoadLibraryA) 注入到
// Game.exe 进程里。ModLoader 在 CREATE_SUSPENDED 状态下注入，因此 DllMain
// 执行时游戏主线程还处于挂起状态，所有 hook 必须在 DllMain 返回前安装完毕。
//
// 职责：
//   1. 初始化日志
//   2. 首次运行自动生成默认配置 INI
//   3. 加载 INI 配置
//   4. 检测游戏版本
//   5. 调用 FeatureManager 安装全部已启用的 Feature
//
// 位数：本 DLL 必须编译为 32 位（Win32），因为 Game.exe 是 32 位进程。
// ---------------------------------------------------------------------------
#include "pch.h"
#include "Core/Logger.h"
#include "Core/IniConfig.h"
#include "Core/GameVersion.h"
#include "Core/Feature.h"
#include "Core/FeatureManager.h"
#include "Core/Paths.h"

// ---- Feature 实现文件（直接 include 进本翻译单元，使 REGISTER_FEATURE
//      宏的静态对象在 DllMain 前完成自注册）----
#include "Features/SigCheckFeature.cpp"
#include "Features/StoreAllFishFeature.cpp"

// 首次运行（INI 不存在）时，自动生成一份带注释的默认配置文件。
// 默认全部启用（Enabled = 1），与项目"开箱即用"的设计一致。
static void EnsureDefaultIni()
{
    std::string path = ge_paths::IniPath();
    { std::ifstream pf(path); if (pf) return; }  // 已存在 -> 保留用户设置
    std::ofstream out(path);
    if (!out) return;
    out
        << "; InsaniquariumGameExtend 配置文件\n"
        << "; 与本 DLL 放在同一目录（即 ModLoader.exe 同级目录）。\n"
        << "; 修改后下次启动游戏生效。\n"
        << "\n"
        << "[SigCheck]\n"
        << "; ---- 签名校验 ----\n"
        << "; 禁用 .sig 签名校验（让被修改的 partner.xml 等能正常加载）\n"
        << "; 1 = 禁用（默认，推荐）；0 = 恢复原版（仍做签名校验）\n"
        << "Enabled = 1\n"
        << "\n"
        << "; 禁用方式\n"
        << "; 1 = 分支补丁（改 sub_486DF0 的 jnz -> jmp，报错分支不可达）\n"
        << "; 2 = 函数替换（把 .sig 校验器整体换成永远返回成功）\n"
        << "Method = 1\n"
        << "\n"
        << "[StoreAllFish]\n"
        << "; ---- 商店扩展：提供所有鱼 ----\n"
        << "; 是否把被隐藏的鱼/道具也放到商店（分到 7..14 槽，双行显示），\n"
        << "; 含 6 种鱼 + 星药剂 + 捕星者，同时保留\"买 X 解锁 Y\"的科技树进度。\n"
        << "; 1 = 启用（默认）；0 = 完全回退原版商店逻辑\n"
        << "Enabled = 1\n";
    LOG_INFO("[Boot]", "Default config generated: %s", path.c_str());
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // ---- 1. 初始化日志 ----
        // 日志写到 DLL 同目录的 logs\InsaniquariumGameExtend.log
        std::string logDir = ge_paths::LogDir();
        CreateDirectoryA(logDir.c_str(), NULL);
        LogInit(logDir, ge_paths::kMainLog, LogLevel::Debug);
        LOG_INFO("[Boot]", "=== InsaniquariumGameExtend attached ===");
        LOG_INFO("[Boot]", "DLL_PROCESS_ATTACH hModule=0x%X", (unsigned)(uintptr_t)hModule);

        // ---- 2. 生成默认 INI（如不存在）----
        EnsureDefaultIni();

        // ---- 3. 加载 INI 配置 ----
        IniConfig cfg;
        std::string iniPath = ge_paths::IniPath();
        if (cfg.Load(iniPath)) {
            LOG_INFO("[Boot]", "INI loaded: %s", iniPath.c_str());
        } else {
            LOG_WARN("[Boot]", "INI not found or unreadable: %s (using defaults)", iniPath.c_str());
        }

        // ---- 4. 检测游戏版本 ----
        GameVersion ver;
        GameTarget target = ver.Detect(cfg);
        if (target == GameTarget::Unknown) {
            LOG_WARN("[Boot]", "Game version unknown; features with GameTarget::Game will be skipped.");
        }

        // ---- 5. 安装全部已启用的 Feature ----
        // 同步安装（而非另起工作线程）：本 DLL 由 ModLoader 在"挂起态"下注入，
        // DllMain 返回、ModLoader 调用 ResumeThread 之后游戏代码才会真正开始跑。
        // 因此在 DllMain 里直接把 hook 装好，能保证它先于游戏任何代码（包括
        // 启动期加载 partner.xml 并做 .sig 校验的那次调用）执行。
        // 这里只做"读 INI + 改目标函数入口字节"这类不触碰 Loader Lock 的轻量操作，
        // 不调用 LoadLibrary 等会死锁的 API，在 DllMain 内同步执行是安全的。
        size_t n = FeatureManager::InstallAll(cfg, ver);
        LOG_INFO("[Boot]", "Extend framework initialized, %zu feature(s) active.", n);
        break;
    }
    case DLL_PROCESS_DETACH:
        LOG_INFO("[Boot]", "DLL_PROCESS_DETACH");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
