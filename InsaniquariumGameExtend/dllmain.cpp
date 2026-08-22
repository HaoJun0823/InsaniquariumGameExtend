// dllmain.cpp : Insaniquarium mod DLL 入口
// ---------------------------------------------------------------------------
// 本 DLL 由 InsaniquariumModLoader 通过 CreateRemoteThread(LoadLibraryA) 注入到
// Game.exe 进程里。它的职责：
//   1. 写一条日志，证明“已成功注入”（用来验证整条注入链路是否打通）；
//   2. 在 DllMain 里（游戏主线程挂起期间）同步做 mod 初始化（见 ModInit）：
//      仅做“读 INI + 改少量指令字节”，不触碰 Loader Lock，安全；
//   3. 未来在这里挂接汉化、分辨率缩放等 hook（锚点已标注在 ModInit 里）。
//
// 位数：本 DLL 必须编译为 32 位（Win32），因为 Game.exe 是 32 位进程。
// ---------------------------------------------------------------------------

#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <mutex>
#include <cctype>

// 日志相关（线程安全，写到 DLL 同目录的 logs\ 下）
static std::string g_logDir;
static std::ofstream g_log;
static std::mutex    g_logMutex;

// 取【本 DLL 自身】所在目录（带结尾反斜杠）
// 注意：GetModuleFileName(NULL) 拿到的是宿主进程(Game.exe)的路径；
//       要拿 DLL 自己的路径，必须用本模块句柄。下面用“函数地址反查模块”的技巧。
static std::string GetSelfDir()
{
    char buf[MAX_PATH] = {0};
    HMODULE hSelf = NULL;
    // 用本函数自身的地址反查它所属的模块（即本 DLL）
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCSTR)&GetSelfDir, &hSelf);
    DWORD n = GetModuleFileNameA(hSelf, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::string s(buf);
    size_t pos = s.find_last_of("\\/");
    if (pos == std::string::npos) return {};
    return s.substr(0, pos + 1);
}

static void Log(const std::string& msg)
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_log.is_open()) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    char ts[32];
    snprintf(ts, sizeof(ts), "[%04hu-%02hu-%02hu %02hu:%02hu:%02hu] ",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    g_log << ts << msg << std::endl;
    g_log.flush();
}

// ---------------------------------------------------------------------------
// 内联 hook 辅助（最小实现）
// ---------------------------------------------------------------------------
// 把目标函数入口处的 5 字节改写成 `JMP rel32` 跳转到 stub。
// 适用于“完全替换目标函数行为”的场景（本文件里用于方式 2：替换 .sig 校验器
// sub_493820，VA 见下方常量，运行时用 VaToRva() 换算成 RVA）。
// 由于这种写法不会再去调用原函数，所以不需要 trampoline（跳板）。
static bool RedirectFunctionEntry(uintptr_t target, void* stub)
{
    if (!target || !stub) return false;

    // 计算 5 字节相对跳转偏移：JMP 指令占 5 字节（E9 + 4 字节 rel32），
    // rel32 = stub 地址 - (target + 5)。
    intptr_t rel = (intptr_t)((uintptr_t)stub - (target + 5));
    if (rel < INT_MIN || rel > INT_MAX) return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect((void*)target, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    // E9 xx xx xx xx  ——  JMP rel32
    *(unsigned char*)target = 0xE9;
    *(int*)((unsigned char*)target + 1) = (int)rel;

    VirtualProtect((void*)target, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (void*)target, 5);
    return true;
}

// 签名校验 stub：与被替换的 sub_493820 保持同一调用约定 ——
//   char __thiscall(void* this, int a2, int a3)
// 我们直接让“校验结果”= 成功（AL=1），并用 `ret 8` 清掉 2 个 4 字节的
// 栈参数(a2,a3)，与 __thiscall 约定一致（this 在 ECX，stub 里不碰它）。
// 用 __declspec(naked) + 内联汇编精确控制返回行为，避免编译器生成的前/后序干扰。
static void __declspec(naked) SigCheckStub(void)
{
    __asm {
        mov al, 1      ; 返回“校验成功”
        ret 8          ; 清掉 2 个栈参数（__thiscall 调用约定）
    }
}

// 简单的 INI 整型读取：取 [section] 下的 key= 值；找不到返回 def。
// 不依赖 Win32 的 GetPrivateProfileInt（它有不易预期的缓存/回退行为），
// 自己解析更可控、也更易懂。
static int IniGetInt(const std::string& path, const std::string& section,
                     const std::string& key, int def)
{
    std::ifstream f(path);
    if (!f) return def;

    auto trim = [](const std::string& s) -> std::string {
        size_t a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return {};
        size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    };

    std::string line;
    bool inSection = false;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty()) continue;
        if (t[0] == '[' && t.back() == ']') {
            inSection = (t.substr(1, t.size() - 2) == section);
            continue;
        }
        if (!inSection) continue;
        size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(t.substr(0, eq));
        std::string v = trim(t.substr(eq + 1));
        if (k == key) {
            try { return std::stoi(v); } catch (...) { return def; }
        }
    }
    return def;
}

// 指针合理性快筛：过滤明显野指针（空指针区 / 非法高位），避免裸解引用拖垮游戏
static bool PlausiblePtr(const void* p)
{
    uintptr_t v = (uintptr_t)p;
    return v >= 0x10000 && v <= 0x7FFEFFFF;
}

// 地址转十六进制串（日志用）
static std::string Hex(uintptr_t v)
{
    char b[24];
    snprintf(b, sizeof(b), "0x%08X", (unsigned int)v);
    return std::string(b);
}

// 首次运行（INI 不存在）时，自动生成一份带注释的默认配置文件，
// 这样用户一定能在 DLL 同目录看到所有可调开关，而不是“凭空有个默认值”。
// 已存在则不覆盖，以免清掉用户改过的值。
static void EnsureIniExists()
{
    std::string path = GetSelfDir() + "InsaniquariumGameExtend.ini";
    { std::ifstream pf(path); if (pf) return; }  // 已存在 -> 保留用户设置
    std::ofstream out(path);
    if (!out) return;
    out
        << "; InsaniquariumGameExtend 配置文件\n"
        << "; 与本 DLL 放在同一目录（即 ModLoader.exe 同级目录）。\n"
        << "; 修改后下次启动游戏生效。\n"
        << "\n"
        << "[Mod]\n"
        << "\n"
        << "; ---- 签名校验 ----\n"
        << "; 是否禁用 .sig 签名校验（让被修改的 partner.xml 等能正常加载）\n"
        << "; 1 = 禁用（默认，推荐）；0 = 恢复原版（仍做签名校验）\n"
        << "DisableSigCheck = 1\n"
        << "\n"
        << "; 禁用方式\n"
        << "; 1 = 分支补丁（改 sub_486DF0 的 jnz -> jmp，报错分支不可达）\n"
        << "; 2 = 函数替换（把 .sig 校验器整体换成永远返回成功）\n"
        << "SigCheckMethod = 1\n"
        << "\n"
        << "; ---- 商店扩展：提供所有鱼 ----\n"
        << "; 是否把被隐藏的鱼/道具也放到商店（分到 7..14 槽，双行显示），\n"
        << "; 含 6 种鱼 + 星药剂 + 捕星者，同时保留“买 X 解锁 Y”的科技树进度。\n"
        << "; 1 = 启用（默认）；0 = 完全回退原版商店逻辑\n"
        << "StoreAllFish = 1\n";
    Log("[配置] 已自动生成默认配置文件：" + path);
}

// ---------------------------------------------------------------------------
// Game.exe 地址常量（均基于【未修改的原版】Game.exe）
// ---------------------------------------------------------------------------
// 【关键概念：VA 与 RVA】
//   IDA 里显示的 sub_XXXXXX 是 VA（虚拟地址），它【已经包含】映像基址；
//   而运行时定位要用 RVA（相对虚拟地址）= VA - 映像基址。
//   Game.exe 的链接基址是 0x400000，所以：
//       sub_486DF0 的 VA = 0x486DF0  ->  RVA = 0x086DF0
//       sub_493820 的 VA = 0x493820  ->  RVA = 0x093820
//   本文件早期版本把 VA 当成 RVA 又加了一次基址
//   （0x400000 + 0x493820 = 0x893820 = 映像之外的野地址），
//   于是补丁从来没写到正确位置 —— 这正是“拦截无效”的真正根因。
//   现在统一用 VaToRva() 换算，从源头消除这类错误。
static const uintptr_t GAME_IMAGE_BASE = 0x400000;
static inline uintptr_t VaToRva(uintptr_t va) { return va - GAME_IMAGE_BASE; }

// --- 方式 1（默认）：改掉“校验失败 -> 弹 FATAL ERROR”的那条条件跳转 ---
// 原版指令序列（IDA 反汇编实证，位于 sub_486DF0 内）：
//   0x486E69  8B 55 00              mov  edx, [ebp+0]      ; edx = app 的 vtable
//   0x486E6C  8B 92 68 01 00 00     mov  edx, [edx+168h]   ; 取槽 +0x168 = sub_493820
//   0x486E7A  FF D2                 call edx               ; 调 .sig 签名校验器
//   0x486E7C  84 C0                 test al, al
//   0x486E7E  0F 85 A8 01 00 00     jnz  0x48702C          ; 校验通过 -> 跳过报错继续解析
//   0x486E84  68 EC FA 5B 00        push "Signature check failed on "   ; <- 弹窗就在这
// 把这条 jnz 改成【无条件 jmp】，报错分支就永远不可达 = 签名校验被彻底禁用。
// 相比 hook 校验函数本身，这种做法的优势：不依赖调用约定、不需要 naked 汇编 stub，
// 而且它就是弹窗的唯一来源（已验证 "Signature check failed on " 全局仅 1 处引用）。
static const uintptr_t SIGFAIL_JNZ_VA  = 0x486E7E;  // 那条 jnz 的 VA
static const int       SIGFAIL_JNZ_REL = 0x1A8;     // 原始 rel32，兼作“版本指纹”

// --- 方式 2（备选）：整体替换 .sig 校验函数，让它永远返回“成功” ---
// sub_493820 = app（Sexy::SexyApp）vtable 槽 +0x168 的虚函数。
// 已双重验证：构造函数 sub_4908E0 写入 vtable=0x5C0394，而 *(0x5C0394+0x168)=0x493820。
static const uintptr_t SIGCHECK_FUNC_VA = 0x493820;

// 把 `jnz rel32`（6 字节）改写成 `jmp rel32`（5 字节）+ `nop`（1 字节）。
// 跳转目标保持不变：jnz 的 rel32 以 addr+6 为基准，jmp 的以 addr+5 为基准，
// 所以新 rel32 = 旧 rel32 + 1。
// 写之前先做“版本指纹”校验：必须确实是 0F 85 且 rel32 与原版一致，
// 否则说明不是未修改的原版 Game.exe —— 直接放弃，绝不乱写内存。
static bool PatchJnzToJmp(uintptr_t addr, int expectRel, std::string& detail)
{
    // 先用 ReadProcessMemory 安全试读（地址非法时它只会返回失败，不会让进程崩溃）
    unsigned char orig[6] = {0};
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, orig, 6, &got)
        || got != 6) {
        detail = "目标地址不可读（基址/版本不对？）";
        return false;
    }

    char hex[64];
    snprintf(hex, sizeof(hex), "%02X %02X %02X %02X %02X %02X",
             orig[0], orig[1], orig[2], orig[3], orig[4], orig[5]);
    detail = std::string("原始字节 = ") + hex;

    if (orig[0] != 0x0F || orig[1] != 0x85) {
        detail += "（期望 0F 85 = jnz rel32，不匹配）";
        return false;
    }
    int rel = *(int*)(orig + 2);
    if (rel != expectRel) {
        char b[96];
        snprintf(b, sizeof(b), "（rel32 期望 0x%X，实际 0x%X，版本不符）", expectRel, rel);
        detail += b;
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect((void*)addr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        detail += "（VirtualProtect 失败）";
        return false;
    }
    unsigned char* p = (unsigned char*)addr;
    p[0] = 0xE9;                  // jmp rel32
    *(int*)(p + 1) = rel + 1;     // 目标不变：基准从 addr+6 变为 addr+5
    p[5] = 0x90;                  // nop，保持总长度 6 字节
    VirtualProtect((void*)addr, 6, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, 6);
    return true;
}

// mod 初始化：由 DllMain 在“游戏主线程挂起”期间同步调用（见 DllMain 注释）。
// 此时游戏任何代码都还没跑，因此 hook 必然先于 partner.xml 的 .sig 校验安装好。
static void ModInitStoreExpand(uintptr_t base);  // 前向声明（定义见文件末尾）

static void ModInit()
{
    Log("=== InsaniquariumGameExtend 已附加 ===");

    // 首次运行自动写出带注释的默认 INI（含所有开关），确保用户看得见、能改
    EnsureIniExists();

    // 宿主进程信息
    char exePath[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    Log(std::string("宿主进程 = ") + exePath);

    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCSTR)&ModInit, &hSelf);
    {
        char b[32];
        snprintf(b, sizeof(b), "0x%08X", (unsigned int)(uintptr_t)hSelf);
        Log(std::string("本 DLL 基址 = ") + b);
    }

    // ---- 进程名校验：只对自己确实是 Game.exe 才装 hook ----
    // 防御：若 DLL 被意外加载到其他进程（理论上 ModLoader 只会注入 Game.exe），
    // 跳过 hook，避免改错函数导致崩溃。
    std::string exeName = exePath;
    size_t bs = exeName.find_last_of("\\/");
    if (bs != std::string::npos) exeName = exeName.substr(bs + 1);
    for (char& c : exeName) c = (char)std::tolower((unsigned char)c);
    if (exeName != "game.exe") {
        Log("[跳过] 当前进程不是 Game.exe（实际=" + exeName +
            "），不安装签名校验 hook。");
        return;
    }

    // ---- 商店扩展：提供所有鱼（独立于签名校验，始终尝试安装）----
    {
        HMODULE hGame2 = GetModuleHandleA(NULL);
        if (hGame2) ModInitStoreExpand((uintptr_t)hGame2);
    }

    // ----------------------------------------------------------------------
    // 功能：禁用签名校验（.sig 验证）—— 让被改的 partner.xml 等也能正常加载。
    // 驱动：本 DLL 同目录的 InsaniquariumGameExtend.ini
    //   [Mod] DisableSigCheck
    //       缺省（INI 不存在 / 非 0）= 启用（跳过 .sig 校验）
    //       显式 =0                  = 恢复原版（仍做 .sig 校验）
    //   [Mod] SigCheckMethod
    //       1（默认）= 分支补丁：改 sub_486DF0 里的 jnz -> jmp，报错分支永不可达
    //       2        = 函数替换：把 sub_493820（.sig 校验器）整体换成永远返回成功
    // “默认启用”是刻意设计：本项目目的就是禁止签名验证，默认必装可避免
    // “忘了部署 INI / INI 值写成 0”这类部署失误。INI 仅作为恢复原版的逃生口。
    // ----------------------------------------------------------------------
    auto Hex = [](uintptr_t v) {
        char b[24];
        snprintf(b, sizeof(b), "0x%08X", (unsigned int)v);
        return std::string(b);
    };

    std::string iniPath = GetSelfDir() + "InsaniquariumGameExtend.ini";
    bool iniExists = false;
    { std::ifstream pf(iniPath); iniExists = (bool)pf; }
    // 缺省 1：INI 不存在也视为“启用禁用”
    int disableSig = IniGetInt(iniPath, "Mod", "DisableSigCheck", 1);
    int method     = IniGetInt(iniPath, "Mod", "SigCheckMethod", 1);
    Log("INI 路径 = " + iniPath + "  存在 = " + (iniExists ? "是" : "否")
        + "  DisableSigCheck = " + std::to_string(disableSig)
        + "  SigCheckMethod = " + std::to_string(method));

    if (disableSig == 0) {
        Log("签名校验保持原样（DisableSigCheck=0，已显式关闭）。");
        return;
    }

    HMODULE hGame = GetModuleHandleA(NULL); // 宿主 Game.exe 基址
    if (!hGame) {
        Log("[错误] 无法获取 Game.exe 基址，跳过签名校验禁用。");
        return;
    }
    uintptr_t base = (uintptr_t)hGame;
    Log("Game.exe 基址 = " + Hex(base)
        + "（原版链接基址 = " + Hex(GAME_IMAGE_BASE) + "）");

    if (method == 2) {
        // ---- 方式 2：替换 .sig 校验函数本身 ----
        uintptr_t target = base + VaToRva(SIGCHECK_FUNC_VA);
        Log("[方式2] 目标 = sub_493820  VA=" + Hex(SIGCHECK_FUNC_VA)
            + "  RVA=" + Hex(VaToRva(SIGCHECK_FUNC_VA))
            + "  运行时地址=" + Hex(target));

        unsigned char probe[2] = {0};
        SIZE_T got = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)target, probe, 2, &got)
            || got != 2) {
            Log("[错误] 目标地址不可读（须用未修改的原版 Game.exe）。");
            return;
        }
        char hx[16];
        snprintf(hx, sizeof(hx), "%02X %02X", probe[0], probe[1]);
        Log(std::string("[方式2] 入口前 2 字节 = ") + hx + "（原版应为 6A FF = push -1）");

        if (!RedirectFunctionEntry(target, (void*)&SigCheckStub)) {
            Log("[错误] 安装 hook 失败（VirtualProtect/写入失败）。");
            return;
        }
        unsigned char verify = 0;
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)target, &verify, 1, NULL);
        if (verify == 0xE9)
            Log("[成功] 已禁用签名校验（方式2：.sig 校验器一律返回成功）。写入验证通过。");
        else
            Log("[警告] 写入函数返回成功，但入口首字节不是 JMP(0xE9)，可能被覆盖。");
        return;
    }

    // ---- 方式 1（默认）：分支补丁 ----
    uintptr_t jnzAddr = base + VaToRva(SIGFAIL_JNZ_VA);
    Log("[方式1] 目标 = sub_486DF0 内的 jnz  VA=" + Hex(SIGFAIL_JNZ_VA)
        + "  RVA=" + Hex(VaToRva(SIGFAIL_JNZ_VA))
        + "  运行时地址=" + Hex(jnzAddr));

    std::string detail;
    if (!PatchJnzToJmp(jnzAddr, SIGFAIL_JNZ_REL, detail)) {
        Log("[错误] 分支补丁失败：" + detail);
        Log("       请确认使用的是【未修改的原版 Game.exe】；"
            "也可在 INI 里设 SigCheckMethod=2 试用备选方式。");
        return;
    }
    Log("[方式1] " + detail);

    // 写入后读回验证：首字节应变成 E9（jmp），末字节应为 90（nop）
    unsigned char after[6] = {0};
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)jnzAddr, after, 6, NULL);
    char hx2[64];
    snprintf(hx2, sizeof(hx2), "%02X %02X %02X %02X %02X %02X",
             after[0], after[1], after[2], after[3], after[4], after[5]);
    if (after[0] == 0xE9 && after[5] == 0x90)
        Log(std::string("[成功] 已禁用签名校验（方式1：jnz -> jmp，报错分支已不可达）。"
                        "补丁后字节 = ") + hx2);
    else
        Log(std::string("[警告] 补丁已写入但读回不符预期，补丁后字节 = ") + hx2);
}

// ===========================================================================
// 功能：提供所有鱼（商店 UI 扩张）
// ---------------------------------------------------------------------------
// 背景（详见工作记忆，已用 IDA 三探针坐实）：
//   商店工具栏是"单行 7 槽"。每项的槽位号存在  *(this + 185 + itemIdx)
//   （4 字节 int，itemIdx=0..11）。sub_541200 按关卡把不需要的项写成 -1（隐藏）、
//   可见的压实到 0..6。sub_5409B0 用栈上 v19[0..6]={18,87,144,217,290,363,436}
//   当 x 坐标，v19 只有 7 项 → 槽位≥7 越界崩溃（v19[7] 被复用成栈地址，8+ 越界）。
//   科技树 sub_549380 不写槽位，只触发"购买效果"并复用已分好槽的按钮。
//
// 用户选定方案：保留科技树 + 双行布局。做法：
//   1) hook sub_541200：调原版后，把 8 种道具（0=guppy,1=breeder,4=carnivore,
//      5=星药剂,6=捕星者,7=guppycruncher,8=beetlemuncher,9=ultravore）中"本关被隐藏(-1)的"
//      强行分到 7..14 空闲槽；0..6 的升级项原样保留（科技树不变）。再显式
//      sub_5409B0(道具) 保证按钮被创建（缓存幂等）。
//   2) hook sub_5409B0：slot<0→不创建；slot≤6→原版单行（不影响其他 30+ 调用者）；
//      slot≥7→把槽位临时降为 0 让原版安全建好按钮，再重摆到第二行（列宽 69 同原版，
//      x=18+col*69, y=3+row*63），按钮存入自有缓存 g_fishCache（避开原版 257 数组越界写）。
//   3) hook sub_538090（购买/点击总闸门）：原版 slot<7 走原版缓存 *(this+257+slot)；
//      slot≥7（仅我改过才出现）→ 改从 g_fishCache[slot] 取按钮。这样第二行按钮被点击时，
//      sub_549380 第一句 result=sub_538090(a2) 能拿到非空的按钮指针，购买逻辑正常执行。
//      （不写 *(this+257+7..14)，避免越界写 StoreScreen 未知字段。）
//   槽位≥7 是"仅我改过才会出现"的值，天然充当"商店上下文"识别，不会误伤其他 UI。
// ===========================================================================

// --- 跳板式 inline hook（x86, 32 位；被偷指令含 ECX(this)，__thiscall 安全）---
struct InlineHook {
    uintptr_t target;     // 原函数入口 VA（运行时）
    uintptr_t hookFn;     // 我们的 hook 函数
    uintptr_t trampoline; // 跳板：执行被偷指令后跳回原函数
    unsigned char saved[32];
    int stolen;           // 偷走的字节数（须≥5 且停在指令边界）
};

static bool MakeTrampoline(InlineHook& h)
{
    unsigned char* t = (unsigned char*)h.target;
    memcpy(h.saved, t, h.stolen);

    // 跳板内存：stolen 字节 + JMP rel32(5)
    h.trampoline = (uintptr_t)VirtualAlloc(NULL, h.stolen + 5,
        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!h.trampoline) return false;
    unsigned char* tr = (unsigned char*)h.trampoline;
    memcpy(tr, h.saved, h.stolen);
    intptr_t rel = (intptr_t)(h.target + h.stolen) - (intptr_t)(tr + h.stolen + 5);
    tr[h.stolen] = 0xE9;
    *(int*)(tr + h.stolen + 1) = (int)rel;

    // 改写 target 入口为 JMP rel32 -> hookFn；多余字节填 NOP
    DWORD op;
    if (!VirtualProtect(t, h.stolen, PAGE_EXECUTE_READWRITE, &op)) return false;
    rel = (intptr_t)h.hookFn - (intptr_t)(t + 5);
    t[0] = 0xE9;
    *(int*)(t + 1) = (int)rel;
    for (int i = 5; i < h.stolen; i++) t[i] = 0x90;
    VirtualProtect(t, h.stolen, op, &op);
    FlushInstructionCache(GetCurrentProcess(), t, h.stolen);
    return true;
}

// IDA 风格整型别名（非标准 C++，这里补齐定义；与 IDA 反编译伪代码一致）
typedef unsigned int  _DWORD;
typedef unsigned char _BYTE;

// 原函数 / 内部函数类型（签名来自 IDA 反编译实证）
typedef _DWORD* (__thiscall* Fn5409B0)(_DWORD* self, int a2, int a3);
typedef int     (__thiscall* Fn541200)(_DWORD* self);
typedef _DWORD* (__thiscall* Fn538090)(_DWORD* self, int a2);  // 当前道具按钮指针闸门

static InlineHook g_hook5409B0 = {0,0,0,{},0};
static InlineHook g_hook541200 = {0,0,0,{},0};
static InlineHook g_hook538090 = {0,0,0,{},0};  // 购买/点击闸门 sub_538090
// 扩展鱼按钮缓存（按 slot 索引）。原版缓存是 *(this+257+slot)，slot≥7 时越界写堆，
// 故鱼按钮存这里；每次开商店（sub_541200）清空，避免跨次进入的悬垂指针。
static _DWORD* g_fishCache[32] = {0};

// 三个钩子实现为普通 __stdcall 自由函数，由内联汇编中继把游戏的 __thiscall 调用
// （ECX=this）转成 (self,...) 再交给自由函数，并经“变量”间接 call 钩子（不走函数符号，
// 规避内联汇编对 __stdcall 修饰名的解析歧义）。
//
// ⚠️ 关键调用约定坑（本会话反复踩，必须同时满足）：
//   (a) 游戏 __thiscall 函数（尤其是 sub_538090）往往“顺手”保留了 edx 这种易失寄存器，
//       而其调用方（sub_549380）会依赖“返回后 edx 仍等于我传入的 a2”去当下标访问数组。
//       我们的 C 钩子任意使用 edx → 改写它 → 调用方拿垃圾 edx 当下标越界崩溃
//       （购买崩溃根因：EIP=0x54939C, EDX=ESI=this）。故中继进钩子前把调用方 edx 压栈保存，
//       钩子返回后再弹栈还原（绝不用 edi 暂存——那会破坏 edi 这个非易失寄存器，
//       导致依赖 edi 的调用方拿到垃圾，引发更隐蔽的崩溃；本回合“进不去关卡”即此类）。
//   (a2) 同样要保活 ecx(this)：sub_538090 原版只读 ecx、从不改写，于是其调用方 sub_549380
//        的 switch 在 case1+ 直接用 ecx 当 this 调 sub_540B30（case0 才有显式“mov ecx,esi”）。
//        我们的 C 钩子会改写 ecx → 返回时 ecx 是垃圾 → case1+ 把垃圾当 this 传入 sub_540B30
//        → *(this+8Ch) 访问违规（本回合点击购买崩溃：EIP=0x540B5A, ECX=1）。
//        故 Relay538090 进钩子前把 ecx(self) 压栈，返回后还原 ecx=self，精确模拟原版“不改 ecx”。
//        （注：sub_5409B0 / sub_541200 的调用方不依赖 ecx 保留，故那两个中继无需保 ecx。）
//   (b) 中继必须以“与原版相同的字节数”平衡栈：
//       sub_5409B0  有 2 个栈参数(thiscall) → 原版 ret 12 → 中继末 `ret 8`（弹 ret+a2+a3）；
//       sub_538090  有 1 个栈参数(thiscall) → 原版 ret 8  → 中继末 `ret 4`（弹 ret+a2）；
//       sub_541200  无栈参数(thiscall)       → 原版 ret 4  → 中继末 `ret`（弹 ret）。
//       少平衡 1 个参数的字节数 → 调用方 ESP 错位 → 表现为“进关卡 / 某处突然崩在原版函数内部”
//       （本回合崩溃 EIP=0x540B03 即 sub_5409B0 内部，因上版中继末 `ret` 少弹 8 字节）。
extern "C" _DWORD* __stdcall Sub5409B0_Hook(_DWORD* self, int a2, int a3);
extern "C" int     __stdcall Sub541200_Hook(_DWORD* self);

static uintptr_t g_relay5409B0_tgt  = 0;  // = (uintptr_t)&Sub5409B0_Hook
static uintptr_t g_relay541200_tgt = 0;  // = (uintptr_t)&Sub541200_Hook
static uintptr_t g_relay538090_tgt = 0;  // = (uintptr_t)&Sub538090_Hook

__declspec(naked) static void Relay5409B0()
{
    __asm {
        push edx                       ; 保存调用方 edx（sub_549380 用它当下标，原版不碰 edx）
        mov  eax, ecx                 ; eax = self(this)
        mov  ecx, [esp+8]             ; ecx = a2（push edx 后：[esp+4]=ret,[esp+8]=a2）
        push [esp+0Ch]                ; 压 a3（[esp+0Ch]=原入口 a3）
        push ecx                      ; 压 a2
        push eax                      ; 压 self
        mov  eax, [g_relay5409B0_tgt]
        call eax                      ; __stdcall(self,a2,a3)，钩子返回 eax=按钮
        mov  edx, [esp]               ; 从栈上保存位还原调用方 edx
        add  esp, 4                   ; 弹出保存位
        ret  8                        ; 平衡栈：弹出 ret+a2+a3（=原版 thiscall ret 12）
    }
}
__declspec(naked) static void Relay541200()
{
    __asm {
        push edx                       ; 保存调用方 edx（防御性）
        mov  eax, ecx                 ; eax = self(this)
        push eax                      ; 压 self
        mov  eax, [g_relay541200_tgt]
        call eax                      ; __stdcall(self)
        mov  edx, [esp]               ; 还原调用方 edx
        add  esp, 4                   ; 弹出保存位
        ret                           ; 平衡栈：弹出 ret（=原版 thiscall ret 4，无栈参数）
    }
}

__declspec(naked) static void Relay538090()
{
    __asm {
        push ecx                       ; 保存 self(this)：原版 sub_538090 只读 ecx、从不改写
        push edx                       ; 保存调用方 edx（sub_549380 用它当下标，原版不碰 edx）
        mov  eax, [esp+4]             ; eax = self
        mov  ecx, [esp+0Ch]           ; ecx = a2（[esp+0]=self,[esp+4]=edx,[esp+8]=ret,[esp+0Ch]=a2）
        push ecx                      ; 压 a2
        push eax                      ; 压 self
        mov  eax, [g_relay538090_tgt]
        call eax                      ; __stdcall(self,a2)，返回 eax=按钮
        mov  ecx, [esp+4]             ; ★还原 ecx = self：sub_549380 的 case1+ 直接用 ecx 当 this 调
                                       ;   sub_540B30（无“mov ecx,esi”），依赖“sub_538090 后 ecx 仍为 this”。
                                       ;   原版只读 ecx 故保留；我们的 C 钩子会改写它，必须在此还原，
                                       ;   否则 case1+ 把垃圾 ecx 当 this 传入 sub_540B30 → *(this+8Ch) 崩。
        mov  edx, [esp]               ; 还原调用方 edx = a2（调用方要它当下标）
        add  esp, 8                   ; 弹出 [edx][self] 保存位
        ret  4                        ; 平衡栈：弹出 ret+a2（=原版 thiscall ret 8）
    }
}

// sub_538090(this, a2)：返回“当前道具 a2 的按钮指针”，是商店点击/购买的总闸门。
//   原版逻辑（IDA 实证）：slot=*(this+185+a2); if(slot>=0) return *(this+257+slot); else 0。
//   sub_549380（购买回调）第一句就是 result=sub_538090(a2); if(result){switch(a2)...}，
//   返回空则整段购买被跳过 —— 这正是“第二行鱼点了没反应”的根因。
// 我们的扩展鱼用 slot>=7（原版从未出现的值）占位，按钮只存在自有缓存 g_fishCache，
// 没写回 *(this+257+slot)（那会越界写 StoreScreen 未知字段，危险）。故在此 hook：
//   slot>=7 且缓存有按钮 -> 直接返回 g_fishCache[slot]（让购买链路识别它）；
//   slot<7（普通道具）   -> 走跳板原版（完全不动原版行为）。
// 这样普通道具、科技树、蛋/结束关等一切原版逻辑零改动，只有第二行鱼被“接上”。
extern "C" _DWORD* __stdcall Sub538090_Hook(_DWORD* self, int a2)
{
    int slot = *(int*)((char*)self + (185 + a2) * 4);
    // slot>=7 仅可能是我们的扩展道具：原版从不产生该值，故 *(this+257+slot) 是未初始化
    // 的野内存，绝不能走原版读取。这里只认自有缓存 g_fishCache——建好就是有效指针，
    // 没建好（极端：创建失败）就是 0，返回 0 让上层“购买被跳过”，绝不拿野指针去购买。
    if (slot >= 7 && slot < 32)
        return g_fishCache[slot];
    return ((Fn538090)g_hook538090.trampoline)(self, a2);
}

extern "C" _DWORD* __stdcall Sub5409B0_Hook(_DWORD* self, int a2, int a3)
{
    Log("[商店扩展][DBG] Sub5409B0 进入 self=" + Hex((uintptr_t)self) + " a2=" + std::to_string(a2));
    int slot = *(int*)((char*)self + (185 + a2) * 4);  // 4 字节 int 槽位（IDA 实证）
    if (slot < 0)
        return nullptr;
    if (slot <= 6)
        return ((Fn5409B0)g_hook5409B0.trampoline)(self, a2, a3);  // 真实道具：原版单行

    // ---- slot ≥ 7：我扩展的第二行鱼 ----
    Log("[商店扩展][DBG]   鱼路径 slot=" + std::to_string(slot));
    if (slot >= 32) return nullptr;                    // 防御：缓存数组边界
    if (g_fishCache[slot]) return g_fishCache[slot];  // 已建好，直接复用（幂等）

    // 临时把本 item 的槽位降为 0，让原版安全建按钮（不触发越界写堆 / 垃圾坐标）
    int*     field       = (int*)((char*)self + (185 + a2) * 4);
    _DWORD** cache0      = (_DWORD**)((char*)self + (257 + 0) * 4);  // 缓存槽存的是按钮指针
    int      savedField  = *field;
    _DWORD*  savedCache0 = *cache0;
    *field  = 0;
    *cache0 = nullptr;   // 强制原版重建：否则它会直接返回真实 slot0 道具(如现金)的缓存按钮
    _DWORD* btn = ((Fn5409B0)g_hook5409B0.trampoline)(self, a2, a3);  // 原版：new+虚表+AddWidget+SetBounds(x=18)
    *field      = savedField;   // 还原 7..12，供下次命中本钩
    *cache0     = savedCache0;  // 还原真实 slot0 缓存，避免覆盖现金等道具
    if (!PlausiblePtr(btn)) {
        Log("[商店扩展][DBG]   鱼按钮创建失败，跳过");
        return nullptr;
    }
    g_fishCache[slot] = btn;    // 存入我们自己的缓存（不碰原版 257+slot）

    // 重摆到第二行：k=槽位-7 作为 0..7 的横向序号，8 个道具排成紧挨第一行下方的一整行
    // （列宽 69 与原版单行一致，x 起点同为 18）。slot 仅作“扩展标识”，视觉位置由此处算。
    int k = slot - 7;
    int col = k % 8;
    int row = k / 8 + 1;   // +1：永远在第一行（y=3）之下
    int x = 18 + col * 69;
    int y = 3 + row * 63;
    // SetBounds(btn, x, y, 58, 60)：btn 虚表 +160（IDA 实证）。任何指针异常都跳过重摆，绝不崩。
    int* btnVtab = *(int**)btn;
    if (PlausiblePtr(btnVtab)) {
        void* setBounds = (void*)(*(int*)((char*)btnVtab + 160));
        if (PlausiblePtr(setBounds))
            ((void(__thiscall*)(_DWORD*, int, int, int, int))setBounds)(btn, x, y, 58, 60);
        else
            Log("[商店扩展][DBG]   setBounds 野指针，跳过重摆（按钮留在原处）");
    } else
        Log("[商店扩展][DBG]   btnVtab 野指针，跳过重摆");
    Log("[商店扩展][DBG]   鱼按钮完成 a2=" + std::to_string(a2) + " @(" + std::to_string(x) + "," + std::to_string(y) + ")");
    return btn;
}

// sub_541200 钩子：调原版后，强制所有鱼可见并触发创建。
// 普通 __stdcall 自由函数，self=StoreScreen（由中继从 ECX 流入），与原版调用约定一致。
extern "C" int __stdcall Sub541200_Hook(_DWORD* self)
{
    Log("[商店扩展][DBG] Sub541200 进入");
    ((Fn541200)g_hook541200.trampoline)(self);  // 先调原版（设价格/槽位）

    // 开商店：清空上一轮的鱼按钮缓存，避免跨次进入时拿到已销毁的悬垂指针（use-after-free）
    memset(g_fishCache, 0, sizeof(g_fishCache));

    // 8 种道具：若本关被隐藏(-1)，强行分到 7..14 空闲槽（不动 0..6 升级项）。
    // 含 6 种鱼(0=guppy,1=breeder,4=carnivore,7=guppycruncher,8=beetlemuncher,9=ultravore)
    // 以及用户要求的 starcatcher(6) 与星药剂(5)，让它们也能在商店直接买到。
    static const int fishIdx[8]  = {0, 1, 4, 5, 6, 7, 8, 9};
    static const int fishSlot[8] = {7, 8, 9, 10, 11, 12, 13, 14};
    for (int k = 0; k < 8; ++k) {
        int* p = (int*)((char*)self + (185 + fishIdx[k]) * 4);
        if (*p == -1)
            *p = fishSlot[k];
    }
    // 显式创建（幂等：Sub5409B0_Hook 内部用 g_fishCache 去重）。
    // 它把槽位临时降为 0 让原版安全建好按钮，再重摆到第二行并存自有缓存。
    for (int k = 0; k < 8; ++k)
        Sub5409B0_Hook(self, fishIdx[k], 1);
    Log("[商店扩展][DBG] Sub541200 完成");
    return 0;
}

static void ModInitStoreExpand(uintptr_t base)
{
    int enable = IniGetInt(GetSelfDir() + "InsaniquariumGameExtend.ini",
                           "Mod", "StoreAllFish", 1);
    Log("[商店扩展] StoreAllFish = " + std::to_string(enable));
    if (enable == 0) {
        Log("[商店扩展] 已禁用（StoreAllFish=0）。");
        return;
    }

    // 安装跳板。stolen 必须落在“指令边界”上（≥5 字节），否则跳板复制的字节会切断一条指令，
    // 跳回 original+stolen 时从中途执行乱码 → 确定性崩溃（本会话反复崩在 DLL 内同一偏移的根因）。
    // 已从本地 Game.exe 实测前导字节：
    //   sub_5409B0: 55 8B EC 6A FF | 68 CB 94 58 00 | 64 A1 00 00 00 00 ...
    //               push ebp;mov ebp,esp;push 0FFh(2字节) ; push 0x5894CB(5字节) ; mov eax,fs:[0] ...
    //               指令边界在 5 字节(push 0FFh 后) 与 10 字节(push imm32 后) —— 故 stolen=10。
    //               （早期误判为“push 0FFFFFFFFh=5字节、整体8字节”，导致 stolen=8 切断 push imm32。）
    //   sub_541200: 53 56 8B F1 8B 8E 8C 00 00 00 ...
    //               push ebx;push esi;mov esi,ecx;mov ecx,[esi+8Ch]  = 10 字节（边界正确，保持）。
    // hookFn 指向中继（普通函数地址，可靠）；中继运行时再从变量跳到真正的钩子，
    // 彻底规避内联汇编对 __stdcall 修饰名的解析歧义（此前崩溃的共同隐患）。
    g_relay5409B0_tgt  = (uintptr_t)&Sub5409B0_Hook;
    g_relay541200_tgt = (uintptr_t)&Sub541200_Hook;
    g_relay538090_tgt = (uintptr_t)&Sub538090_Hook;
    g_hook5409B0.target = base + VaToRva(0x5409B0);
    g_hook5409B0.hookFn = (uintptr_t)&Relay5409B0;
    g_hook5409B0.stolen = 10;   // 见下方注释：真实前导 16 字节，指令边界在 5 与 10
    g_hook541200.target = base + VaToRva(0x541200);
    g_hook541200.hookFn = (uintptr_t)&Relay541200;
    g_hook541200.stolen = 10;
    g_hook538090.target = base + VaToRva(0x538090);
    g_hook538090.hookFn = (uintptr_t)&Relay538090;
    g_hook538090.stolen = 6;    // push ebp(1)+mov ebp,esp(2)+mov eax,[ebp+8](3) = 6 字节，指令边界（实测）

    if (!MakeTrampoline(g_hook5409B0)) {
        Log("[商店扩展][错误] sub_5409B0 跳板安装失败。");
        return;
    }
    if (!MakeTrampoline(g_hook541200)) {
        Log("[商店扩展][错误] sub_541200 跳板安装失败。");
        return;
    }
    if (!MakeTrampoline(g_hook538090)) {
        Log("[商店扩展][错误] sub_538090 跳板安装失败。");
        return;
    }
    Log("[商店扩展] 已安装（sub_5409B0 + sub_541200 + sub_538090）。被隐藏的 8 种道具将分到 7..14 槽并双行显示，点击可正常购买。");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // 日志写到 DLL 同目录的 logs\InsaniquariumGameExtend.log
        g_logDir = GetSelfDir() + "logs\\";
        CreateDirectoryA(g_logDir.c_str(), NULL);
        g_log.open(g_logDir + "InsaniquariumGameExtend.log", std::ios::trunc);
        Log("DLL_PROCESS_ATTACH");

        // 同步安装 hook（而不是另起工作线程）。
        // 本 DLL 由 ModLoader 在 Game.exe 的“挂起态”下注入：此刻游戏主线程还处于
        // 挂起状态，DllMain 返回、ModLoader 调用 ResumeThread 之后游戏代码才会真正
        // 开始跑。因此在 DllMain 里直接把 hook 装好，能保证它先于游戏任何代码（包括
        // 启动期加载 partner.xml 并做 .sig 校验的那次调用）执行，彻底消除“校验点抢跑、
        // hook 还没装上”的竞态——这正是“拦截偶发无效”的常见根因。
        // 这里只做“读 INI + 改目标函数入口 5 字节”这类不触碰 Loader Lock 的轻量操作，
        // 不调用 LoadLibrary 等会死锁的 API，在 DllMain 内同步执行是安全的。
        ModInit();
        break;
    }
    case DLL_PROCESS_DETACH:
        Log("DLL_PROCESS_DETACH");
        if (g_log.is_open()) g_log.close();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
