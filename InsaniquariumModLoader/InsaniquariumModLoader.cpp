// InsaniquariumModLoader.cpp
// ---------------------------------------------------------------------------
// 作用：替代 PopCap 的 DRM 自解压启动器（InsaniquariumDeluxe.exe），直接拉起真正的
//       游戏主程序 Game.exe，并在其“启动初期（主线程挂起）”把 mod DLL 注入进去。
//
// 为什么需要它（背景）：
//   InsaniquariumDeluxe.exe 是 DRM 启动器，运行期才把内嵌的 Game.exe 解压到临时目录、
//   作为子进程启动、退出后自删。因此：
//     - 不能“放进目录替换 DLL”做代理（而且 shell32 这类系统 DLL 在 KnownDLLs 里，
//       就算替换了也不会被加载）；
//     - 也不能向启动器注入，因为它会自删、且真正的游戏逻辑在子进程 Game.exe 里。
//   正解是：由本程序接管启动流程 —— 直接运行真正的 Game.exe（绕过 DRM 启动器），
//   再用“挂起进程 + CreateRemoteThread(LoadLibrary)”把 mod DLL 注入到 Game.exe。
//
// 位数要求（很重要）：
//   Game.exe 是 32 位进程，所以本注入器与 mod DLL 都【必须编译为 32 位(Win32)】。
//   用 64 位注入器去注入 32 位进程会因 Wow64 限制而失败。本项目已把工程收敛为 Win32-only。
// ---------------------------------------------------------------------------

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>

// 文件名常量
static const char* LAUNCHER_NAME = "InsaniquariumDeluxe.exe";  // DRM 启动器（内嵌 Game.exe）
static const char* GAME_NAME     = "Game.exe";                // 真正的游戏主程序
static const char* MOD_DLL_NAME  = "InsaniquariumGameExtend.dll"; // 要注入的 mod

// 取本 exe 所在目录（带结尾反斜杠）
static std::string GetSelfDir()
{
    char buf[MAX_PATH] = {0};
    DWORD n = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::string s(buf);
    size_t pos = s.find_last_of("\\/");
    if (pos == std::string::npos) return {};
    return s.substr(0, pos + 1);
}

// 在 launcher 二进制里找“最后一个合法的 MZ+PE”位置。
// DRM 启动器通常把 Game.exe 这个 PE 包在自己尾部，所以用“最后一个 PE 头”来定位 payload。
static long FindLastPeHeader(const std::vector<BYTE>& data)
{
    long found = -1;
    for (size_t i = 0; i + 0x40 < data.size(); ++i) {
        if (data[i] == 'M' && data[i + 1] == 'Z') {
            // e_lfanew 在偏移 0x3C，小端 4 字节
            DWORD e_lfanew = (DWORD)data[i + 0x3C]
                           | ((DWORD)data[i + 0x3D] << 8)
                           | ((DWORD)data[i + 0x3E] << 16)
                           | ((DWORD)data[i + 0x3F] << 24);
            if (i + e_lfanew + 4 <= data.size() &&
                data[i + e_lfanew] == 'P' && data[i + e_lfanew + 1] == 'E') {
                found = (long)i; // 取最大的那个（最后的 PE 才是 Game.exe）
            }
        }
    }
    return found;
}

// 从启动器提取内嵌的 Game.exe 到 gameDir\Game.exe（仅当该文件不存在时才需要）
static bool ExtractGameExe(const std::string& gameDir)
{
    std::string launcher = gameDir + LAUNCHER_NAME;
    std::string out      = gameDir + GAME_NAME;

    if (GetFileAttributesA(out.c_str()) != INVALID_FILE_ATTRIBUTES)
        return true; // 目标已存在，无需提取

    printf("[信息] 未找到 %s，尝试从启动器 %s 提取内嵌 Game.exe...\n",
           GAME_NAME, LAUNCHER_NAME);

    HANDLE h = CreateFileA(launcher.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[错误] 无法打开启动器 %s (err=%lu)\n", launcher.c_str(), GetLastError());
        return false;
    }

    DWORD size = GetFileSize(h, NULL);
    std::vector<BYTE> buf(size);
    DWORD read = 0;
    if (!ReadFile(h, buf.data(), size, &read, NULL) || read != size) {
        printf("[错误] 读取启动器失败 (read=%lu)\n", read);
        CloseHandle(h);
        return false;
    }
    CloseHandle(h);

    long off = FindLastPeHeader(buf);
    if (off < 0) {
        printf("[错误] 在启动器内未找到合法的 PE 头，无法提取 Game.exe。\n");
        return false;
    }

    size_t payloadSize = buf.size() - off;
    HANDLE ho = CreateFileA(out.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (ho == INVALID_HANDLE_VALUE) {
        printf("[错误] 无法写出 %s (err=%lu)\n", out.c_str(), GetLastError());
        return false;
    }
    DWORD written = 0;
    WriteFile(ho, buf.data() + off, (DWORD)payloadSize, &written, NULL);
    CloseHandle(ho);

    printf("[成功] 已从启动器提取 Game.exe -> %s (%lu 字节)\n", out.c_str(), written);
    return written == (DWORD)payloadSize;
}

// 注入 mod DLL：在目标进程里分配内存写路径，再用远程线程执行 LoadLibraryA
static bool InjectDll(HANDLE hProcess, const std::string& dllPath)
{
    // 1) 在目标进程分配内存，写入 DLL 绝对路径（ANSI）
    SIZE_T pathLen = dllPath.size() + 1;
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemote) {
        printf("[错误] VirtualAllocEx 失败 (err=%lu)\n", GetLastError());
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pRemote, dllPath.c_str(), pathLen, &written)) {
        printf("[错误] WriteProcessMemory 失败 (err=%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return false;
    }

    // 2) LoadLibraryA 在所有进程里地址都一样（位于 kernel32），可跨进程直接使用
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel, "LoadLibraryA");
    if (!pLoadLibraryA) {
        printf("[错误] 找不到 LoadLibraryA\n");
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return false;
    }

    // 3) 起一个远程线程执行 LoadLibraryA(dllPath)
    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                        pRemote, 0, &tid);
    if (!hThread) {
        printf("[错误] CreateRemoteThread 失败 (err=%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return false;
    }

    // 4) 等注入线程结束；其返回值 = LoadLibrary 的模块句柄（非 0 即成功）
    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);

    if (exitCode == 0) {
        printf("[错误] 目标进程内 LoadLibrary 失败（mod DLL 可能缺失，或 32/64 位不匹配）\n");
        return false;
    }
    printf("[成功] 已注入 %s (base=0x%08lX)\n", dllPath.c_str(), exitCode);
    return true;
}

int main(int argc, char** argv)
{
    printf("=== Insaniquarium ModLoader ===\n");

    // 游戏目录：默认取本 exe 所在目录（部署时把 ModLoader 放在游戏目录里）；
    // 也可通过命令行参数传入（便于本地调试）。
    std::string gameDir = GetSelfDir();
    if (argc > 1 && argv[1][0] != '\0') {
        gameDir = argv[1];
        char last = gameDir.back();
        if (last != '\\' && last != '/') gameDir += '\\';
    }
    if (gameDir.empty()) {
        printf("[错误] 无法获取游戏目录。\n");
        return 1;
    }
    printf("[信息] 游戏目录 = %s\n", gameDir.c_str());

    // 1) 准备 Game.exe（优先用现成的；缺失时从启动器提取）
    std::string gameExe = gameDir + GAME_NAME;
    if (GetFileAttributesA(gameExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (!ExtractGameExe(gameDir)) {
            printf("[错误] 无法获得 Game.exe，退出。\n");
            return 1;
        }
    } else {
        printf("[信息] 使用现有 %s\n", gameExe.c_str());
    }

    // 2) 确认 mod DLL 存在（与 ModLoader 同目录即可）
    std::string modDll = GetSelfDir() + MOD_DLL_NAME;
    if (GetFileAttributesA(modDll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("[错误] 找不到 %s（请与本 ModLoader 放在同一目录）\n", modDll.c_str());
        return 1;
    }

    // 3) 以“挂起主线程”的方式启动游戏
    //    lpCurrentDirectory 必须设为游戏目录，Game.exe 才能找到 images/ data/ bass.dll 等。
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(gameExe.c_str(), NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, gameDir.c_str(), &si, &pi)) {
        printf("[错误] 启动 %s 失败 (err=%lu)\n", gameExe.c_str(), GetLastError());
        return 1;
    }
    printf("[信息] 已以挂起态启动 Game.exe (pid=%lu)\n", pi.dwProcessId);

    // 4) 注入 mod DLL
    bool injected = InjectDll(pi.hProcess, modDll);
    if (!injected)
        printf("[警告] 注入失败，游戏将以原版运行。\n");

    // 5) 恢复主线程，游戏正式开始
    ResumeThread(pi.hThread);

    // 6) 等待游戏进程退出（此期间 ModLoader 充当“启动器”）
    printf("[信息] 游戏运行中...（关闭游戏窗口即可退出 ModLoader）\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("[信息] 游戏已退出 (code=%lu)\n", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
