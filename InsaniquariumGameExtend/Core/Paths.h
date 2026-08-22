#pragma once
#include <string>
#include <cstddef>
#include <windows.h>

// 路径常量与工具函数。
// 本 DLL 由 ModLoader 注入到 Game.exe 进程，DLL 可能不在 exe 同目录，
// 故所有路径以【DLL 自身所在目录】为基准（通过 GetModuleHandleEx 反查本模块）。
//
// 目录布局：
//   <DLL目录>/
//     InsaniquariumGameExtend.dll   本 DLL
//     InsaniquariumGameExtend.ini   配置文件
//     InsaniquariumGameExtendModLoader.exe  注入器
//     logs/                         日志文件夹

namespace ge_paths {

    // 目录
    constexpr const char* kLogDir = "logs";

    // 配置文件名
    constexpr const char* kIniFile = "InsaniquariumGameExtend.ini";

    // 主日志文件名
    constexpr const char* kMainLog = "InsaniquariumGameExtend.log";

    // 返回本 DLL 自身所在目录，带尾部反斜杠（如 "C:\\Game\\"）。
    // 使用 GetModuleHandleEx 反查本模块句柄，而非 GetModuleFileName(NULL)
    // （后者返回宿主进程 Game.exe 的路径，不一定是 DLL 目录）。
    inline std::string DllDir() {
        char buf[MAX_PATH] = {};
        HMODULE hSelf = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           reinterpret_cast<LPCSTR>(&DllDir), &hSelf);
        DWORD n = GetModuleFileNameA(hSelf, buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return std::string();
        std::string path(buf, n);
        size_t slash = path.find_last_of("\\/");
        if (slash == std::string::npos) return std::string();
        return path.substr(0, slash + 1);
    }

    // 拼接 DLL 目录 + 相对路径
    inline std::string Resolve(const char* rel) {
        std::string dir = DllDir();
        if (dir.empty()) return std::string(rel);
        return dir + rel;
    }

    inline std::string LogDir()   { return Resolve(kLogDir); }
    inline std::string IniPath()  { return Resolve(kIniFile); }

} // namespace ge_paths
