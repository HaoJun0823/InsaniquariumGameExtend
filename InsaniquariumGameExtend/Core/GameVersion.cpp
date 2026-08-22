#include "pch.h"
#include <cctype>
#include "GameVersion.h"
#include "fs_compat.h"
#include "Paths.h"
#include "Logger.h"

namespace {
const char* kCategory = "[Version]";
} // namespace

const char* GameTargetName(GameTarget t) {
    switch (t) {
        case GameTarget::Game:    return "Game.exe";
        case GameTarget::Any:     return "Any";
        default:                  return "Unknown";
    }
}

GameTarget GameVersion::Detect(const IniConfig& cfg) {
    m_target  = GameTarget::Unknown;
    m_exeName.clear();
    m_base    = (uintptr_t)GetModuleHandleA(NULL);

    // 进程名校验：只对 Game.exe 才装 hook。
    // 防御：若 DLL 被意外加载到其他进程，跳过所有功能。
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    std::string exeName = exePath;
    size_t bs = exeName.find_last_of("\\/");
    if (bs != std::string::npos) exeName = exeName.substr(bs + 1);
    for (char& c : exeName) c = (char)::tolower((unsigned char)c);

    if (exeName != "game.exe") {
        LOG_WARN(kCategory, "Current process is not Game.exe (actual=%s), skipping all features.", exeName.c_str());
        return m_target;
    }

    m_target  = GameTarget::Game;
    m_exeName = exePath;
    LOG_INFO(kCategory, "Detected game: %s (base=0x%X)", exePath, (unsigned)m_base);
    return m_target;
}
