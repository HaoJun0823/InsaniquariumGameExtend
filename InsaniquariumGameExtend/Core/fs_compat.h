#pragma once
// 文件系统兼容层。
// v141 工具集（VS2017, _MSC_VER < 1920）无官方 <filesystem>，
// 使用 <experimental/filesystem>；v142+（VS2019+, _MSC_VER >= 1920）使用 <filesystem>。
// 统一暴露在 ge::fs 命名空间下。

#if defined(_MSC_VER) && (_MSC_VER < 1920)
    #include <experimental/filesystem>
    namespace ge { namespace fs = std::experimental::filesystem; }
#else
    #include <filesystem>
    namespace ge { namespace fs = std::filesystem; }
#endif

#include <string>

namespace ge {

// 容错地剥除 UTF-8 BOM（EF BB BF），使带或不带 BOM 的文本数据文件都能正确解析。
inline void StripUtf8Bom(std::string& s) {
    if (s.size() >= 3 &&
        (unsigned char)s[0] == 0xEF &&
        (unsigned char)s[1] == 0xBB &&
        (unsigned char)s[2] == 0xBF) {
        s.erase(0, 3);
    }
}

} // namespace ge
