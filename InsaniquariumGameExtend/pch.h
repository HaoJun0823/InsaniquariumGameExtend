// pch.h: 预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#ifndef PCH_H
#define PCH_H

// 规避 IntelliSense 对 __declspec(no_init_all) 的误报（E1097 / 级联 E0169）。
// winnt.h 在 _MSC_VER>=1915 时会把 DECLSPEC_NOINITALL 定义为 __declspec(no_init_all)，
// 而 IntelliSense 的 EDG 解析器不认识该属性。提前定义为空 -> winnt.h 走 #else 空分支，
// 无任何功能副作用（该属性仅用于抑制"未初始化"相关警告）。
#ifndef DECLSPEC_NOINITALL
#define DECLSPEC_NOINITALL
#endif

// 添加要在此处预编译的标头
#include "framework.h"

// 标准库（预编译以提速）
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <fstream>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstring>

#include <mutex>

// 文件系统兼容层（v141 下自动回退到 experimental）
#include "Core/fs_compat.h"

#endif //PCH_H
