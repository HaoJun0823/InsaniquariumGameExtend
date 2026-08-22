// StoreAllFishFeature.cpp
// ===================================================================
// [StoreAllFish]
// 商店扩展：把被隐藏的鱼/道具也放到商店（分到 7..14 槽，双行显示），
// 含 6 种鱼 + 星药剂 + 捕星者，同时保留"买 X 解锁 Y"的科技树进度。
//
// 背景（详见工作记忆，已用 IDA 三探针坐实）：
//   商店工具栏是"单行 7 槽"。每项的槽位号存在 *(this + 185 + itemIdx)
//   （4 字节 int，itemIdx=0..11）。sub_541200 按关卡把不需要的项写成 -1（隐藏）、
//   可见的压实到 0..6。sub_5409B0 用栈上 v19[0..6]={18,87,144,217,290,363,436}
//   当 x 坐标，v19 只有 7 项 -> 槽位>=7 越界崩溃。
//   科技树 sub_549380 不写槽位，只触发"购买效果"并复用已分好槽的按钮。
//
// 实现方案（保留科技树 + 双行布局）：
//   1) hook sub_541200：调原版后，把 8 种道具中"本关被隐藏(-1)的"强行分到
//      7..14 空闲槽；0..6 的升级项原样保留（科技树不变）。再显式
//      Sub5409B0_Hook(道具) 保证按钮被创建（缓存幂等）。
//   2) hook sub_5409B0：slot<0->不创建；slot<=6->原版单行（不影响其他 30+ 调用者）；
//      slot>=7->把槽位临时降为 0 让原版安全建好按钮，再重摆到第二行
//      （列宽 69 同原版，x=18+col*69, y=3+row*63），按钮存入自有缓存 g_fishCache
//      （避开原版 257 数组越界写）。
//   3) hook sub_538090（购买/点击总闸门）：原版 slot<7 走原版缓存 *(this+257+slot)；
//      slot>=7（仅我改过才出现）-> 改从 g_fishCache[slot] 取按钮。这样第二行按钮
//      被点击时，sub_549380 第一句 result=sub_538090(a2) 能拿到非空的按钮指针，
//      购买逻辑正常执行。
//
// 配置（InsaniquariumGameExtend.ini）：
//   [StoreAllFish]
//   Enabled = 1    ; 1 = 启用（默认）；0 = 完全回退原版商店逻辑
// ===================================================================
#include "pch.h"
#include "Core/Feature.h"
#include "Core/IniConfig.h"
#include "Core/GameVersion.h"
#include "Core/Patch.h"
#include "Core/Logger.h"
#include "Core/GameApi.h"
#include "Core/Trampoline.h"
#include <cstring>

using namespace gameapi; // _DWORD, _BYTE, Fn typedefs, addr::, Va, VaToRva

// ===========================================================================
// 文件作用域：hook 状态 + 中继函数
// （中继函数含内联汇编，引用的变量必须在文件作用域，不能放命名空间内）
// ===========================================================================

// ---- hook 状态（文件级静态，DLL 生命周期内持久）----
static InlineHook g_hook5409B0 = {0, 0, 0, {}, 0};
static InlineHook g_hook541200 = {0, 0, 0, {}, 0};
static InlineHook g_hook538090 = {0, 0, 0, {}, 0};

// 扩展鱼按钮缓存（按 slot 索引）。原版缓存是 *(this+257+slot)，slot>=7 时越界写堆，
// 故鱼按钮存这里；每次开商店（sub_541200）清空，避免跨次进入的悬垂指针。
static _DWORD* g_fishCache[32] = {0};

// 中继 -> 钩子 的函数指针（中继通过 call eax 间接调用，规避内联汇编修饰名歧义）
static uintptr_t g_relay5409B0_tgt = 0;
static uintptr_t g_relay541200_tgt = 0;
static uintptr_t g_relay538090_tgt = 0;

// ---- 前向声明（钩子函数定义在下方命名空间内，extern "C" 保证 C 链接）----
extern "C" _DWORD* __stdcall Sub5409B0_Hook(_DWORD* self, int a2, int a3);
extern "C" int     __stdcall Sub541200_Hook(_DWORD* self);
extern "C" _DWORD* __stdcall Sub538090_Hook(_DWORD* self, int a2);

// ===========================================================================
// 中继函数（__declspec(naked) + 内联汇编）
// ---------------------------------------------------------------------------
// 把游戏的 __thiscall 调用（ECX=this）转成 (self,...) 再交给自由函数钩子，
// 并经"变量"间接 call 钩子（不走函数符号，规避内联汇编对 __stdcall
// 修饰名的解析歧义）。
//
// 关键调用约定坑（必须同时满足）：
//   (a) 游戏 __thiscall 函数（尤其是 sub_538090）往往"顺手"保留了 edx 这种
//       易失寄存器，而其调用方（sub_549380）会依赖"返回后 edx 仍等于 a2"去
//       当下标访问数组。C 钩子任意使用 edx -> 改写它 -> 调用方拿垃圾 edx 当
//       下标越界崩溃。故中继进钩子前把调用方 edx 压栈保存，返回后再弹栈还原。
//   (a2) 同样要保活 ecx(this)：sub_538090 原版只读 ecx、从不改写，于是其调用方
//        sub_549380 的 switch 在 case1+ 直接用 ecx 当 this 调 sub_540B30。
//        C 钩子会改写 ecx -> 返回时 ecx 是垃圾 -> case1+ 把垃圾当 this 传入
//        -> *(this+8Ch) 访问违规。故 Relay538090 进钩子前把 ecx(self) 压栈，
//        返回后还原 ecx=self，精确模拟原版"不改 ecx"。
//        （sub_5409B0 / sub_541200 的调用方不依赖 ecx 保留，故那两个中继无需保 ecx。）
//   (b) 中继必须以"与原版相同的字节数"平衡栈：
//       sub_5409B0 有 2 个栈参数(thiscall) -> ret 8（弹 ret+a2+a3）；
//       sub_538090 有 1 个栈参数(thiscall) -> ret 4（弹 ret+a2）；
//       sub_541200 无栈参数(thiscall)     -> ret（弹 ret）。
// ===========================================================================

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
        mov  ecx, [esp+4]             ; 还原 ecx = self：sub_549380 的 case1+ 直接用 ecx 当
                                       ;   this 调 sub_540B30（无"mov ecx,esi"），依赖
                                       ;   "sub_538090 后 ecx 仍为 this"。原版只读 ecx 故保留；
                                       ;   C 钩子会改写它，必须在此还原，否则 case1+ 把垃圾
                                       ;   ecx 当 this 传入 sub_540B30 -> *(this+8Ch) 崩。
        mov  edx, [esp]               ; 还原调用方 edx = a2（调用方要它当下标）
        add  esp, 8                   ; 弹出 [edx][self] 保存位
        ret  4                        ; 平衡栈：弹出 ret+a2（=原版 thiscall ret 8）
    }
}

// ===========================================================================
// 钩子实现（extern "C" 保证 C 链接；放在命名空间内但 C 链接不受命名空间影响）
// ===========================================================================

namespace fe_storeallfish {

static const char* kName = "StoreAllFish";
static const char* kCat  = "[StoreAllFish]";

// sub_538090(this, a2)：返回"当前道具 a2 的按钮指针"，是商店点击/购买的总闸门。
//   原版逻辑：slot=*(this+185+a2); if(slot>=0) return *(this+257+slot); else 0。
//   sub_549380（购买回调）第一句就是 result=sub_538090(a2); if(result){switch(a2)...}，
//   返回空则整段购买被跳过 -- 这正是"第二行鱼点了没反应"的根因。
// 我们的扩展鱼用 slot>=7（原版从未出现的值）占位，按钮只存在自有缓存 g_fishCache，
// 没写回 *(this+257+slot)。故在此 hook：slot>=7 且缓存有按钮 -> 返回 g_fishCache[slot]；
// slot<7 -> 走跳板原版（完全不动原版行为）。
extern "C" _DWORD* __stdcall Sub538090_Hook(_DWORD* self, int a2)
{
    int slot = *(int*)((char*)self + (185 + a2) * 4);
    // slot>=7 仅可能是我们的扩展道具：原版从不产生该值
    if (slot >= 7 && slot < 32)
        return g_fishCache[slot];
    return ((Fn538090)g_hook538090.trampoline)(self, a2);
}

// sub_5409B0(this, a2=itemIdx, a3=visible)：通用按钮工厂。
//   slot<0 -> 不创建；slot<=6 -> 原版单行；slot>=7 -> 扩展第二行鱼。
extern "C" _DWORD* __stdcall Sub5409B0_Hook(_DWORD* self, int a2, int a3)
{
    LOG_DEBUG(kCat, "Sub5409B0 enter self=%s a2=%d", Patch::Hex((uintptr_t)self).c_str(), a2);
    int slot = *(int*)((char*)self + (185 + a2) * 4);  // 4 字节 int 槽位（IDA 实证）
    if (slot < 0)
        return nullptr;
    if (slot <= 6)
        return ((Fn5409B0)g_hook5409B0.trampoline)(self, a2, a3);  // 真实道具：原版单行

    // ---- slot >= 7：我扩展的第二行鱼 ----
    LOG_DEBUG(kCat, "  fish path slot=%d", slot);
    if (slot >= 32) return nullptr;                    // 防御：缓存数组边界
    if (g_fishCache[slot]) return g_fishCache[slot];  // 已建好，直接复用（幂等）

    // 临时把本 item 的槽位降为 0，让原版安全建按钮（不触发越界写堆 / 垃圾坐标）
    int*     field       = (int*)((char*)self + (185 + a2) * 4);
    _DWORD** cache0      = (_DWORD**)((char*)self + (257 + 0) * 4);
    int      savedField  = *field;
    _DWORD*  savedCache0 = *cache0;
    *field  = 0;
    *cache0 = nullptr;   // 强制原版重建：否则它会直接返回真实 slot0 道具的缓存按钮
    _DWORD* btn = ((Fn5409B0)g_hook5409B0.trampoline)(self, a2, a3);  // 原版：new+虚表+AddWidget+SetBounds(x=18)
    *field      = savedField;   // 还原 7..14，供下次命中本钩
    *cache0     = savedCache0;  // 还原真实 slot0 缓存，避免覆盖现金等道具
    if (!Patch::PlausiblePtr(btn)) {
        LOG_DEBUG(kCat, "  fish button creation failed, skip");
        return nullptr;
    }
    g_fishCache[slot] = btn;    // 存入我们自己的缓存（不碰原版 257+slot）

    // 重摆到第二行：k=槽位-7 作为 0..7 的横向序号
    int k = slot - 7;
    int col = k % 8;
    int row = k / 8 + 1;   // +1：永远在第一行（y=3）之下
    int x = 18 + col * 69;
    int y = 3 + row * 63;
    // SetBounds(btn, x, y, 58, 60)：btn 虚表 +160（IDA 实证）
    int* btnVtab = *(int**)btn;
    if (Patch::PlausiblePtr(btnVtab)) {
        void* setBounds = (void*)(*(int*)((char*)btnVtab + 160));
        if (Patch::PlausiblePtr(setBounds))
            ((void(__thiscall*)(_DWORD*, int, int, int, int))setBounds)(btn, x, y, 58, 60);
        else
            LOG_DEBUG(kCat, "  setBounds wild pointer, skip reposition");
    } else
        LOG_DEBUG(kCat, "  btnVtab wild pointer, skip reposition");
    LOG_DEBUG(kCat, "  fish button done a2=%d @(%d,%d)", a2, x, y);
    return btn;
}

// sub_541200 钩子：调原版后，强制所有鱼可见并触发创建。
extern "C" int __stdcall Sub541200_Hook(_DWORD* self)
{
    LOG_DEBUG(kCat, "Sub541200 enter");
    ((Fn541200)g_hook541200.trampoline)(self);  // 先调原版（设价格/槽位）

    // 开商店：清空上一轮的鱼按钮缓存，避免悬垂指针（use-after-free）
    memset(g_fishCache, 0, sizeof(g_fishCache));

    // 8 种道具：若本关被隐藏(-1)，强行分到 7..14 空闲槽（不动 0..6 升级项）。
    // 含 6 种鱼(0=guppy,1=breeder,4=carnivore,7=guppycruncher,8=beetlemuncher,9=ultravore)
    // 以及 starcatcher(6) 与星药剂(5)。
    static const int fishIdx[8]  = {0, 1, 4, 5, 6, 7, 8, 9};
    static const int fishSlot[8] = {7, 8, 9, 10, 11, 12, 13, 14};
    for (int k = 0; k < 8; ++k) {
        int* p = (int*)((char*)self + (185 + fishIdx[k]) * 4);
        if (*p == -1)
            *p = fishSlot[k];
    }
    // 显式创建（幂等：Sub5409B0_Hook 内部用 g_fishCache 去重）
    for (int k = 0; k < 8; ++k)
        Sub5409B0_Hook(self, fishIdx[k], 1);
    LOG_DEBUG(kCat, "Sub541200 done");
    return 0;
}

// ===========================================================================
// Feature 类
// ===========================================================================
class StoreAllFishFeature : public Feature {
public:
    const char* GetName() const override { return kName; }
    GameTarget  GetTarget() const override { return GameTarget::Game; }

    bool OnInstall(IniConfig& cfg, GameVersion& ver) override {
        gameapi::Init(ver.GetBaseAddress());

        // 安装跳板。stolen 必须落在"指令边界"上（>=5 字节），否则跳板复制的
        // 字节会切断一条指令 -> 跳回 original+stolen 时从中途执行乱码 -> 确定性崩溃。
        // 已从本地 Game.exe 实测前导字节：
        //   sub_5409B0: 55 8B EC 6A FF | 68 CB 94 58 00 | 64 A1 ...
        //     push ebp;mov ebp,esp;push 0FFh(2字节) ; push imm32(5字节) ; mov eax,fs:[0]...
        //     指令边界在 5 与 10 -> stolen=10
        //   sub_541200: 53 56 8B F1 8B 8E 8C 00 00 00 ...
        //     push ebx;push esi;mov esi,ecx;mov ecx,[esi+8Ch] = 10 字节 -> stolen=10
        //   sub_538090: 55 8B EC 8B 45 08 ...
        //     push ebp;mov ebp,esp;mov eax,[ebp+8] = 6 字节 -> stolen=6
        g_relay5409B0_tgt  = (uintptr_t)&Sub5409B0_Hook;
        g_relay541200_tgt  = (uintptr_t)&Sub541200_Hook;
        g_relay538090_tgt  = (uintptr_t)&Sub538090_Hook;

        g_hook5409B0.target = gameapi::Va<uintptr_t>(addr::Sub5409B0);
        g_hook5409B0.hookFn = (uintptr_t)&Relay5409B0;
        g_hook5409B0.stolen = 10;

        g_hook541200.target = gameapi::Va<uintptr_t>(addr::Sub541200);
        g_hook541200.hookFn = (uintptr_t)&Relay541200;
        g_hook541200.stolen = 10;

        g_hook538090.target = gameapi::Va<uintptr_t>(addr::Sub538090);
        g_hook538090.hookFn = (uintptr_t)&Relay538090;
        g_hook538090.stolen = 6;

        if (!MakeTrampoline(g_hook5409B0)) {
            LOG_ERROR(kCat, "sub_5409B0 trampoline install failed.");
            return false;
        }
        if (!MakeTrampoline(g_hook541200)) {
            LOG_ERROR(kCat, "sub_541200 trampoline install failed.");
            return false;
        }
        if (!MakeTrampoline(g_hook538090)) {
            LOG_ERROR(kCat, "sub_538090 trampoline install failed.");
            return false;
        }
        LOG_INFO(kCat, "Installed (sub_5409B0 + sub_541200 + sub_538090). "
                 "Hidden 8 items will be placed in slots 7..14 with dual-row display, "
                 "clickable for purchase.");
        return true;
    }
};

REGISTER_FEATURE(StoreAllFishFeature)

} // namespace fe_storeallfish
