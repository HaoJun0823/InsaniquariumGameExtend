exe = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\Game.exe"
exeb = open(exe, "rb").read()
import re
print("---- 'default' 上下文（路径/格式串迹象）----")
for m in re.finditer(rb"default", exeb):
    i = m.start()
    ctx = exeb[max(0,i-30):i+30]
    if b"\\" in ctx or b"%" in ctx or b".xml" in ctx or b".properties" in ctx:
        print(f"@ {i}: {ctx!r}")
print("---- 'default'+'.xml' 拼接痕迹 ----")
for m in re.finditer(rb"default[^ -~]{0,8}\.xml", exeb):
    print("found:", m.group(), "@", m.start())
print("---- 每个 .xml 字面量前的 50 字节（看资源名怎么构造）----")
for m in re.finditer(rb"[ -~\\/]{2,50}\.xml", exeb):
    s = m.start()
    pre = exeb[max(0,s-50):s]
    print(f"@ {s} pre={pre!r}  full={m.group()!r}")
