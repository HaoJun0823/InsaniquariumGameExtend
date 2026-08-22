import re, os

p = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\old_cn_patch\patch_cn\properties\default.xml"
with open(p, "rb") as f:
    raw = f.read()
print("==== default.xml ====")
print("size:", len(raw), "encoding head:", raw[:30])
entries = re.findall(rb'<String\s+id="([^"]*)"[^>]*>([^<]*)</String>', raw)
print("count <String id=...>: ", len(entries))
for e in entries[:6]:
    print("   ", e[0].decode('utf-8','ignore'), "->", e[1].decode('utf-8','ignore'))

# mod/data 副本
q = r"G:\Projects\InsaniquariumGameExtend\mod\data\l10n_source\default.xml"
if os.path.exists(q):
    raw2 = open(q, "rb").read()
    print("mod/data copy size:", len(raw2), "same bytes:", raw == raw2,
          "entries:", len(re.findall(rb'<String\s+id="', raw2)))

# 在英文原版 exe 中查 .xml 字面量 + 关键引用
exe = r"E:\SteamLibrary\steamapps\common\Insaniquarium Deluxe\Game.exe"
exeb = open(exe, "rb").read()
print("==== Game.exe (English unmodified) size", len(exeb), "====")
xmls = sorted(set(m.group().decode("latin1","ignore") for m in re.finditer(rb"[ -~\\/]{2,40}\.xml", exeb)))
print(".xml literals:", xmls)
for kw in [b"default.xml", b"default", b"properties", b"partner.xml", b"resources.xml"]:
    i = exeb.find(kw)
    print(f"  {kw!r}: {'FOUND@'+str(i) if i>=0 else 'NOT FOUND'}")

# 游戏用"符号键"还是"英文串"做查表？抽查几个 key 是否在 exe 里出现
print("==== key-presence probe (does exe embed these symbolic ids?) ====")
for key in [b"DIALOG_BUTTON_YES", b"DIALOG_BUTTON_NO", b"UPDATE_CHECK_TITLE", b"NEW_VERSION_BODY"]:
    print(f"  {key.decode()}: {'in exe' if key in exeb else 'NOT in exe'}")

# 抽查对应英文译文是否在 exe（判断 def 是不是英文原文）
print("==== def-probe (does exe embed the English text?) ====")
for key, en in [("DIALOG_BUTTON_YES","Yes"),("DIALOG_BUTTON_NO","No"),("UPDATE_CHECK_TITLE","Update Check"),("NEW_VERSION_BODY","There is an update available")]:
    print(f"  {key}: EN '{en}' -> {'in exe' if en.encode() in exeb else 'NOT in exe'}")
