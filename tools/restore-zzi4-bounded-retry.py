from pathlib import Path

path = Path("src/targets/pa3q-S938BXXUCZZI4/target.h")
text = path.read_text(encoding="utf-8")
old = (
    "#define APP_TRACEFS_PHYS_ALIAS_DATA 1\n"
    "#ifndef DEFAULT_EXPLOIT_ATTEMPTS\n"
    "#define DEFAULT_EXPLOIT_ATTEMPTS 4\n"
    "#endif\n"
)
new = (
    "#define APP_TRACEFS_PHYS_ALIAS_DATA 1\n"
    "/* A missed pselect/FOPS window is state-neutral. Retry only while no write\n"
    " * has landed; preload.c stops immediately after a landed write and keeps\n"
    " * the route-delay index shared across supervisor children. */\n"
    "#define APP_FOPS_RETRY_BUDGET 8\n"
)
count = text.count(old)
if count != 1:
    raise SystemExit(f"expected exact target policy block once, found {count}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("restored APP_FOPS_RETRY_BUDGET=8 for ZZI4")
