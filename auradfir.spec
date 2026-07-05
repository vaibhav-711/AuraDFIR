# PyInstaller spec — builds a single-file, obfuscated AuraDFIR.exe.
#
# Do not run PyInstaller against this spec directly; run `python build/build.py`,
# which first obfuscates the source with PyArmor into build/obf/ and then invokes
# PyInstaller. This spec reads the obfuscated tree.
#
# IMPORTANT: because PyArmor obfuscation hides the `import` statements from
# PyInstaller's static analysis, every third-party dependency must be collected
# explicitly with collect_all() — otherwise the exe raises ModuleNotFoundError
# at runtime (e.g. "No module named 'fastapi'").
import os
from PyInstaller.utils.hooks import collect_all, collect_submodules

ROOT = os.path.abspath(os.getcwd())
OBF = os.path.join(ROOT, "build", "obf")

datas, binaries, hidden = [], [], []

# Full dependency closure (datas + binaries + submodules) for anything the
# obfuscated code imports at runtime.
for pkg in [
    "fastapi", "starlette", "pydantic", "pydantic_core", "uvicorn", "anyio",
    "sniffio", "httpx", "httpcore", "h11", "certifi", "idna",
    "elasticsearch", "elastic_transport", "sqlalchemy", "jinja2", "markupsafe",
    "segno", "pyotp", "multipart", "dotenv", "openpyxl",
]:
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hidden += h
    except Exception as exc:  # noqa: BLE001
        print(f"[spec] collect_all({pkg!r}) skipped: {exc}")

# Our own (obfuscated) package: enumerate names from the importable original
# source; pathex=[OBF, ROOT] makes PyInstaller bundle the obfuscated copies.
hidden += collect_submodules("app")
hidden += [
    "uvicorn.lifespan.on", "uvicorn.loops.auto", "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto", "email.mime.text",
    "sqlalchemy.dialects.sqlite",
]

# PyArmor runtime package (name has a machine-specific suffix) must ride along.
if os.path.isdir(OBF):
    for entry in os.listdir(OBF):
        if entry.startswith("pyarmor_runtime"):
            hidden.append(entry)

# App assets (templates/static resolved from sys._MEIPASS at runtime).
datas += [
    (os.path.join(ROOT, "app", "templates"), os.path.join("app", "templates")),
    (os.path.join(ROOT, "app", "static"), os.path.join("app", "static")),
    (os.path.join(ROOT, ".env.example"), "."),
]

a = Analysis(
    [os.path.join(OBF, "launcher.py")],
    pathex=[OBF, ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "PyQt5", "PySide6"],
    noarchive=False,
)
pyz = PYZ(a.pure)

# Passing a.binaries + a.datas into EXE (with no COLLECT step) yields a
# single-file executable.
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AuraDFIR",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
