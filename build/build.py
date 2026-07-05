"""Build an obfuscated single-file AuraDFIR.exe.

Pipeline:
  1. PyArmor obfuscates `app/` + `launcher.py` into build/obf/ (basic mode:
     bytecode is transformed so pyinstxtractor + a decompiler yield nothing
     usable — enough to stop a low-effort reverse engineer, without the
     fragility of maximum/BCC modes).
  2. PyInstaller bundles the obfuscated tree into one self-contained .exe
     (Python runtime + all dependencies included — the user just double-clicks;
     nothing to pip-install).

Usage (from the project root, inside the venv):
    pip install -r requirements.txt -r requirements-build.txt
    python build/build.py
Output: dist/AuraDFIR.exe
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBF = ROOT / "build" / "obf"
TARGETS = ["app", "launcher.py"]


def run(cmd):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.check_call([str(c) for c in cmd], cwd=str(ROOT))


def main():
    py = sys.executable

    # sanity: build tools present
    for mod in ("PyInstaller", "pyarmor.cli"):
        try:
            __import__(mod)
        except ImportError:
            sys.exit(f"Missing build tool for '{mod}'. Run:\n"
                     f"  {py} -m pip install -r requirements-build.txt")

    # 1. obfuscate (PyArmor 8 entry point is the pyarmor.cli module)
    if OBF.exists():
        shutil.rmtree(OBF)
    OBF.mkdir(parents=True)
    run([py, "-m", "pyarmor.cli", "gen", "-O", OBF, "--recursive", *TARGETS])

    # 2. package (spec reads build/obf and adds templates/static as data)
    run([py, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", ROOT / "dist", "--workpath", ROOT / "build" / "pyi",
         ROOT / "auradfir.spec"])

    exe = ROOT / "dist" / ("AuraDFIR.exe" if sys.platform == "win32" else "Aura DFIR")
    print("\n" + "=" * 60)
    print(f"  Done: {exe}" if exe.exists() else "  Build finished (check dist/).")
    print("  Ship dist/AuraDFIR.exe together with a .env file and make sure")
    print("  Elasticsearch is reachable at ES_URL.")
    print("=" * 60)


if __name__ == "__main__":
    main()
