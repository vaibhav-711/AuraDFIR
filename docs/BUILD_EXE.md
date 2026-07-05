# Building the obfuscated AuraDFIR.exe

This produces a **single, self-contained Windows executable**. The end user just
double-clicks it — the Python interpreter and every dependency are bundled inside,
so there is nothing to `pip install`. The application code is obfuscated with
PyArmor so a low-effort attacker who unpacks the exe cannot read or decompile it.

## Why this approach

| Concern | How it's handled |
|---|---|
| "User just runs it, installs all deps" | PyInstaller **onefile** bundles CPython + all wheels into the exe. |
| "Obfuscated so it can't be trivially de-obfuscated" | PyArmor transforms the bytecode; `pyinstxtractor` + `decompyle3`/`pycdc` on the extracted files yield unusable output. This is intentionally *moderate* protection (fast, robust) — not maximum-mode, which is brittle. |
| Templates / static / .env | Added as PyInstaller `datas`; resolved from `sys._MEIPASS` at runtime (see `app/config.py`). |
| Writable database | SQLite is written next to the exe (or `%LOCALAPPDATA%\Aura DFIR` if you set `AURADFIR_DATA`). |

## Prerequisites

- Windows, Python 3.11 (the exe targets the OS/arch you build on).
- The project's venv with runtime **and** build dependencies:

```powershell
cd "D:\AI DFCII\Aura DFIR"
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-build.txt
```

## Build

```powershell
python build\build.py
```

Steps performed:
1. `pyarmor gen -O build/obf --recursive app launcher.py` → obfuscated source tree.
2. `PyInstaller auradfir.spec` → `dist\AuraDFIR.exe` (single file).

Build time is typically 1–3 minutes; the exe is ~40–70 MB (it embeds CPython,
FastAPI, uvicorn, the Elasticsearch client, etc.).

## Running the exe

Aura DFIR is a web app that needs **Elasticsearch** as its log store. Elasticsearch
is a separate Java service, so it is *not* baked into the exe — but the exe
**manages it for you** (no Docker):

1. Create the first admin (no Python needed):
   ```
   AuraDFIR.exe --create-admin admin
   ```
2. Start it:
   ```
   AuraDFIR.exe
   ```
   **On the very first launch** it asks how to get Elasticsearch:
   - enter the folder of an **existing** ES install (contains `bin\elasticsearch.bat`), or
   - enter the **URL** of an ES already running elsewhere, or
   - press **Enter** to **download & set it up automatically** (one-time ~600 MB).

   Your choice is saved to `es_config.json` next to the exe. **Every later launch
   starts Elasticsearch automatically — no prompt, no re-download.** When you close
   the window, the exe stops the Elasticsearch it started.

`AuraDFIR.exe --help` lists all subcommands; `AuraDFIR.exe --reset-es` forgets the
saved Elasticsearch choice so the next launch prompts again. The SQLite DB,
`es_config.json` and (optional) downloaded ES live next to the exe, or under
`%LOCALAPPDATA%\Aura DFIR` if you set `AURADFIR_DATA`.

A `.env` next to the exe is optional; use it to pin settings, e.g.:

```
SECRET_KEY=<long-random-string>
ES_URL=http://localhost:9200          # if set & reachable, the prompt is skipped
```

## Distribution notes / caveats

- **Antivirus false positives**: PyInstaller onefile + PyArmor commonly trip
  heuristic AV. Code-sign the exe (`signtool`) for real distribution, and/or
  submit to vendors. Unsigned onefile exes may be flagged.
- **Cross-platform**: build on each target OS; there is no cross-compile.
- **Reproducibility**: pin exact versions in `requirements*.txt` before release.
- **Not DRM**: obfuscation raises the bar; it is not unbreakable. Keep secrets
  (API keys) in the runtime DB/.env, never hard-coded.

## Alternative: PyInstaller only (no obfuscation)

If you don't want the PyArmor dependency, build directly — you still get a
onefile exe, just with easier-to-decompile bytecode:

```powershell
pyinstaller --onefile --name Aura DFIR ^
  --add-data "app/templates;app/templates" ^
  --add-data "app/static;app/static" ^
  --collect-submodules uvicorn --collect-submodules app launcher.py
```
