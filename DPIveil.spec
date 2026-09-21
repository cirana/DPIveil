# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

project_root = Path(SPECPATH)

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[(str(project_root / "profiles" / "default.json"), "profiles")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# WinDivert is intentionally NOT embedded in DPIveil.exe.
# The official DLL and driver are copied next to the EXE by scripts/build.ps1.
blocked = {"windivert64.dll", "windivert64.sys"}
a.binaries = [entry for entry in a.binaries if Path(entry[0]).name.lower() not in blocked]
a.datas = [entry for entry in a.datas if Path(entry[0]).name.lower() not in blocked]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="DPIveil",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
