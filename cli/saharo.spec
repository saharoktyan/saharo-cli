# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
import sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

SPEC_FILE = Path(sys.argv[0]).resolve()
ROOT = SPEC_FILE.parent.parent

hiddenimports = []

hiddenimports += [
    "shellingham",
    "shellingham.nt",
    "shellingham.posix",
    "httpx",
    "httpcore",
    "certifi",
]

hiddenimports += collect_submodules("saharo_cli")
hiddenimports += collect_submodules("saharo_client")

datas = []
datas += collect_data_files("saharo_cli", include_py_files=False)
datas += collect_data_files("saharo_client", include_py_files=False)

a = Analysis(
    ["saharo_entrypoint.py"],
    pathex=[str(ROOT), str(ROOT / "lib"), str(ROOT / "cli")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="saharo",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
