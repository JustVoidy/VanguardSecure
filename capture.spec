# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for NetShield capture binary
# Run: pyinstaller capture.spec   (from project root, with venv active)

block_cipher = None

a = Analysis(
    ['scripts/capture.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'scapy.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.layers.l2',
        'scapy.layers.dns',
        'scapy.sendrecv',
        'scapy.arch',
        'scapy.arch.linux',
        'scapy.compat',
        'sklearn.utils._cython_blas',
        'sklearn.neighbors.typedefs',
        'sklearn.neighbors._partition_nodes',
        'joblib',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tensorflow', 'torch', 'matplotlib', 'pandas'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
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
    name='capture',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
