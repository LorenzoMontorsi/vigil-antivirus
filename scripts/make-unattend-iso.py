"""Crea una ISO (ISO9660 + Joliet) con i file di una cartella.

Uso: python -I make-unattend-iso.py <cartella-sorgente> <file.iso>
Richiede pycdlib. Windows Setup cerca autounattend.xml nella radice di tutti i supporti.
"""

import io
import sys
from pathlib import Path

import pycdlib

src, out = Path(sys.argv[1]), Path(sys.argv[2])
iso = pycdlib.PyCdlib()
iso.new(interchange_level=3, joliet=3, vol_ident="VIGIL_UNATTEND")
for i, f in enumerate(sorted(p for p in src.iterdir() if p.is_file())):
    data = f.read_bytes()
    # Nome ISO9660 breve e univoco; quello vero (lungo) sta nel record Joliet.
    iso.add_fp(io.BytesIO(data), len(data), f"/F{i:02d}.;1", joliet_path="/" + f.name)
    print(f"  {f.name} ({len(data)} byte)")
iso.write(str(out))
iso.close()
print(f"ISO creata: {out}")
