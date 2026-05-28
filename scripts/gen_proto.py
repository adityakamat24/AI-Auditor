#!/usr/bin/env python
"""Generate Python protobuf bindings from ``proto/*.proto`` into ``auditor/proto_gen/``.

protoc (via grpcio-tools) emits flat cross-imports like ``import events_pb2``; this rewrites them to
package-qualified ``from auditor.proto_gen import events_pb2`` so the generated code imports cleanly as
``auditor.proto_gen.<name>_pb2``. Invoked by ``make proto`` / ``./make.ps1 proto``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTO_DIR = ROOT / "proto"
OUT_DIR = ROOT / "auditor" / "proto_gen"
PACKAGE = "auditor.proto_gen"

# Matches protoc's generated cross-imports: `import events_pb2` or `import events_pb2 as events__pb2`
_IMPORT_RE = re.compile(r"^import (\w+_pb2)\b", re.MULTILINE)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    protos = sorted(str(p) for p in PROTO_DIR.glob("*.proto"))
    if not protos:
        print("no .proto files found in", PROTO_DIR, file=sys.stderr)
        return 1

    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        f"--pyi_out={OUT_DIR}",
        *protos,
    ]
    print("running:", " ".join(cmd))
    res = subprocess.run(cmd, cwd=str(ROOT))
    if res.returncode != 0:
        return res.returncode

    # Rewrite flat cross-imports -> package-qualified.
    for f in sorted([*OUT_DIR.glob("*_pb2.py"), *OUT_DIR.glob("*_pb2.pyi")]):
        text = f.read_text(encoding="utf-8")
        new = _IMPORT_RE.sub(rf"from {PACKAGE} import \1", text)
        if new != text:
            f.write_text(new, encoding="utf-8")
            print("fixed imports in", f.name)

    (OUT_DIR / "__init__.py").write_text(
        '"""Generated protobuf bindings (DO NOT EDIT). Regenerate with ``make proto``."""\n',
        encoding="utf-8",
    )
    print("proto generation complete ->", OUT_DIR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
