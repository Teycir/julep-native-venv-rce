#!/usr/bin/env python3
"""Trace who can publish/sign a bundle and who verifies it before native exec.

Static, line-cited trace of the publication path:
  POST /releases -> release_from_bytes        (no signing, admin-gated)
  CLI publish_bundle -> JULEP_BUNDLE_SIGNING_KEY -> signature
  worker resolve_and_register -> allowed signers -> native grant -> executor

Usage: JULEP_SRC=/path/to/julep python3 bundle_signature_trace.py
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

SRC = Path(os.environ.get("JULEP_SRC", "")).resolve()
if not (SRC / "julep").is_dir():
    print("error: set JULEP_SRC to a Julep source tree", file=sys.stderr)
    raise SystemExit(2)


def line_of(path: Path, pattern: str) -> int | None:
    rx = re.compile(pattern)
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if rx.search(line):
            return number
    return None


def func_node(path: Path, name: str) -> ast.AST | None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def identifiers(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            out.add(child.id)
        elif isinstance(child, ast.Attribute):
            out.add(child.attr)
    return out


CHECKS = [
    ("julep/server/routes/releases.py", r"def publish_release", "POST /releases handler"),
    ("julep/server/routes/releases.py", r"release_from_bytes", "stores prebuilt release bytes"),
    ("julep/server/routes/releases.py", r"Depends\(require_admin\)", "admin gate on publication"),
    ("julep/bundle.py", r"def publish_bundle", "CLI bundle publisher"),
    ("julep/bundle.py", r"JULEP_BUNDLE_SIGNING_KEY", "signing key source"),
    ("julep/deploy.py", r"publish_bundle\(", "deploy path calls publisher"),
    ("julep/worker_store.py", r"def resolve_and_register", "worker-side registration"),
    ("julep/worker_store.py", r"JULEP_BUNDLE_ALLOWED_SIGNERS", "allowed signer config"),
    ("julep/worker_store.py", r"JULEP_PURE_NATIVE_DEPS", "native grant config"),
    ("julep/cli/_resolve_child.py", r"_LOCAL_DEV_SIGNING_KEY", "dev-only local key"),
]

rows: list[tuple[str, str, int | None, str]] = []
missing: list[str] = []
for rel, pattern, label in CHECKS:
    path = SRC / rel
    if not path.is_file():
        missing.append(f"{rel} missing")
        rows.append((rel, label, None, "MISSING FILE"))
        continue
    number = line_of(path, pattern)
    if number is None:
        missing.append(f"{rel}: {pattern}")
    rows.append((rel, label, number, "found" if number else "NOT FOUND"))

releases = SRC / "julep/server/routes/releases.py"
node = func_node(releases, "publish_release") if releases.is_file() else None
signs_in_route = False
route_line = None
if node is not None:
    route_line = node.lineno
    names = identifiers(node)
    signs_in_route = any("sign" in name.lower() for name in names)

head = subprocess.run(
    ["git", "-C", str(SRC), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
).stdout.strip()

print(f"source: {SRC}")
print(f"commit: {head}")
print("")
print(f"{'file':<45} {'line':<6} {'status':<10} label")
for rel, label, number, status in rows:
    print(f"{rel:<45} {str(number or '-'):<6} {status:<10} {label}")
print("")
print(f"publish_release line: {route_line}")
print(f"POST /releases signs bundle: {signs_in_route} (expected False)")
print(f"missing symbols: {len(missing)}")
for item in missing:
    print(f"  MISSING {item}")

ok = not missing and not signs_in_route
print(f"RESULT: {'PASS' if ok else 'FAIL'}")
raise SystemExit(0 if ok else 1)
