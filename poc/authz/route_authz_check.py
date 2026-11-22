#!/usr/bin/env python3
"""Static authorization-chain inventory for the Julep control plane.

Unlike a declaration grep, this walks every route module, resolves
``Depends(...)`` transitively (params + auth calls in function bodies), verifies
the gate implementations, and pins the source commit before reporting.

Usage:
  JULEP_SRC=/path/to/julep python3 route_authz_check.py --out evidence/authz

Exit 0 only when: commit matches, tree is clean, every mutating route has a
resolved gate, and the gate implementations contain the expected role check.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

AUTH_FUNCS = {"require_key", "require_admin", "require_client", "require_worker"}
GATE_LEVEL = {
    "require_admin": "admin",
    "require_worker": "worker",
    "require_client": "client_or_admin",
}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
DEFAULT_COMMIT = "fc74d079a18c8124b2627ca4717f5a9c269267db"


def dep_from_expr(expr: ast.AST | None) -> str | None:
    """Return the dependency name from ``Depends(fn)``."""
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "Depends":
        if expr.args:
            arg = expr.args[0]
            if isinstance(arg, ast.Name):
                return arg.id
            if isinstance(arg, ast.Attribute):
                return arg.attr
    return None


def param_deps(arg: ast.arg) -> list[str]:
    """Dependencies declared in the annotation (``Annotated[T, Depends(fn)]``)."""
    out: list[str] = []
    ann = arg.annotation
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name) and ann.value.id == "Annotated":
        sl = ann.slice
        elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
        for elt in elts:
            name = dep_from_expr(elt)
            if name:
                out.append(name)
    return out


def function_deps(node: ast.AST) -> list[str]:
    """All ``Depends(...)`` declarations on a function: annotations + defaults."""
    out: list[str] = []
    for arg in list(node.args.args) + list(node.args.kwonlyargs):
        out.extend(param_deps(arg))
    defaults = list(node.args.defaults)
    if defaults:
        for default in defaults:
            name = dep_from_expr(default)
            if name:
                out.append(name)
    for default in node.args.kw_defaults:
        if default is None:
            continue
        name = dep_from_expr(default)
        if name:
            out.append(name)
    return out


def body_calls(node: ast.AST) -> set[str]:
    return {
        call.func.id
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }


def index_functions(src: Path) -> dict[str, tuple[ast.AST, Path]]:
    """Index functions by ``module:name`` plus unambiguous bare names.

    Bare names are only kept when exactly one definition exists, so a same-named
    helper in two modules can never silently resolve to the wrong file.
    """
    qualified: dict[str, tuple[ast.AST, Path]] = {}
    by_name: dict[str, list[tuple[ast.AST, Path]]] = {}
    for path in sorted(src.rglob("*.py")):
        if any(part in {".git", ".venv", "__pycache__", "node_modules"} for part in path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified.setdefault(f"{path.stem}:{node.name}", (node, path))
                by_name.setdefault(node.name, []).append((node, path))
    index = dict(qualified)
    for name, entries in by_name.items():
        if len(entries) == 1:
            index[name] = entries[0]
    return index


def _lookup(name: str, index, module: str | None):
    if module:
        entry = index.get(f"{module}:{name}")
        if entry is not None:
            return entry
    return index.get(name)


def resolve(name: str, index, seen: set[str], module: str | None = None) -> set[str]:
    if name in seen:
        return set()
    seen.add(name)
    deps = {name}
    entry = _lookup(name, index, module)
    if not entry:
        return deps
    node, path = entry
    inner = path.stem
    for dep in function_deps(node):
        deps |= resolve(dep, index, seen, inner)
    for call in body_calls(node):
        if call in AUTH_FUNCS:
            deps |= resolve(call, index, seen, inner)
    return deps


def direct_deps(name: str, index, module: str | None = None) -> set[str]:
    entry = _lookup(name, index, module)
    if not entry:
        return set()
    node, _ = entry
    out: set[str] = set(function_deps(node))
    out |= {call for call in body_calls(node) if call in AUTH_FUNCS}
    return out


def parse_route_module(path: Path, index) -> tuple[list[dict], dict[str, dict]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    routers: dict[str, dict] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "APIRouter"):
            continue
        prefix = ""
        deps: list[str] = []
        for kw in value.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                prefix = kw.value.value
            if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                deps = [d for elt in kw.value.elts if (d := dep_from_expr(elt))]
        for target in node.targets:
            if isinstance(target, ast.Name):
                routers[target.id] = {"prefix": prefix, "deps": deps}

    routes: list[dict] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and isinstance(dec.func.value, ast.Name)
                and dec.func.value.id in routers
            ):
                continue
            router = routers[dec.func.value.id]
            method = dec.func.attr.upper()
            route_path = ""
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                route_path = dec.args[0].value
            direct = list(router["deps"])
            direct.extend(function_deps(node))
            routes.append(
                {
                    "method": method,
                    "path": router["prefix"] + route_path,
                    "func": node.name,
                    "file": str(path),
                    "line": node.lineno,
                    "direct_deps": sorted(set(direct)),
                    "router_level_deps": sorted(set(router["deps"])),
                }
            )
    return routes, routers


def include_router_deps(src: Path) -> dict[str, set[str]]:
    """Map route-module stem -> dependencies attached at ``app.include_router``."""
    app_py = src / "julep" / "server" / "app.py"
    if not app_py.is_file():
        return {}
    tree = ast.parse(app_py.read_text(encoding="utf-8"))
    alias_to_module: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(".routes"):
            for alias in node.names:
                if alias.name == "router" and alias.asname:
                    alias_to_module[alias.asname] = node.module.rsplit(".", 1)[-1]
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "include_router"
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            continue
        module = alias_to_module.get(node.args[0].id)
        if module is None:
            continue
        for kw in node.keywords:
            if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                deps = {d for elt in kw.value.elts if (d := dep_from_expr(elt))}
                out.setdefault(module, set()).update(deps)
    return out


def _raises_403(statements: list[ast.stmt]) -> bool:
    for statement in statements:
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "status_code"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value == 403
                ):
                    return True
    return False


def _structural_role_guard(node: ast.AST, role: str, op_type: type[ast.cmpop]) -> bool:
    """True only for ``if <...>.role <op> "<role>": raise ...403``."""
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.If):
            continue
        test = candidate.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], op_type)
        ):
            continue
        left_has_role = any(
            isinstance(item, ast.Attribute) and item.attr == "role"
            for item in ast.walk(test.left)
        )
        right_has_role = any(
            isinstance(item, ast.Constant) and item.value == role
            for item in ast.walk(test.comparators[0])
        )
        if left_has_role and right_has_role and _raises_403(candidate.body):
            return True
    return False


def verify_gate_impl(index, src: Path) -> dict:
    out: dict = {}
    expectations = (
        ("require_admin", "admin", ast.NotEq),
        ("require_worker", "worker", ast.NotEq),
        ("require_client", "worker", ast.Eq),
    )
    for fn, role, op_type in expectations:
        entry = index.get(fn)
        if not entry:
            out[fn] = {"found": False, "verified": False}
            continue
        node, path = entry
        strings = {
            c.value
            for c in ast.walk(node)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
        }
        structural = _structural_role_guard(node, role, op_type)
        out[fn] = {
            "found": True,
            "file": str(path),
            "line": node.lineno,
            "expected_role": role,
            "expected_literal_present": role in strings,
            "structural_role_guard": structural,
            "raises_403": _raises_403([node]),
            "verified": bool(structural and role in strings),
        }

    entry = index.get("require_key")
    if entry:
        node, path = entry
        strings = {
            c.value
            for c in ast.walk(node)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
        }
        delegates = any(
            isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and c.func.attr == "authenticate"
            for c in ast.walk(node)
        )
        out["require_key"] = {
            "found": True,
            "file": str(path),
            "line": node.lineno,
            "bearer_scheme": "bearer" in {s.lower() for s in strings},
            "delegates_to_keyring": delegates,
            "verified": bool("bearer" in {s.lower() for s in strings} and delegates),
        }

    auth_py = src / "julep" / "server" / "auth.py"
    if auth_py.is_file():
        tree = ast.parse(auth_py.read_text(encoding="utf-8"))
        for cls in tree.body:
            if not (isinstance(cls, ast.ClassDef) and cls.name == "KeyRing"):
                continue
            for item in cls.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "authenticate":
                    constant_time = any(
                        isinstance(c, ast.Call)
                        and isinstance(c.func, ast.Attribute)
                        and c.func.attr == "compare_digest"
                        for c in ast.walk(item)
                    )
                    out["KeyRing.authenticate"] = {
                        "found": True,
                        "file": str(auth_py),
                        "line": item.lineno,
                        "constant_time_compare": constant_time,
                        "verified": constant_time,
                    }
    return out


def git(src: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(src), *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default=os.environ.get("JULEP_SRC", ""))
    parser.add_argument("--out", default="")
    parser.add_argument("--expected-commit", default=os.environ.get("JULEP_EXPECTED_COMMIT", DEFAULT_COMMIT))
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    if not args.src:
        print("error: --src or JULEP_SRC required", file=sys.stderr)
        return 2
    src = Path(args.src).resolve()
    if not (src / "julep" / "server" / "routes").is_dir():
        print(f"error: not a Julep tree: {src}", file=sys.stderr)
        return 2

    head = git(src, "rev-parse", "HEAD")
    dirty_lines = git(src, "status", "--porcelain")
    commit_ok = head == args.expected_commit
    clean = not dirty_lines

    index = index_functions(src)
    route_root = src / "julep" / "server" / "routes"
    route_files = sorted(
        path
        for path in route_root.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    routes: list[dict] = []
    for path in route_files:
        found, _ = parse_route_module(path, index)
        routes.extend(found)

    include_deps = include_router_deps(src)
    for route in routes:
        extra = include_deps.get(Path(route["file"]).stem, set())
        if extra:
            route["direct_deps"] = sorted(set(route["direct_deps"]) | extra)
            route["include_router_deps"] = sorted(extra)

    edges: list[dict] = []
    all_nodes: set[str] = set()
    for route in routes:
        module = Path(route["file"]).stem
        transitive: set[str] = set()
        for dep in route["direct_deps"]:
            transitive |= resolve(dep, index, set(), module)
            for target in direct_deps(dep, index, module):
                edges.append({"from": dep, "to": target, "kind": "dependency"})
        route["transitive_deps"] = sorted(transitive)
        levels = [GATE_LEVEL[d] for d in transitive if d in GATE_LEVEL]
        route["gate_level"] = levels[0] if levels else None
        route["gated"] = bool(levels)
        all_nodes.add(route["func"])
        all_nodes |= transitive
        for dep in route["direct_deps"]:
            edges.append({"from": route["func"], "to": dep, "kind": "route_param"})

    mutating = [r for r in routes if r["method"] in MUTATING]
    ungated_mutating = [r for r in mutating if not r["gated"]]
    ungated_gets = [r for r in routes if r["method"] == "GET" and not r["gated"]]
    gate_impl = verify_gate_impl(index, src)
    gates_ok = all(v.get("verified") for v in gate_impl.values())

    matrix = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": str(src),
        "commit": head,
        "expected_commit": args.expected_commit,
        "commit_ok": commit_ok,
        "dirty": bool(dirty_lines),
        "routes": routes,
        "summary": {
            "total": len(routes),
            "mutating": len(mutating),
            "ungated_mutating": len(ungated_mutating),
            "ungated_gets": len(ungated_gets),
            "gates_verified": gates_ok,
        },
        "gate_impl": gate_impl,
    }

    inventory = [f"# route inventory @ {head} ({'clean' if clean else 'DIRTY'})", ""]
    for route in sorted(routes, key=lambda r: (r["path"], r["method"])):
        inventory.append(
            f"{route['method']:<6} {route['path']:<28} {route['func']:<24} "
            f"deps={','.join(route['direct_deps']) or '-'} "
            f"gate={route['gate_level'] or 'NONE'}"
        )
    inventory.append("")
    inventory.append(f"total={len(routes)} mutating={len(mutating)} ungated_mutating={len(ungated_mutating)}")

    graph = {"nodes": sorted(all_nodes), "edges": sorted(edges, key=lambda e: (e["from"], e["to"]))}

    commit_txt = [
        f"source: {src}",
        f"HEAD: {head}",
        f"expected: {args.expected_commit}",
        f"match: {commit_ok}",
        f"dirty: {bool(dirty_lines)}",
    ]
    if dirty_lines:
        commit_txt.append("dirty files:")
        commit_txt.extend(f"  {line}" for line in dirty_lines.splitlines())

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "route_inventory.txt").write_text("\n".join(inventory) + "\n", encoding="utf-8")
        (out / "route_authz_matrix.json").write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
        (out / "dependency_graph.json").write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")
        (out / "commit_verification.txt").write_text("\n".join(commit_txt) + "\n", encoding="utf-8")

    print(f"source: {src}")
    print(f"commit: {head} (expected {args.expected_commit}) -> {'OK' if commit_ok else 'MISMATCH'}")
    print(f"dirty: {bool(dirty_lines)}")
    print(f"routes: {len(routes)} mutating: {len(mutating)} ungated_mutating: {len(ungated_mutating)}")
    for route in ungated_mutating:
        print(f"  UNGATED {route['method']} {route['path']} -> {route['func']}")
    for name, info in gate_impl.items():
        print(f"gate {name}: {'verified' if info.get('verified') else 'NOT VERIFIED'} {info.get('file', '')}:{info.get('line', '')}")
    if ungated_gets:
        print(f"ungated GETs (informational): {', '.join(r['path'] for r in ungated_gets)}")

    ok = commit_ok and (clean or args.allow_dirty) and not ungated_mutating and gates_ok
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
