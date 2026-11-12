from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    if not version:
        crate = fetch_json(f"https://crates.io/api/v1/crates/{quote(name)}")
        versions = crate.get("versions") if crate else None
        if isinstance(versions, list) and versions:
            first = versions[0]
            if isinstance(first, dict):
                version = first.get("num")
    if not version:
        return []
    data = fetch_json(f"https://crates.io/api/v1/crates/{quote(name)}/{quote(version)}/dependencies")
    raw_deps = data.get("dependencies") if data else None
    if not isinstance(raw_deps, list):
        return []
    deps: list[PackageDependency] = []
    for item in raw_deps:
        if not isinstance(item, dict):
            continue
        dep_name = item.get("crate_id") or item.get("name")
        if not dep_name:
            continue
        kind = str(item.get("kind") or "normal")
        deps.append(
            PackageDependency(
                ecosystem="cargo",
                name=str(dep_name),
                version_spec=str(item.get("req") or "") or None,
                dependency_type=kind,
                scope={"normal": "runtime", "build": "build-time", "dev": "test-only"}.get(kind),
                optional=bool(item.get("optional")),
                source="crates.io",
            )
        )
    return deps
