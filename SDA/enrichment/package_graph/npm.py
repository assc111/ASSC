from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    data = fetch_json(f"https://registry.npmjs.org/{quote(name, safe='@')}")
    if not data:
        return []
    versions = data.get("versions")
    if not isinstance(versions, dict):
        return []
    selected = version
    if not selected:
        latest = data.get("dist-tags", {}).get("latest") if isinstance(data.get("dist-tags"), dict) else None
        selected = latest if isinstance(latest, str) else None
    meta = versions.get(selected) if selected else None
    if not isinstance(meta, dict):
        return []
    deps: list[PackageDependency] = []
    for field, scope, optional in [
        ("dependencies", "runtime", False),
        ("optionalDependencies", "optional", True),
        ("peerDependencies", "optional", True),
        ("devDependencies", None, False),
    ]:
        values = meta.get(field)
        if not isinstance(values, dict):
            continue
        for dep_name, spec in values.items():
            if not isinstance(dep_name, str):
                continue
            deps.append(
                PackageDependency(
                    ecosystem="npm",
                    name=dep_name,
                    version_spec=str(spec) if spec else None,
                    dependency_type=field,
                    scope=scope,
                    optional=optional,
                    source="npm-registry",
                )
            )
    return deps
