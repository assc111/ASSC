from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    data = fetch_json(f"https://repo.packagist.org/p2/{quote(name, safe='/')}.json")
    packages = data.get("packages", {}).get(name) if data else None
    if not isinstance(packages, list):
        return []
    selected = next(
        (
            item
            for item in packages
            if isinstance(item, dict) and (not version or str(item.get("version") or "") == version)
        ),
        None,
    )
    if not isinstance(selected, dict):
        return []
    deps: list[PackageDependency] = []
    for field, scope in [("require", "runtime"), ("require-dev", None)]:
        values = selected.get(field)
        if not isinstance(values, dict):
            continue
        for dep_name, spec in values.items():
            if not isinstance(dep_name, str) or dep_name.lower() == "php" or dep_name.startswith("ext-"):
                continue
            deps.append(
                PackageDependency(
                    ecosystem="composer",
                    name=dep_name,
                    version_spec=str(spec) if spec else None,
                    dependency_type=field,
                    scope=scope,
                    source="packagist",
                )
            )
    return deps
