from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    url = f"https://rubygems.org/api/v2/rubygems/{quote(name)}/versions/{quote(version)}.json" if version else f"https://rubygems.org/api/v1/gems/{quote(name)}.json"
    data = fetch_json(url)
    deps_data = data.get("dependencies") if data else None
    if not isinstance(deps_data, dict):
        return []
    deps: list[PackageDependency] = []
    for field, scope in [("runtime", "runtime"), ("development", None)]:
        values = deps_data.get(field)
        if not isinstance(values, list):
            continue
        for dep in values:
            if not isinstance(dep, dict) or not dep.get("name"):
                continue
            deps.append(
                PackageDependency(
                    ecosystem="gem",
                    name=str(dep["name"]),
                    version_spec=str(dep.get("requirements") or "") or None,
                    dependency_type=field,
                    scope=scope,
                    source="rubygems",
                )
            )
    return deps
