from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    data = fetch_json(f"https://formulae.brew.sh/api/formula/{quote(name)}.json")
    if not data:
        return []
    deps: list[PackageDependency] = []
    for dep_name in data.get("dependencies") or []:
        if isinstance(dep_name, str):
            deps.append(
                PackageDependency(
                    ecosystem="brew",
                    name=dep_name,
                    dependency_type="dependencies",
                    scope="runtime",
                    source="homebrew-api",
                )
            )
    for dep_name in data.get("build_dependencies") or []:
        if isinstance(dep_name, str):
            deps.append(
                PackageDependency(
                    ecosystem="brew",
                    name=dep_name,
                    dependency_type="build_dependencies",
                    scope="build-time",
                    source="homebrew-api",
                )
            )
    return deps
