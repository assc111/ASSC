from __future__ import annotations

from packaging.requirements import InvalidRequirement, Requirement

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    data = fetch_json(url)
    info = data.get("info") if data else None
    if not isinstance(info, dict):
        return []
    deps: list[PackageDependency] = []
    for raw in info.get("requires_dist") or []:
        if not isinstance(raw, str):
            continue
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue
        marker = f"; {req.marker}" if req.marker else ""
        optional = bool(req.extras) or "extra ==" in marker or "extra in" in marker
        deps.append(
            PackageDependency(
                ecosystem="pypi",
                name=req.name,
                version_spec=str(req.specifier) or None,
                dependency_type="requires_dist",
                scope="runtime",
                optional=optional,
                source="pypi-json",
                version=None,
            )
        )
        if marker:
            deps[-1] = PackageDependency(
                ecosystem=deps[-1].ecosystem,
                name=deps[-1].name,
                version=deps[-1].version,
                version_spec=f"{deps[-1].version_spec or ''}{marker}".strip(),
                dependency_type=deps[-1].dependency_type,
                scope=deps[-1].scope,
                optional=deps[-1].optional,
                source=deps[-1].source,
            )
    return deps
