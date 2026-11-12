from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    data = fetch_json(f"https://api.anaconda.org/package/conda-forge/{quote(name)}")
    files = data.get("files") if data else None
    if not isinstance(files, list):
        return []
    selected = None
    for item in files:
        if not isinstance(item, dict):
            continue
        attrs = item.get("attrs")
        if not isinstance(attrs, dict):
            continue
        if version and str(attrs.get("version") or "") != version:
            continue
        selected = attrs
        if version:
            break
    if not isinstance(selected, dict):
        return []
    deps: list[PackageDependency] = []
    for raw in selected.get("depends") or []:
        if not isinstance(raw, str):
            continue
        pieces = raw.split()
        if not pieces:
            continue
        dep_name = pieces[0]
        if dep_name.startswith("__"):
            continue
        deps.append(
            PackageDependency(
                ecosystem="conda",
                name=dep_name,
                version_spec=" ".join(pieces[1:]) or None,
                dependency_type="depends",
                scope="runtime",
                source="anaconda-api",
            )
        )
    return deps
