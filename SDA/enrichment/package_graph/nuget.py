from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    package = name.lower()
    data = fetch_json(f"https://api.nuget.org/v3/registration5-gz-semver2/{quote(package)}/index.json")
    items = data.get("items") if data else None
    if not isinstance(items, list):
        return []
    catalog_items: list[dict] = []
    for page in items:
        if not isinstance(page, dict):
            continue
        page_items = page.get("items")
        if isinstance(page_items, list):
            catalog_items.extend(item for item in page_items if isinstance(item, dict))
        elif page.get("@id"):
            subpage = fetch_json(str(page["@id"]))
            sub_items = subpage.get("items") if subpage else None
            if isinstance(sub_items, list):
                catalog_items.extend(item for item in sub_items if isinstance(item, dict))
    selected = None
    for item in catalog_items:
        catalog = item.get("catalogEntry")
        if not isinstance(catalog, dict):
            continue
        if not version or str(catalog.get("version") or "").lower() == version.lower():
            selected = catalog
            if version:
                break
    if not isinstance(selected, dict):
        return []
    groups = selected.get("dependencyGroups") or []
    deps: list[PackageDependency] = []
    if not isinstance(groups, list):
        return deps
    for group in groups:
        if not isinstance(group, dict):
            continue
        for dep in group.get("dependencies") or []:
            if not isinstance(dep, dict) or not dep.get("id"):
                continue
            deps.append(
                PackageDependency(
                    ecosystem="nuget",
                    name=str(dep["id"]),
                    version_spec=str(dep.get("range") or "") or None,
                    dependency_type="dependencyGroups",
                    scope="runtime",
                    source="nuget-registration",
                )
            )
    return deps
