from __future__ import annotations

from collections.abc import Callable
from ..labels import JsonDict, normalize_package_name, parse_package_ref
from ..merge import merge_component_fields, relationship_key
from . import brew, cargo, composer, conda, gem, golang, npm, nuget, pypi
from .models import PackageDependency, dependency_component


Resolver = Callable[[str, str | None], list[PackageDependency]]


RESOLVERS: dict[str, Resolver] = {
    "brew": brew.resolve,
    "cargo": cargo.resolve,
    "composer": composer.resolve,
    "conda": conda.resolve,
    "gem": gem.resolve,
    "golang": golang.resolve,
    "npm": npm.resolve,
    "nuget": nuget.resolve,
    "pypi": pypi.resolve,
}


_DEPENDENCY_CACHE: dict[tuple[str, str, str], list[PackageDependency]] = {}


def enrich_package_graph(skillbom: JsonDict) -> dict[str, int]:
    stats = {
        "package_graph_roots": 0,
        "package_graph_roots_resolved": 0,
        "package_graph_dependencies": 0,
        "package_graph_components_added": 0,
        "package_graph_relationships_added": 0,
        "package_graph_unsupported": 0,
        "package_graph_failed": 0,
    }
    components = list(skillbom.get("components") or [])
    package_components = [item for item in components if isinstance(item, dict) and parse_package_ref(item)]
    if not package_components:
        return stats

    package_by_key = {
        package_key(component): component
        for component in components
        if isinstance(component, dict) and parse_package_ref(component)
    }
    relationships = list(skillbom.get("relationship") or [])
    known_relationships = {relationship_key(rel) for rel in relationships if isinstance(rel, dict)}

    for component in package_components:
        parsed = parse_package_ref(component)
        if not parsed:
            continue
        ecosystem, name, version = parsed
        stats["package_graph_roots"] += 1
        resolver = RESOLVERS.get(ecosystem)
        if resolver is None:
            stats["package_graph_unsupported"] += 1
            continue
        deps = cached_dependencies(ecosystem, name, str(version or ""), resolver)
        if deps is None:
            stats["package_graph_failed"] += 1
            continue
        stats["package_graph_roots_resolved"] += 1
        stats["package_graph_dependencies"] += len(deps)
        source_id = str(component.get("ID") or component.get("purl") or "")
        if not source_id:
            continue
        for dep in deps:
            dep_key = dependency_key(dep)
            target = package_by_key.get(dep_key)
            if target is None:
                target = dependency_component(dep)
                components.append(target)
                package_by_key[dep_key] = target
                stats["package_graph_components_added"] += 1
            else:
                merge_component_fields(target, dependency_component(dep))
            target_id = str(target.get("ID") or target.get("purl") or "")
            if not target_id or target_id == source_id:
                continue
            rel = package_relationship(source_id, target_id, dep)
            key = relationship_key(rel)
            if key in known_relationships:
                continue
            relationships.append(rel)
            known_relationships.add(key)
            stats["package_graph_relationships_added"] += 1

    skillbom["components"] = components
    if relationships:
        skillbom["relationship"] = relationships
    return stats


def cached_dependencies(
    ecosystem: str,
    name: str,
    version: str,
    resolver: Resolver,
) -> list[PackageDependency] | None:
    key = (ecosystem, normalize_package_name(ecosystem, name), version)
    if key not in _DEPENDENCY_CACHE:
        try:
            _DEPENDENCY_CACHE[key] = resolver(name, version or None)
        except Exception:
            return None
    return _DEPENDENCY_CACHE[key]


def package_key(component: JsonDict) -> tuple[str, str]:
    parsed = parse_package_ref(component)
    if not parsed:
        return "", ""
    ecosystem, name, _version = parsed
    return ecosystem, normalize_package_name(ecosystem, name)


def dependency_key(dep: PackageDependency) -> tuple[str, str]:
    return dep.ecosystem, normalize_package_name(dep.ecosystem, dep.name)


def package_relationship(source_id: str, target_id: str, dep: PackageDependency) -> JsonDict:
    rel: JsonDict = {
        "type": "DEPENDS_ON",
        "sourceID": source_id,
        "targetID": target_id,
    }
    scope = "optional" if dep.optional else dep.scope
    if scope and scope != "unknown":
        rel["scope"] = scope
    comment = dependency_comment(dep)
    if comment:
        rel["comment"] = comment
    return rel


def dependency_comment(dep: PackageDependency) -> str:
    if dep.dependency_type in {"", "dependencies", "requires_dist", "normal"}:
        return ""
    return f"dependency_type={dep.dependency_type}"
