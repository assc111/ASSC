from __future__ import annotations

from copy import deepcopy
from typing import Any

from .labels import JsonDict, component_repo_labels, normalize_name, package_identity, primary_component


def merge_dependency_bom(
    root: JsonDict,
    dependency: JsonDict,
    *,
    old_target_id: str | None = None,
    resolved_by: str | None = None,
    resolved_from: str | None = None,
) -> str | None:
    dep_primary = primary_component(dependency)
    if not dep_primary:
        return None
    new_target_id = str(dep_primary.get("ID") or "")
    if not new_target_id:
        return None

    id_map, root_id_map = merge_components(root, dependency, canonical_source_ids={new_target_id})
    final_target_id = id_map.get(new_target_id, new_target_id)
    if old_target_id and old_target_id != final_target_id:
        rewrite_relationship_target(root, old_target_id, final_target_id, resolved_by, resolved_from)
    if root_id_map:
        rewrite_root_references(root, root_id_map)
    root_primary = primary_component(root)
    blocked_sources = {str(root_primary.get("ID") or "")} if root_primary else set()
    merge_relationships(root, dependency, blocked_source_ids=blocked_sources, id_map=id_map)
    merge_annotations(root, dependency, id_map=id_map)
    remove_unreferenced_component(root, old_target_id)
    return final_target_id


def merge_components(
    root: JsonDict,
    dependency: JsonDict,
    *,
    canonical_source_ids: set[str] | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    canonical_source_ids = canonical_source_ids or set()
    components = list(root.get("components") or [])
    known = {component_key(item) for item in components if isinstance(item, dict)}
    by_key = {component_key(item): item for item in components if isinstance(item, dict)}
    id_map: dict[str, str] = {}
    root_id_map: dict[str, str] = {}
    for component in dependency.get("components") or []:
        if not isinstance(component, dict):
            continue
        key = component_key(component)
        source_id = str(component.get("ID") or "")
        if key in known:
            target = by_key[key]
            if source_id in canonical_source_ids:
                replacement = deepcopy(component)
                merge_component_fields(replacement, target)
                replace_component(components, target, replacement)
                by_key[key] = replacement
                target_id = str(replacement.get("ID") or "")
                old_target_id = str(target.get("ID") or "")
                if source_id and target_id:
                    id_map[source_id] = target_id
                if old_target_id and target_id and old_target_id != target_id:
                    root_id_map[old_target_id] = target_id
            else:
                merge_component_fields(target, component)
                if source_id and target.get("ID"):
                    id_map[source_id] = str(target["ID"])
            continue
        appended = deepcopy(component)
        components.append(appended)
        known.add(key)
        by_key[key] = appended
        if source_id:
            id_map[source_id] = source_id
    root["components"] = components
    return id_map, root_id_map


def replace_component(components: list[Any], target: JsonDict, replacement: JsonDict) -> None:
    for index, component in enumerate(components):
        if component is target:
            components[index] = replacement
            return


def merge_component_fields(target: JsonDict, source: JsonDict) -> None:
    for key, value in source.items():
        if key in {"properties", "external_references", "licenses", "checksum"}:
            merge_list_field(target, source, key)
        elif key == "version":
            merge_version_field(target, value)
        elif is_empty_value(target.get(key)) and not is_empty_value(value):
            target[key] = deepcopy(value)


def merge_version_field(target: JsonDict, value: Any) -> None:
    if is_empty_value(value):
        return
    existing = target.get("version")
    if is_empty_value(existing):
        target["version"] = deepcopy(value)
        return


def is_empty_value(value: Any) -> bool:
    return value is None or value == "" or value == "NOASSERTION"


def merge_list_field(target: JsonDict, source: JsonDict, key: str) -> None:
    existing = list(target.get(key) or [])
    seen = {stable_json(item) for item in existing}
    for item in source.get(key) or []:
        marker = stable_json(item)
        if marker not in seen:
            existing.append(deepcopy(item))
            seen.add(marker)
    if existing:
        target[key] = existing


def merge_relationships(
    root: JsonDict,
    dependency: JsonDict,
    *,
    blocked_source_ids: set[str] | None = None,
    id_map: dict[str, str] | None = None,
) -> None:
    blocked_source_ids = blocked_source_ids or set()
    id_map = id_map or {}
    relationships = list(root.get("relationship") or [])
    known = {relationship_key(item) for item in relationships if isinstance(item, dict)}
    for rel in dependency.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        rewritten = deepcopy(rel)
        if rewritten.get("sourceID") in id_map:
            rewritten["sourceID"] = id_map[str(rewritten.get("sourceID") or "")]
        if rewritten.get("targetID") in id_map:
            rewritten["targetID"] = id_map[str(rewritten.get("targetID") or "")]
        if str(rewritten.get("sourceID") or "") in blocked_source_ids:
            continue
        key = relationship_key(rewritten)
        if key in known:
            continue
        relationships.append(rewritten)
        known.add(key)
    if relationships:
        root["relationship"] = relationships


def merge_annotations(root: JsonDict, dependency: JsonDict, *, id_map: dict[str, str] | None = None) -> None:
    id_map = id_map or {}
    annotations = list(root.get("annotations") or [])
    known = {annotation_key(item) for item in annotations if isinstance(item, dict)}
    for annotation in dependency.get("annotations") or []:
        if not isinstance(annotation, dict):
            continue
        rewritten = deepcopy(annotation)
        subjects = []
        for subject in rewritten.get("subjects") or []:
            subjects.append(id_map.get(str(subject), subject))
        if subjects:
            rewritten["subjects"] = subjects
        key = annotation_key(rewritten)
        if key in known:
            continue
        annotations.append(rewritten)
        known.add(key)
    if annotations:
        root["annotations"] = annotations


def rewrite_relationship_target(
    root: JsonDict,
    old_target_id: str,
    new_target_id: str,
    resolved_by: str | None,
    resolved_from: str | None,
) -> None:
    for rel in root.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        if rel.get("targetID") != old_target_id:
            continue
        rel["targetID"] = new_target_id
        notes = [str(rel.get("comment") or "").strip()]
        if resolved_from:
            notes.append(f"resolved_from={resolved_from}")
        if resolved_by:
            notes.append(f"resolved_by={resolved_by}")
        rel["comment"] = "; ".join(note for note in notes if note)


def rewrite_root_references(root: JsonDict, id_map: dict[str, str]) -> None:
    for rel in root.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        source_id = str(rel.get("sourceID") or "")
        target_id = str(rel.get("targetID") or "")
        if source_id in id_map:
            rel["sourceID"] = id_map[source_id]
        if target_id in id_map:
            rel["targetID"] = id_map[target_id]

    for annotation in root.get("annotations") or []:
        if not isinstance(annotation, dict):
            continue
        subjects = [id_map.get(str(subject), subject) for subject in annotation.get("subjects") or []]
        if subjects:
            annotation["subjects"] = subjects


def remove_unreferenced_component(root: JsonDict, component_id: str | None) -> None:
    if not component_id:
        return
    for rel in root.get("relationship") or []:
        if isinstance(rel, dict) and component_id in {rel.get("sourceID"), rel.get("targetID")}:
            return
    root["components"] = [
        item for item in root.get("components") or [] if not isinstance(item, dict) or item.get("ID") != component_id
    ]


def merge_package_component(target: JsonDict, enriched: JsonDict, *, source: str) -> None:
    merge_component_fields(target, enriched)


def component_key(component: JsonDict) -> tuple[str, str, str]:
    if component.get("purl") or str(component.get("ID") or "").startswith("pkg:"):
        ecosystem, name, _version = package_identity(component)
        return "package", ecosystem, name
    repo_labels = sorted(component_repo_labels(component))
    name = normalize_name(component.get("name"))
    if repo_labels and name:
        return "repo-name", repo_labels[0], name
    if component.get("ID"):
        return "id", str(component.get("ID")), ""
    return "name", str(component.get("type") or ""), str(component.get("name") or "")


def relationship_key(rel: JsonDict) -> tuple[str, str, str]:
    return str(rel.get("type") or ""), str(rel.get("sourceID") or ""), str(rel.get("targetID") or "")


def annotation_key(annotation: JsonDict) -> tuple[str, str]:
    return str(annotation.get("ID") or ""), str(annotation.get("text") or "")


def stable_json(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, ensure_ascii=False)
