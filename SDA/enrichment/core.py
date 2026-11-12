from __future__ import annotations

import json
import posixpath
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .index import SkillBomIndex
from .labels import (
    RELATED_SKILL_EVIDENCE_PATTERN,
    JsonDict,
    append_property,
    is_dependency_skill_reference,
    is_skill_reference_component,
    parse_skill_reference,
    primary_component,
    properties_map,
    relationship_evidence,
)
from .merge import merge_dependency_bom
from .package_graph import enrich_package_graph
from .packages import enrich_package_components


_INDEX_CACHE: dict[Path, SkillBomIndex] = {}


@dataclass
class EnrichmentReport:
    skill_dependencies_seen: int = 0
    skill_dependencies_resolved: int = 0
    skill_dependencies_self: int = 0
    skill_dependencies_missing: int = 0
    skill_dependencies_ambiguous: int = 0
    skill_dependencies_other_unresolved: int = 0
    skill_dependencies_ignored_non_dependency: int = 0
    package_components_seen: int = 0
    package_components_enriched: int = 0
    pypi_components_seen: int = 0
    pypi_components_enriched: int = 0
    package_graph_roots: int = 0
    package_graph_roots_resolved: int = 0
    package_graph_dependencies: int = 0
    package_graph_components_added: int = 0
    package_graph_relationships_added: int = 0
    package_graph_unsupported: int = 0
    package_graph_failed: int = 0
    examples: list[dict[str, Any]] = field(default_factory=list)
    unresolved_skill_dependencies: list[dict[str, Any]] = field(default_factory=list)
    missing_skill_dependencies: list[dict[str, Any]] = field(default_factory=list)

    def add_example(self, kind: str, **payload: Any) -> None:
        if len(self.examples) >= 50:
            return
        self.examples.append({"kind": kind, **payload})

    def add_unresolved_skill_dependency(
        self,
        *,
        reason: str,
        target_id: str,
        source_id: str,
        comment: str,
        root_component: JsonDict | None,
        source_component: JsonDict | None,
    ) -> None:
        root_props = properties_map(root_component or {})
        source_props = properties_map(source_component or {})
        payload = {
            "reason": reason,
            "targetID": target_id,
            "sourceID": source_id,
            "root_skill": (root_component or {}).get("name"),
            "root_repo": root_props.get("skillmd:repo") or root_props.get("skill:repo"),
            "root_path": root_props.get("skillmd:path") or root_props.get("skill:declared_path"),
            "source_skill": (source_component or {}).get("name"),
            "source_repo": source_props.get("skillmd:repo") or source_props.get("skill:repo"),
            "source_path": source_props.get("skillmd:path") or source_props.get("skill:declared_path"),
            "comment": comment,
        }
        self.unresolved_skill_dependencies.append(payload)
        if reason == "missing":
            self.missing_skill_dependencies.append(payload)

    def merge_package_stats(self, stats: dict[str, int]) -> None:
        self.package_components_seen += stats.get("package_components", 0)
        self.package_components_enriched += stats.get("package_components_enriched", 0)
        self.pypi_components_seen += stats.get("pypi_components", 0)
        self.pypi_components_enriched += stats.get("pypi_components_enriched", 0)

    def merge_package_graph_stats(self, stats: dict[str, int]) -> None:
        self.package_graph_roots += stats.get("package_graph_roots", 0)
        self.package_graph_roots_resolved += stats.get("package_graph_roots_resolved", 0)
        self.package_graph_dependencies += stats.get("package_graph_dependencies", 0)
        self.package_graph_components_added += stats.get("package_graph_components_added", 0)
        self.package_graph_relationships_added += stats.get("package_graph_relationships_added", 0)
        self.package_graph_unsupported += stats.get("package_graph_unsupported", 0)
        self.package_graph_failed += stats.get("package_graph_failed", 0)

    def merge(self, other: "EnrichmentReport") -> None:
        for field_name in REPORT_COUNTER_FIELDS:
            setattr(self, field_name, getattr(self, field_name) + getattr(other, field_name))
        for example in other.examples:
            if len(self.examples) >= 50:
                break
            self.examples.append(deepcopy(example))
        self.unresolved_skill_dependencies.extend(deepcopy(other.unresolved_skill_dependencies))
        self.missing_skill_dependencies.extend(deepcopy(other.missing_skill_dependencies))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


REPORT_COUNTER_FIELDS = (
    "skill_dependencies_seen",
    "skill_dependencies_resolved",
    "skill_dependencies_self",
    "skill_dependencies_missing",
    "skill_dependencies_ambiguous",
    "skill_dependencies_other_unresolved",
    "skill_dependencies_ignored_non_dependency",
    "package_components_seen",
    "package_components_enriched",
    "pypi_components_seen",
    "pypi_components_enriched",
    "package_graph_roots",
    "package_graph_roots_resolved",
    "package_graph_dependencies",
    "package_graph_components_added",
    "package_graph_relationships_added",
    "package_graph_unsupported",
    "package_graph_failed",
)


@dataclass(frozen=True)
class EnrichmentOptions:
    skill_db: Path | None = None
    run_env: Path | None = None
    report_path: Path | None = None
    complete_packages: bool = True


def enrich_skillbom(
    skillbom: JsonDict,
    *,
    options: EnrichmentOptions | None = None,
    index: SkillBomIndex | None = None,
    report: EnrichmentReport | None = None,
    _depth: int = 0,
    _visited: set[Path] | None = None,
) -> JsonDict:
    options = options or EnrichmentOptions()
    report = report or EnrichmentReport()
    visited = _visited or set()
    enriched = deepcopy(skillbom)

    if index is None and options.skill_db:
        index = cached_index(options.skill_db)

    if index is not None:
        enrich_skill_dependencies(
            enriched,
            index=index,
            options=options,
            report=report,
            depth=_depth,
            visited=visited,
        )

    if options.complete_packages:
        package_stats = enrich_package_components(
            enriched,
            run_env=options.run_env,
        )
        report.merge_package_stats(package_stats)
        package_graph_stats = enrich_package_graph(enriched)
        report.merge_package_graph_stats(package_graph_stats)
    normalize_relationship_scopes(enriched)
    normalize_components(enriched)
    prune_local_file_components(enriched)
    if options.report_path and _depth == 0:
        write_report(options.report_path, report)
    return enriched


def enrich_skill_dependencies(
    skillbom: JsonDict,
    *,
    index: SkillBomIndex,
    options: EnrichmentOptions,
    report: EnrichmentReport,
    depth: int,
    visited: set[Path],
) -> None:
    root_component = primary_component(skillbom)
    mark_related_skill_relationships_optional(skillbom)
    relationships = prune_non_dependency_skill_relationships(skillbom, report=report)
    components_by_id = component_lookup(skillbom)
    for rel in relationships:
        if not isinstance(rel, dict) or rel.get("type") != "DEPENDS_ON":
            continue
        target_id = str(rel.get("targetID") or "")
        target_component = components_by_id.get(target_id)
        if not is_skill_reference_component(target_id, target_component):
            continue
        report.skill_dependencies_seen += 1
        source_component = components_by_id.get(str(rel.get("sourceID") or ""))
        record, reason = index.match_skill_reference(
            target_id,
            comment=str(rel.get("comment") or ""),
            source_component=source_component,
            target_component=target_component,
        )
        if record is None:
            if reason == "missing":
                report.skill_dependencies_missing += 1
            elif reason == "ambiguous":
                report.skill_dependencies_ambiguous += 1
            else:
                report.skill_dependencies_other_unresolved += 1
            report.add_example(
                "skill-unresolved",
                targetID=target_id,
                reason=reason,
                sourceID=rel.get("sourceID"),
            )
            report.add_unresolved_skill_dependency(
                reason=reason,
                target_id=target_id,
                source_id=str(rel.get("sourceID") or ""),
                comment=str(rel.get("comment") or ""),
                root_component=root_component,
                source_component=source_component,
            )
            continue
        if is_same_skill_component(root_component, record.component):
            report.skill_dependencies_self += 1
            report.add_example(
                "skill-self",
                targetID=target_id,
                sourceID=rel.get("sourceID"),
                bom=str(record.path),
            )
            continue
        if record.path in visited:
            dependency_bom = record.load_bom()
        else:
            cached = index.enriched_dependency_cache.get(record.path)
            if cached is not None:
                dependency_bom, dependency_report = cached
                report.merge(dependency_report)
            else:
                visited.add(record.path)
                dependency_report = EnrichmentReport()
                dependency_bom = enrich_skillbom(
                    record.load_bom(),
                    options=replace(options, complete_packages=False),
                    index=index,
                    report=dependency_report,
                    _depth=depth + 1,
                    _visited=visited,
                )
                index.enriched_dependency_cache[record.path] = (dependency_bom, dependency_report)
        merge_dependency_bom(
            skillbom,
            dependency_bom,
            old_target_id=target_id,
            resolved_by=reason,
            resolved_from=target_id,
        )
        components_by_id = component_lookup(skillbom)
        report.skill_dependencies_resolved += 1
        report.add_example(
            "skill-resolved",
            targetID=target_id,
            resolved_by=reason,
            bom=str(record.path),
        )


def component_lookup(skillbom: JsonDict) -> dict[str, JsonDict]:
    return {
        str(component.get("ID")): component
        for component in skillbom.get("components") or []
        if isinstance(component, dict) and component.get("ID")
    }


def mark_related_skill_relationships_optional(skillbom: JsonDict) -> None:
    for rel in skillbom.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        if rel.get("type") != "DEPENDS_ON":
            continue
        target = rel.get("targetID")
        if not is_skill_reference_component(str(target or "")):
            continue
        evidence = relationship_evidence(str(rel.get("comment") or ""))
        if not RELATED_SKILL_EVIDENCE_PATTERN.search(evidence):
            continue
        rel["scope"] = "optional"


def normalize_relationship_scopes(skillbom: JsonDict) -> None:
    for rel in skillbom.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        if rel.pop("optional", False):
            rel["scope"] = "optional"


REDUNDANT_PROPERTY_KEYS = {
    "skill:name",
    "skill:declared_name",
    "skill:repo",
    "skill:declared_path",
    "skillmd:repo",
    "skillmd:path",
    "skillmd:html_url",
    "skillmd:content_hash",
    "skillmd:stars",
    "skillmd:source",
    "skillbom:enriched_by",
    "skillbom:version_spec",
    "skillbom:resolved_by",
    "skillbom:observed_version",
    "skillbom.local_resource.ecosystem",
    "skillbom.local_resource.source",
}


def normalize_components(skillbom: JsonDict) -> None:
    for component in skillbom.get("components") or []:
        if not isinstance(component, dict):
            continue
        promote_legacy_skill_metadata(component)
        clean_external_references(component)
        clean_component_properties(component)


def promote_legacy_skill_metadata(component: JsonDict) -> None:
    props = properties_map(component)
    repo = github_repo_from_url(props.get("skillmd:html_url")) or props.get("skillmd:repo")
    if repo:
        repo_url = repo if str(repo).startswith(("http://", "https://")) else f"https://github.com/{str(repo).strip('/')}"
        component["source_repo"] = repo_url
        add_external_reference(component, repo_url, "vcs", "source repository")
    path = props.get("skillmd:path") or github_path_from_url(props.get("skillmd:html_url"))
    if path:
        append_property(component, "skill:path", path)
    content_hash = props.get("skillmd:content_hash")
    if content_hash and not component.get("checksum"):
        component["checksum"] = [{"alg": "SHA-256", "value": content_hash}]


def github_repo_from_url(url: str | None) -> str | None:
    parsed = urlparse(str(url or ""))
    if parsed.netloc.lower() != "github.com":
        return None
    pieces = parsed.path.strip("/").split("/")
    if len(pieces) < 2:
        return None
    return f"{pieces[0]}/{pieces[1]}"


def github_path_from_url(url: str | None) -> str | None:
    parsed = urlparse(str(url or ""))
    if parsed.netloc.lower() != "github.com":
        return None
    marker = "/blob/" if "/blob/" in parsed.path else "/tree/" if "/tree/" in parsed.path else ""
    if not marker:
        return None
    _, _, rest = parsed.path.partition(marker)
    pieces = rest.split("/", 1)
    if len(pieces) != 2:
        return None
    return pieces[1]


def clean_external_references(component: JsonDict) -> None:
    refs = []
    for ref in component.get("external_references") or []:
        if not isinstance(ref, dict):
            refs.append(ref)
            continue
        url = str(ref.get("url") or "")
        comment = str(ref.get("comment") or "")
        if comment == "original skill source" and github_path_from_url(url):
            append_property(component, "skill:path", github_path_from_url(url))
            repo = github_repo_from_url(url)
            if repo:
                repo_url = f"https://github.com/{repo}"
                if not any(isinstance(item, dict) and item.get("url") == repo_url for item in refs):
                    refs.append({"url": repo_url, "type": "vcs", "comment": "source repository"})
            continue
        refs.append(ref)
    if refs:
        component["external_references"] = refs
    else:
        component.pop("external_references", None)


def add_external_reference(component: JsonDict, url: str, ref_type: str, comment: str) -> None:
    refs = list(component.get("external_references") or [])
    if any(isinstance(ref, dict) and ref.get("url") == url for ref in refs):
        component["external_references"] = refs
        return
    refs.append({"url": url, "type": ref_type, "comment": comment})
    component["external_references"] = refs


def clean_component_properties(component: JsonDict) -> None:
    properties = [
        prop
        for prop in component.get("properties") or []
        if isinstance(prop, dict) and prop.get("key") not in REDUNDANT_PROPERTY_KEYS
    ]
    if properties:
        component["properties"] = properties
    else:
        component.pop("properties", None)


def prune_local_file_components(skillbom: JsonDict) -> None:
    components = list(skillbom.get("components") or [])
    local_file_ids = {
        str(component.get("ID") or "")
        for component in components
        if isinstance(component, dict)
        and component.get("type") == "file"
        and str(component.get("ID") or "").startswith("urn:skillbom:local-resource:")
    }
    if not local_file_ids:
        return
    skillbom["relationship"] = [
        rel
        for rel in skillbom.get("relationship") or []
        if not (
            isinstance(rel, dict)
            and (str(rel.get("sourceID") or "") in local_file_ids or str(rel.get("targetID") or "") in local_file_ids)
        )
    ]
    skillbom["components"] = [
        component
        for component in components
        if not (isinstance(component, dict) and str(component.get("ID") or "") in local_file_ids)
    ]


def prune_non_dependency_skill_relationships(skillbom: JsonDict, *, report: EnrichmentReport) -> list[JsonDict]:
    components_by_id = {
        str(component.get("ID")): component
        for component in skillbom.get("components") or []
        if isinstance(component, dict) and component.get("ID")
    }
    kept: list[JsonDict] = []
    removed_targets: set[str] = set()
    for rel in skillbom.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        target_id = str(rel.get("targetID") or "")
        target_component = components_by_id.get(target_id)
        if (
            rel.get("type") == "DEPENDS_ON"
            and is_skill_reference_component(target_id, target_component)
            and not is_dependency_skill_reference(target_id, str(rel.get("comment") or ""), target_component)
        ):
            report.skill_dependencies_ignored_non_dependency += 1
            removed_targets.add(target_id)
            report.add_example(
                "skill-ignored-non-dependency",
                targetID=target_id,
                sourceID=rel.get("sourceID"),
            )
            continue
        kept.append(rel)

    if len(kept) != len(skillbom.get("relationship") or []):
        skillbom["relationship"] = kept
        remove_orphan_skill_reference_components(skillbom, removed_targets)
    return kept


def remove_orphan_skill_reference_components(skillbom: JsonDict, candidate_ids: set[str]) -> None:
    if not candidate_ids:
        return
    referenced = set()
    for rel in skillbom.get("relationship") or []:
        if not isinstance(rel, dict):
            continue
        referenced.add(str(rel.get("sourceID") or ""))
        referenced.add(str(rel.get("targetID") or ""))
    skillbom["components"] = [
        component
        for component in skillbom.get("components") or []
        if not (
            isinstance(component, dict)
            and str(component.get("ID") or "") in candidate_ids
            and str(component.get("ID") or "") not in referenced
        )
    ]


def is_same_skill_component(left: JsonDict | None, right: JsonDict | None) -> bool:
    if not left or not right:
        return False
    left_id = str(left.get("ID") or "")
    right_id = str(right.get("ID") or "")
    if left_id and right_id and left_id == right_id:
        return True
    left_hash = component_content_hash(left)
    right_hash = component_content_hash(right)
    return bool(left_hash and right_hash and left_hash == right_hash)


def component_content_hash(component: JsonDict) -> str:
    props = properties_map(component)
    if props.get("skillmd:content_hash"):
        return props["skillmd:content_hash"]
    for checksum in component.get("checksum") or []:
        if isinstance(checksum, dict) and checksum.get("value"):
            return str(checksum["value"])
    return ""


def enrich_directory(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    skill_db: str | Path,
    run_env: str | Path | None = None,
    report_path: str | Path | None = None,
) -> EnrichmentReport:
    source = Path(input_dir).expanduser().resolve()
    target = Path(output_dir).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    options = EnrichmentOptions(
        skill_db=Path(skill_db).expanduser().resolve(),
        run_env=Path(run_env).expanduser().resolve() if run_env else None,
    )
    index = cached_index(options.skill_db)
    report = EnrichmentReport()
    for path in sorted(source.glob("*.skillbom.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        enriched = enrich_skillbom(
            data,
            options=options,
            index=index,
            report=report,
        )
        (target / path.name).write_text(
            json.dumps(enriched, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if report_path:
        write_report(Path(report_path), report)
    return report


def write_report(path: str | Path, report: EnrichmentReport) -> None:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def cached_index(path: str | Path) -> SkillBomIndex:
    resolved = Path(path).expanduser().resolve()
    existing = _INDEX_CACHE.get(resolved)
    if existing is not None:
        return existing
    index = SkillBomIndex.from_path(resolved)
    _INDEX_CACHE[resolved] = index
    return index
