from __future__ import annotations

import json
import re
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .labels import (
    JsonDict,
    WEAK_SKILL_REFERENCE_NAMES,
    component_name_labels,
    component_path_labels,
    component_repo_labels,
    extract_github_skill_paths,
    extract_skill_paths,
    normalize_name,
    normalize_path,
    normalize_repo,
    parse_skill_reference,
    primary_component,
    properties_map,
    relationship_evidence,
)


@dataclass(frozen=True)
class SkillBomRecord:
    path: Path
    bom: JsonDict | None
    component: JsonDict
    name_label: str
    name_labels: frozenset[str]
    repo_labels: frozenset[str]
    path_labels: frozenset[str]
    content_hash: str
    stars: int

    def load_bom(self) -> JsonDict:
        if self.bom is not None:
            return self.bom
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}


class SkillBomIndex:
    def __init__(self, records: list[SkillBomRecord]) -> None:
        self.records = records
        self.by_global_name: dict[str, list[SkillBomRecord]] = {}
        self.by_name_token: dict[str, list[SkillBomRecord]] = {}
        self.enriched_dependency_cache: dict[Path, tuple[JsonDict, Any]] = {}
        self._prefix_match_cache: dict[str, list[SkillBomRecord]] = {}
        self._relaxed_match_cache: dict[str, list[SkillBomRecord]] = {}
        self._sorted_global_names: list[str] | None = None
        for record in records:
            for name in record.name_labels:
                self.by_global_name.setdefault(name, []).append(record)
                for token in name_index_tokens(name):
                    self.by_name_token.setdefault(token, []).append(record)

    @classmethod
    def from_path(cls, path: str | Path) -> "SkillBomIndex":
        root = Path(path).expanduser().resolve()
        files = [root] if root.is_file() else root.glob("*.skillbom.json")
        records: list[SkillBomRecord] = []
        for bom_path in files:
            try:
                data = json.loads(bom_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            component = primary_component(data)
            if not component:
                continue
            props = properties_map(component)
            content_hash = props.get("skillmd:content_hash") or checksum_value(component)
            records.append(
                SkillBomRecord(
                    path=bom_path,
                    bom=data if root.is_file() else None,
                    component=component,
                    name_label=normalize_name(component.get("name")),
                    name_labels=frozenset(component_name_labels(component)),
                    repo_labels=frozenset(component_repo_labels(component)),
                    path_labels=frozenset(component_path_labels(component)),
                    content_hash=content_hash,
                    stars=parse_int(props.get("skillmd:stars")),
                )
            )
        return cls(records)

    def match_skill_reference(
        self,
        target_id: str,
        *,
        comment: str = "",
        source_component: JsonDict | None = None,
        target_component: JsonDict | None = None,
    ) -> tuple[SkillBomRecord | None, str]:
        target_id = str(target_id or "")
        parsed = parse_skill_reference(target_id)
        primary_target_names = target_component_name_labels(target_component or {})
        target_names = set(primary_target_names)
        if not primary_target_names:
            target_names.update(component_name_labels(target_component or {}))
            target_names.update(target_id_name_labels(target_id))
        target_paths = set(component_path_labels(target_component or {}))
        target_repos = set(component_repo_labels(target_component or {}))
        if parsed:
            repo_label, name_label = parsed
            target_repos.add(repo_label)
            if not primary_target_names:
                target_names.add(name_label)
        source_paths = component_path_labels(source_component or {})
        source_path = next(iter(source_paths), "")
        source_repos = set(component_repo_labels(source_component or {}))
        target_paths = expanded_paths(target_paths, source_path)

        evidence_repos: set[str] = set()
        evidence_paths: set[str] = set()
        for evidence_repo, evidence_path in extract_github_skill_paths(comment):
            evidence_repos.add(normalize_repo(evidence_repo))
            evidence_paths.add(normalize_path(evidence_path))
        for evidence_path in extract_skill_paths(comment, source_path):
            for normalized in candidate_paths(evidence_path, source_path):
                evidence_paths.add(normalized)
        evidence_paths = expanded_paths(evidence_paths, source_path)
        target_paths.update(evidence_paths)
        target_repos.update(evidence_repos)
        if evidence_paths and not evidence_repos:
            target_repos.update(source_repos)

        if not primary_target_names:
            target_names.update(comment_skill_name_labels(comment, source_path))
        if not target_names:
            return None, "not-skill"

        candidates, match_kind = self.name_candidates(target_names, target_repos=target_repos)
        if not candidates or match_kind is None:
            return None, "missing"
        if len(candidates) == 1:
            return candidates[0], match_kind

        return best_name_match(
            candidates,
            target_repos=target_repos,
            target_paths=target_paths,
            match_kind=match_kind,
        )

    def name_candidates(
        self,
        target_names: set[str],
        *,
        target_repos: set[str] | frozenset[str],
    ) -> tuple[list[SkillBomRecord], str | None]:
        exact_candidates = unique_records(
            [
                record
                for name in target_names
                for record in self.by_global_name.get(name, [])
            ]
        )
        exact_candidates = filter_repo_compatible(exact_candidates, target_repos)
        if exact_candidates:
            return exact_candidates, "name"

        prefix_candidates = unique_records(
            [
                record
                for name in target_names
                for record in self.prefix_name_candidates(name)
            ]
        )
        prefix_candidates = filter_repo_compatible(prefix_candidates, target_repos)
        if prefix_candidates:
            return prefix_candidates, "prefix-name"

        relaxed_candidates = unique_records(
            [
                record
                for name in target_names
                for record in self.relaxed_name_candidates(name)
            ]
        )
        relaxed_candidates = filter_repo_compatible(relaxed_candidates, target_repos)
        if relaxed_candidates:
            return relaxed_candidates, "relaxed-name"

        return [], None

    def prefix_name_candidates(self, target_name: str) -> list[SkillBomRecord]:
        normalized = normalize_name(target_name)
        if len(normalized) < 2 or normalized in WEAK_SKILL_REFERENCE_NAMES:
            return []
        cached = self._prefix_match_cache.get(normalized)
        if cached is not None:
            return cached
        if self._sorted_global_names is None:
            self._sorted_global_names = sorted(self.by_global_name)
        sorted_names = self._sorted_global_names
        start = bisect_left(sorted_names, normalized)
        candidates: list[SkillBomRecord] = []
        for indexed_name in sorted_names[start:]:
            if not indexed_name.startswith(normalized):
                break
            candidates.extend(self.by_global_name[indexed_name])
        self._prefix_match_cache[normalized] = unique_records(candidates)
        return self._prefix_match_cache[normalized]

    def relaxed_name_candidates(self, target_name: str) -> list[SkillBomRecord]:
        normalized = normalize_name(target_name)
        if len(normalized) < 4 or normalized in WEAK_SKILL_REFERENCE_NAMES:
            return []
        cached = self._relaxed_match_cache.get(normalized)
        if cached is not None:
            return cached
        tokens = name_index_tokens(normalized)
        if not tokens:
            self._relaxed_match_cache[normalized] = []
            return []
        rarest_token = min(tokens, key=lambda token: len(self.by_name_token.get(token, [])))
        pool = unique_records(self.by_name_token.get(rarest_token, []))
        candidates = [
            record
            for record in pool
            if any(relaxed_name_match(normalized, indexed_name) for indexed_name in record.name_labels)
        ]
        self._relaxed_match_cache[normalized] = unique_records(candidates)
        return self._relaxed_match_cache[normalized]


def filter_repo_compatible(candidates: list[SkillBomRecord], target_repos: set[str]) -> list[SkillBomRecord]:
    return [record for record in candidates if repos_compatible(target_repos, record.repo_labels)]


def expanded_paths(paths: set[str] | frozenset[str], source_path: str = "") -> set[str]:
    expanded: set[str] = set()
    for path in paths:
        expanded.update(candidate_paths(path, source_path))
    return {path for path in expanded if path}


def repos_compatible(left: set[str] | frozenset[str], right: set[str] | frozenset[str]) -> bool:
    if not left or not right:
        return True
    return bool(left & right)


def target_id_name_labels(target_id: str) -> set[str]:
    parsed = parse_skill_reference(target_id)
    if parsed:
        _repo, name = parsed
        return {name} if usable_skill_name_label(name) else set()
    prefix = "urn:skill:"
    if not str(target_id or "").startswith(prefix):
        return set()
    body = str(target_id)[len(prefix) :].strip()
    if not body:
        return set()
    name = body.rsplit(":", 1)[-1]
    return {normalize_name(name)} if usable_skill_name_label(name) else set()


def target_component_name_labels(component: JsonDict) -> set[str]:
    name = normalize_name(component.get("name") if component else "")
    if not usable_skill_name_label(name):
        return set()
    return {name}


def comment_skill_name_labels(comment: str, source_path: str = "") -> set[str]:
    labels: set[str] = set()
    evidence = relationship_evidence(comment)
    for path in extract_skill_paths(evidence, source_path):
        labels.update(path_name_labels(path))
    for _repo, path in extract_github_skill_paths(evidence):
        labels.update(path_name_labels(path))
    for match in re.finditer(r"\bskill:([A-Za-z0-9][A-Za-z0-9_.-]{1,120})", evidence):
        labels.add(normalize_name(match.group(1)))
    for match in re.finditer(
        r"\b(?:next[-_ ]skill|related[-_ ]skills?|similar[-_ ]skills?|requires?|dependencies?|depends(?:\s+on)?)\s*[:=]\s*([^;\n|]+)",
        evidence,
        re.I,
    ):
        for token in re.split(r"[,，]\s*|\s+and\s+", match.group(1)):
            labels.update(inline_skill_name_labels(token))
    return {label for label in labels if usable_skill_name_label(label)}


def inline_skill_name_labels(value: str) -> set[str]:
    text = str(value or "").strip()
    if not text:
        return set()
    text = re.sub(r"\[[^\]]+\]\(([^)]+)\)", r"\1", text)
    text = text.strip("`'\" [](){}")
    if not text:
        return set()
    if "/" in text or text.lower().endswith((".md", ".mdc")):
        return path_name_labels(text)
    return {normalize_name(text)}


def path_name_labels(path: str) -> set[str]:
    normalized = normalize_path(path)
    if not normalized:
        return set()
    posix = PurePosixPath(normalized)
    if posix.name.lower() == "skill.md":
        return name_variants(posix.parent.name)
    if posix.suffix.lower() in {".md", ".mdc"}:
        return name_variants(posix.stem)
    return name_variants(posix.name)


def usable_skill_name_label(label: str) -> bool:
    normalized = normalize_name(label)
    if len(normalized) < 2:
        return False
    if normalized in WEAK_SKILL_REFERENCE_NAMES:
        return False
    return True


def name_variants(value: object) -> set[str]:
    normalized = normalize_name(value)
    if not normalized:
        return set()
    variants = {normalized}
    stripped = re.sub(r"^\d+-", "", normalized)
    if stripped:
        variants.add(stripped)
    for suffix in ("-skill", "-skills"):
        if normalized.endswith(suffix):
            variants.add(normalized[: -len(suffix)])
        if stripped.endswith(suffix):
            variants.add(stripped[: -len(suffix)])
    return {variant for variant in variants if usable_skill_name_label(variant)}


def relaxed_name_match(target_name: str, indexed_name: str) -> bool:
    target_variants = name_variants(target_name)
    indexed_variants = name_variants(indexed_name)
    for target in target_variants:
        for indexed in indexed_variants:
            if target == indexed:
                return True
            if len(indexed) >= 4 and target.startswith(indexed):
                return True
            if len(target) >= 4 and indexed.startswith(target):
                return True
            if token_subset_match(target, indexed):
                return True
    return False


def token_subset_match(left: str, right: str) -> bool:
    left_tokens = meaningful_name_tokens(left)
    right_tokens = meaningful_name_tokens(right)
    if len(left_tokens) < 2 or len(right_tokens) < 2:
        return False
    shorter, longer = (left_tokens, right_tokens) if len(left_tokens) <= len(right_tokens) else (right_tokens, left_tokens)
    return shorter <= longer


def meaningful_name_tokens(value: str) -> set[str]:
    tokens = {token for token in normalize_name(value).split("-") if token and not token.isdigit()}
    return {token for token in tokens if token not in {"skill", "skills", "agent", "code", "coding", "tool", "tools"}}


def name_index_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for variant in name_variants(value):
        tokens.update(meaningful_name_tokens(variant))
    return tokens


def unique_records(candidates: list[SkillBomRecord]) -> list[SkillBomRecord]:
    unique: dict[Path, SkillBomRecord] = {}
    for item in candidates:
        unique.setdefault(item.path, item)
    return list(unique.values())


def best_name_match(
    candidates: list[SkillBomRecord],
    *,
    target_repos: set[str],
    target_paths: set[str],
    match_kind: str = "name",
) -> tuple[SkillBomRecord | None, str]:
    scored = [
        (
            name_match_priority(record, target_repos=target_repos, target_paths=target_paths),
            record,
        )
        for record in candidates
    ]
    scored.sort(key=lambda item: (-item[0], -item[1].stars, str(item[1].path)))
    priority, record = scored[0]
    if match_kind == "prefix-name":
        reason_prefix = "prefix-name"
    elif match_kind == "relaxed-name":
        reason_prefix = "relaxed-name"
    else:
        reason_prefix = "name"
    if priority == 3:
        return record, f"{reason_prefix}-repo-path"
    if priority == 2:
        return record, f"{reason_prefix}-repo"
    if priority == 1:
        return record, f"{reason_prefix}-path"
    return record, f"{reason_prefix}-stars"


def name_match_priority(
    record: SkillBomRecord,
    *,
    target_repos: set[str],
    target_paths: set[str],
) -> int:
    repo_matches = bool(record.repo_labels & target_repos)
    path_matches = bool(record.path_labels & target_paths)
    if repo_matches and path_matches:
        return 3
    if repo_matches:
        return 2
    if path_matches:
        return 1
    return 0


def checksum_value(component: JsonDict) -> str:
    for checksum in component.get("checksum") or []:
        if isinstance(checksum, dict) and checksum.get("value"):
            return str(checksum["value"])
    return ""


def parse_int(value: object) -> int:
    try:
        return int(str(value or "").strip())
    except ValueError:
        return 0


def candidate_paths(path: str, source_path: str = "") -> set[str]:
    normalized = normalize_path(path)
    if not normalized:
        return set()
    candidates = {normalized}
    if normalized.startswith("../") or normalized.startswith("./"):
        source_dir = PurePosixPath(source_path).parent if source_path else PurePosixPath("")
        candidates.add(PurePosixPath(source_dir, normalized).as_posix())
    if normalized.startswith(".claude/") or normalized.startswith(".github/") or normalized.startswith("skills/"):
        candidates.add(normalized)
    return {normalize_path(item) for item in candidates if item}
