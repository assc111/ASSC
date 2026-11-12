from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse


JsonDict = dict[str, Any]


def slug(value: object, *, max_len: int = 120) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        return ""
    return text[:max_len].strip("-")


def properties_map(component: JsonDict) -> dict[str, str]:
    props: dict[str, str] = {}
    for item in component.get("properties") or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        value = str(item.get("value") or "").strip()
        if key and value:
            props[key] = value
    return props


def append_property(component: JsonDict, key: str, value: object | None) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    props = list(component.get("properties") or [])
    for prop in props:
        if isinstance(prop, dict) and prop.get("key") == key and prop.get("value") == text:
            return
    props.append({"key": key, "value": text})
    component["properties"] = props


def normalize_repo(value: object) -> str:
    text = str(value or "").strip()
    if text.startswith("http://") or text.startswith("https://"):
        parsed = urlparse(text)
        path = parsed.path.strip("/")
        if parsed.netloc.lower() == "github.com" and path:
            pieces = path.split("/")
            if len(pieces) >= 2:
                text = f"{pieces[0]}/{pieces[1]}"
    return slug(text.replace("_", "-"))


def normalize_name(value: object) -> str:
    return slug(str(value or "").replace("_", "-"))


def normalize_path(value: object) -> str:
    text = str(value or "").strip().strip("`'\"")
    if not text:
        return ""
    text = text.split("#", 1)[0].split("?", 1)[0]
    if text.startswith("@"):
        text = text[1:]
    if text.startswith("~/"):
        text = text[2:]
    if text.startswith("/skills/") or text.startswith("/.claude/") or text.startswith("/.github/"):
        text = text[1:]
    return PurePosixPath(text).as_posix()


def component_repo_labels(component: JsonDict) -> set[str]:
    props = properties_map(component)
    labels = {
        normalize_repo(props.get("skillmd:repo")),
        normalize_repo(props.get("skill:repo")),
        normalize_repo(component.get("source_repo")),
    }
    for ref in component.get("external_references") or []:
        if isinstance(ref, dict):
            labels.add(normalize_repo(ref.get("url")))
    return {label for label in labels if label}


def _path_name_aliases(path: str) -> set[str]:
    normalized = normalize_path(path)
    if not normalized:
        return set()
    posix = PurePosixPath(normalized)
    if posix.name.lower() == "skill.md":
        return {normalize_name(posix.parent.name)}
    if posix.suffix.lower() in {".md", ".mdc"}:
        return {normalize_name(posix.stem)}
    return {normalize_name(posix.name)}


def component_name_labels(component: JsonDict) -> set[str]:
    props = properties_map(component)
    labels = {
        normalize_name(component.get("name")),
        normalize_name(props.get("skill:name")),
        normalize_name(props.get("skillmd:name")),
    }
    for path in component_path_labels(component):
        labels.update(_path_name_aliases(path))
    return {label for label in labels if label}


def component_path_labels(component: JsonDict) -> set[str]:
    props = properties_map(component)
    labels = {
        normalize_path(props.get("skillmd:path")),
        normalize_path(props.get("skill:declared_path")),
        normalize_path(props.get("skill:path")),
    }
    labels.update(github_blob_paths(component.get("source_repo")))
    for ref in component.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        labels.update(github_blob_paths(ref.get("url")))
    return {label for label in labels if label}


def github_blob_paths(url: object) -> set[str]:
    parsed = urlparse(str(url or ""))
    if parsed.netloc.lower() != "github.com" or "/blob/" not in parsed.path:
        return set()
    _, _, rest = parsed.path.partition("/blob/")
    pieces = rest.split("/", 1)
    if len(pieces) == 2:
        return {normalize_path(pieces[1])}
    return set()


def primary_component(skillbom: JsonDict) -> JsonDict | None:
    components = skillbom.get("components") or []
    if not components:
        return None
    first = components[0]
    return first if isinstance(first, dict) else None


def parse_skill_reference(value: str) -> tuple[str, str] | None:
    prefixes = ("urn:skillbom:skill:", "urn:skillbom:skill-reference:")
    prefix = next((item for item in prefixes if value.startswith(item)), "")
    if not prefix:
        return None
    parts = value[len(prefix) :].split(":")
    if len(parts) < 2:
        return None
    return normalize_repo(parts[0]), normalize_name(parts[1])


def is_skill_reference_component(target_id: str, component: JsonDict | None = None) -> bool:
    if parse_skill_reference(target_id):
        return True
    if str(target_id or "").startswith("urn:skill:"):
        return True
    return bool(component and str(component.get("ID") or "").startswith("urn:skill:"))


def raw_skill_reference_name(value: str) -> str:
    prefixes = ("urn:skillbom:skill:", "urn:skillbom:skill-reference:")
    prefix = next((item for item in prefixes if value.startswith(item)), "")
    if not prefix:
        return ""
    body = value[len(prefix) :]
    parts = body.split(":")
    if len(parts) < 2:
        return ""
    return parts[1].strip()


WEAK_SKILL_REFERENCE_NAMES = {
    "doc",
    "docs",
    "documentation",
    "main",
    "readme",
    "reference",
    "references",
    "skill",
    "skill-md",
    "skills",
    "source",
    "sources",
    "unknown",
}


NON_SKILL_REFERENCE_SUFFIXES = {
    ".bash",
    ".cjs",
    ".css",
    ".csv",
    ".html",
    ".js",
    ".json",
    ".jsx",
    ".lock",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}


DEPENDENCY_EVIDENCE_PATTERN = re.compile(
    r"\b(?:"
    r"depend(?:s|ency|encies)?|requires?|use|uses|using|invoke|call|run|execute|"
    r"delegate|delegates|handoff|hand[- ]?off|route|routes|orchestrate|compose|chain|"
    r"coordinate|load|install|import"
    r")\b",
    re.I,
)


REFERENCE_ONLY_EVIDENCE_PATTERN = re.compile(
    r"\b(?:"
    r"see|see also|reference|references|docs?|documentation|guide|handbook|example|"
    r"index|catalog|catalogue|list of|similar|related|alternative|inspired by|credit"
    r")\b",
    re.I,
)


EXPLICIT_SKILL_DOC_PATTERN = re.compile(r"(?i)(?:^|[/\\])(?:SKILL|skill)\.md(?:$|[#?\s`'\"<>)]|\|)")

STRUCTURED_SKILL_LIST_PATTERN = re.compile(
    r"\b(?:skills?|requires?|dependencies?|depends(?:\s+on)?)\s*[:=]",
    re.I,
)

RELATED_SKILL_EVIDENCE_PATTERN = re.compile(
    r"\b(?:related[-_]skill|related[-_]skills|similar[-_]skills|enhances)\s*[:=]",
    re.I,
)

SEE_ALSO_EVIDENCE_PATTERN = re.compile(r"\bsee[-_]also\s*[:=]", re.I)

NON_SKILL_REFERENCE_NAMES = {
    "a",
    "an",
    "any",
    "bar",
    "current",
    "esta",
    "essa",
    "este",
    "every",
    "false",
    "foo",
    "given",
    "installed",
    "my",
    "none",
    "null",
    "off-by-default",
    "per",
    "prompt-accepting",
    "that",
    "the",
    "this",
    "to",
    "true",
    "user-invocable",
    "your",
}

SCHEMA_FIELD_REFERENCE_NAMES = {
    "agent",
    "allowed-tools",
    "argument-hint",
    "context",
    "description",
    "disable-model-invocation",
    "hooks",
    "input",
    "metadata",
    "model",
    "name",
    "output",
    "parameters",
    "skill",
    "skill-name",
    "skills",
    "user-invocable",
    "version",
    "schema",
    "schemas",
}

CONFIG_REFERENCE_NAME_PATTERN = re.compile(
    r"(?:api[-_]?key|secret|token|password|passwd|credential|access[-_]?key|"
    r"private[-_]?key|signer[-_]?key|wallet[-_]?address|router[-_]?key|"
    r"base[-_]?url|endpoint|webhook|dsn|connection[-_]?string|service[-_]?key|"
    r"openai[-_]?model|model|language|output[-_]?folder|user[-_]?name|"
    r"recommended[-_]?owner|provider|host|port|\.com)$",
    re.I,
)

RUNTIME_REFERENCE_NAME_PATTERN = re.compile(
    r"(?:^go\d|go1[.-]|python\d|node\d|typescript|javascript|poetry|poetry-core|"
    r"npm|pnpm|yarn|pip|cargo|rust|java|dotnet|\.net|aspnet|entityframework|"
    r"swashbuckle|opentelemetry|llama-cpp-python|pluginlib|controller-interface|"
    r"hardware-interface|wasm|rquickjs|sdk|cli|package)$",
    re.I,
)

PLACEHOLDER_SKILL_PATH_PATTERN = re.compile(
    r"(?:/path/to|path/to/|skills/<name>|<[^>]+>|xxx/SKILL\.md|yyy/SKILL\.md|"
    r"seed-skill/SKILL\.md|cluster-xxx)",
    re.I,
)

NEGATED_SKILL_REFERENCE_PATTERN = re.compile(
    r"(?:"
    r"❌\s*bad|bad\s*:\s*`?@?(?:skills?/)?|"
    r"\b(?:do\s+not|don't|avoid|never)\b.{0,120}\b(?:force[- ]?load|load|use|invoke|call)\b|"
    r"\b(?:force[- ]?loads?|burns?\s+context)\b"
    r")",
    re.I,
)

ILLUSTRATIVE_SKILL_EXAMPLE_PATTERN = re.compile(
    r"\b(?:for\s+example|example)\s*:\s*when\s+(?:building|designing|implementing|creating)\s+(?:a|an|the)?\s*`?[A-Za-z0-9_.-]+`?\s+skill\b",
    re.I,
)


def evidence_has_non_skill_file_reference(evidence: str) -> bool:
    token_pattern = re.compile(r"(?<![\w/.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.[A-Za-z0-9]+)(?![\w/.-])")
    for match in token_pattern.finditer(evidence):
        path = PurePosixPath(match.group(1).lower())
        if path.name == "skill.md":
            continue
        if path.suffix in NON_SKILL_REFERENCE_SUFFIXES:
            return True
        if path.suffix in {".md", ".mdc"}:
            return True
    return False


def is_dependency_skill_reference(target_id: str, comment: str = "", component: JsonDict | None = None) -> bool:
    parsed = parse_skill_reference(target_id)
    if not parsed and not is_skill_reference_component(target_id, component):
        return False
    normalized_names = set(component_name_labels(component or {}))
    if parsed:
        _repo, parsed_name = parsed
        normalized_names.add(parsed_name)
    if not normalized_names:
        return False
    normalized_names = {name for name in normalized_names if name not in WEAK_SKILL_REFERENCE_NAMES}
    if not normalized_names:
        return False
    normalized_name = next(iter(normalized_names))
    raw_name = raw_skill_reference_name(target_id) or str((component or {}).get("name") or "")
    raw_lower = raw_name.strip().lower()
    if raw_lower in NON_SKILL_REFERENCE_NAMES:
        return False
    if raw_lower in SCHEMA_FIELD_REFERENCE_NAMES:
        return False
    if CONFIG_REFERENCE_NAME_PATTERN.search(raw_lower):
        return False
    if RUNTIME_REFERENCE_NAME_PATTERN.search(raw_lower):
        return False
    if raw_lower:
        raw_path = PurePosixPath(raw_lower.replace("\\", "/"))
        if raw_path.suffix in NON_SKILL_REFERENCE_SUFFIXES:
            return False
        if raw_path.suffix in {".md", ".mdc"} and raw_path.name.lower() != "skill.md":
            return False
    evidence = relationship_evidence(comment)
    lower_comment = evidence.lower()
    has_explicit_skill_doc = EXPLICIT_SKILL_DOC_PATTERN.search(evidence) is not None
    if NEGATED_SKILL_REFERENCE_PATTERN.search(evidence):
        return False
    if ILLUSTRATIVE_SKILL_EXAMPLE_PATTERN.search(evidence):
        return False
    if PLACEHOLDER_SKILL_PATH_PATTERN.search(evidence):
        return False
    if re.search(r"\b(?:this|the|esta|essa|este|current|given|my|your|any|a|an)\s+skill\b", evidence, re.I):
        if not (has_explicit_skill_doc or RELATED_SKILL_EVIDENCE_PATTERN.search(evidence) or SEE_ALSO_EVIDENCE_PATTERN.search(evidence)):
            return False
    if (
        re.search(
            r"\bskills?\s*[:=].*\b(?:name|description|allowed-tools|argument-hint|"
            r"user-invocable|context|agent|model|hooks)\b",
            evidence,
            re.I,
        )
        and not RELATED_SKILL_EVIDENCE_PATTERN.search(evidence)
        and not has_explicit_skill_doc
    ):
        return False
    if not has_explicit_skill_doc and evidence_has_non_skill_file_reference(evidence):
        return False
    if RELATED_SKILL_EVIDENCE_PATTERN.search(evidence):
        return True
    if SEE_ALSO_EVIDENCE_PATTERN.search(evidence):
        return True
    if ("/references/" in lower_comment or "/docs/" in lower_comment) and not has_explicit_skill_doc:
        return False
    if has_explicit_skill_doc:
        return True
    if STRUCTURED_SKILL_LIST_PATTERN.search(evidence):
        return True
    has_dependency_evidence = DEPENDENCY_EVIDENCE_PATTERN.search(lower_comment) is not None
    has_reference_only_evidence = REFERENCE_ONLY_EVIDENCE_PATTERN.search(lower_comment) is not None
    if has_reference_only_evidence and not has_dependency_evidence:
        return True
    return True


def relationship_evidence(comment: str) -> str:
    text = str(comment or "")
    if "evidence=" not in text:
        return text
    pieces = []
    for segment in text.split("evidence=")[1:]:
        segment = segment.split("; resolved_from=", 1)[0]
        segment = segment.split("; resolved_by=", 1)[0]
        segment = segment.split(" | source=", 1)[0]
        pieces.append(segment.strip())
    return " | ".join(piece for piece in pieces if piece) or text


def parse_package_ref(component: JsonDict) -> tuple[str, str, str | None] | None:
    raw = str(component.get("purl") or component.get("ID") or "")
    if not raw.startswith("pkg:"):
        return None
    without_prefix = raw[4:]
    package_part = without_prefix.split("?", 1)[0]
    package_part = package_part.split("#", 1)[0]
    if "/" not in package_part:
        return None
    ecosystem, rest = package_part.split("/", 1)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
    name = rest
    declared_name = str(component.get("name") or "").strip()
    if ecosystem == "npm" and declared_name.startswith("@"):
        name = declared_name
    elif ecosystem == "composer" and "/" in declared_name:
        name = declared_name
    elif ecosystem == "golang" and "/" in declared_name:
        name = declared_name
    if ecosystem in {"npm", "composer", "golang"} and "/" in rest:
        name = name or rest
    return ecosystem.lower(), name, version or component.get("version")


def package_identity(component: JsonDict) -> tuple[str, str, str]:
    parsed = parse_package_ref(component)
    if parsed:
        ecosystem, name, version = parsed
        return ecosystem, normalize_package_name(ecosystem, name), str(version or "")
    return "", normalize_package_name("", component.get("name")), str(component.get("version") or "")


def normalize_package_name(ecosystem: str, name: object) -> str:
    text = str(name or "").strip().lower().replace("_", "-")
    if ecosystem == "pypi":
        text = re.sub(r"[-_.]+", "-", text)
    return text


def extract_skill_paths(comment: str, source_path: str | None = None) -> set[str]:
    source_dir = ""
    if source_path:
        source_dir = str(PurePosixPath(source_path).parent)
        if source_dir == ".":
            source_dir = ""
    pattern = re.compile(
        r"[@~]?(?:/?\.?(?:claude|github)/skills|/?skills|"
        r"(?:\.\./|\./)+[^\s`\])|]+|[\w.-]+/(?:[\w.-]+/)*)"
        r"(?:[^\s`\])|]*/)?(?:SKILL|skill)\.md(?:#[^\s`\])|]+)?"
    )
    paths: set[str] = set()
    for match in pattern.finditer(comment or ""):
        raw = normalize_path(match.group(0))
        if not raw:
            continue
        if raw.startswith("../") or raw.startswith("./"):
            raw = PurePosixPath(source_dir, raw).as_posix() if source_dir else raw
            raw = PurePosixPath(raw).as_posix()
        paths.add(raw)
    return paths


def extract_github_skill_paths(comment: str) -> set[tuple[str, str]]:
    pattern = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s]+)/blob/[^/\s]+/([^\s`'\"<>)]*?(?:SKILL|skill)\.md)", re.I)
    refs: set[tuple[str, str]] = set()
    for match in pattern.finditer(comment or ""):
        repo = normalize_repo(f"{match.group(1)}/{match.group(2)}")
        path = normalize_path(match.group(3))
        if repo and path:
            refs.add((repo, path))
    return refs
