#!/usr/bin/env python3
"""
Build a middleware-format SBOM for agent skills.

The scanner logic stays in scan_skill_dep.py. This module turns those findings
into SIT's middleware.Component, middleware.Relationship, and
middleware.Annotation objects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid4, uuid5
from packageurl import PackageURL


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
SIT_ROOT = REPO_ROOT / "SIT"
if str(SIT_ROOT) not in sys.path:
    sys.path.insert(0, str(SIT_ROOT))

from SIT.output import middleware  # noqa: E402

try:  # noqa: E402
    from . import scan_skill_dep
    from .skillbom_conversion import Middleware2SkillBOM
except ImportError:  # pragma: no cover - supports direct script execution
    import scan_skill_dep  # type: ignore
    from skillbom_conversion import Middleware2SkillBOM  # type: ignore


LICENSE_LIST_VERSION = "3.23"
DEFAULT_NAMESPACE = "https://github.com/assc111/ASSC"
DEFAULT_INPUT = THIS_DIR / "input"
MAX_COMMENT_CHARS = 900
MAX_DESCRIPTION_CHARS = 1000
MAX_PROPERTY_VALUE_CHARS = 900

SKILL_MARKDOWN_MARKERS = {"skill.md"}
SKILL_MARKDOWN_SUFFIXES = ("_skill.md",)

PURL_TYPES = {
    "cargo": "cargo",
    "conda": "conda",
    "docker": "docker",
    "dotnet": "nuget",
    "go": "golang",
    "homebrew": "brew",
    "npm": "npm",
    "php": "composer",
    "pypi": "pypi",
    "ruby": "gem",
}


@dataclass(frozen=True)
class SkillInput:
    root: Path
    source: Path
    is_file: bool


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def stable_id(kind: str, *parts: object) -> str:
    raw = "\0".join(str(part) for part in parts)
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]
    return f"urn:skillbom:{kind}:{digest}"


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        return "unknown"
    return text[:max_len].strip("-") or "unknown"


def readable_id(kind: str, *parts: object) -> str:
    compact = ":".join(slugify(part) for part in parts if str(part or "").strip())
    if not compact:
        compact = "unknown"
    return f"urn:skillbom:{kind}:{compact}"


def uuid_urn(kind: str, *parts: object) -> str:
    raw = "\0".join(str(part or "") for part in parts)
    return f"urn:{kind}:{uuid5(NAMESPACE_URL, raw)}"


def looks_like_generated_skill_input(path: str) -> bool:
    return bool(re.fullmatch(r"\d+_.+_(?:SKILL|skill)\.md", Path(path).name))


def github_repo_url(repo: str | None) -> str | None:
    repo = str(repo or "").strip().strip("/")
    if not repo:
        return None
    if repo.startswith(("http://", "https://")):
        return repo
    return f"https://github.com/{repo}"


def source_repo_for_skill(repo: str | None, declared_path: str, rel_source: str) -> str | None:
    return github_repo_url(repo)


def source_path_property(declared_path: str, rel_source: str) -> str | None:
    if not declared_path or declared_path == rel_source:
        return None
    if looks_like_generated_skill_input(declared_path):
        return None
    return declared_path


def safe_property_value(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:MAX_PROPERTY_VALUE_CHARS]


def make_property(key: str, value: object | None) -> middleware.Extension | None:
    cleaned = safe_property_value(value)
    if cleaned is None:
        return None
    return middleware.Extension(key=key, value=cleaned)


def truncate(value: str, limit: int) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", text, re.S)
    if not match:
        return {}

    metadata: dict[str, str] = {}
    parent_key = ""
    for line in match.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("-"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip()
        if line[:1].isspace() and parent_key:
            key = f"{parent_key}.{key}"
        elif not line[:1].isspace():
            parent_key = key if not value.strip() else ""
        value = strip_quotes(value.strip())
        if key and value:
            metadata[key] = value
    return metadata


def metadata_get(metadata: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value:
            return value
    return None


def split_metadata_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    items = [
        strip_quotes(piece.strip())
        for piece in re.split(r"\s*,\s*|\s*;\s*", value)
        if piece.strip()
    ]
    return items or None


def individual_from_metadata(value: str | None) -> list[middleware.Individual] | None:
    if not value:
        return None
    if value.startswith(("http://", "https://")):
        return [middleware.Individual(type="person", url=[value])]
    return [middleware.Individual(type="person", name=value)]


def skill_name_from_path(path: Path) -> str:
    name = path.stem
    name = re.sub(r"^\d+_", "", name)
    name = re.sub(r"_(?:SKILL|skill)$", "", name)
    return name or path.name


def repo_from_skillmd_filename(path: Path) -> str:
    stem = re.sub(r"^\d+_", "", path.stem)
    stem = re.sub(r"_(?:SKILL|skill)$", "", stem)
    owner, sep, repo = stem.partition("_")
    if sep and owner and repo:
        return f"{owner}/{repo}"
    return ""


def normalize_skill_ref(value: str) -> str:
    ref = value.strip().strip("`'\"")
    ref = ref.replace("\\", "/")
    ref = ref.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    lower = ref.lower()
    if lower.endswith("/skill.md"):
        ref = ref[: -len("/skill.md")]
    elif lower in {"skill.md", "skills.md"}:
        ref = lower
    elif lower.endswith((".md", ".mdc")):
        ref = Path(ref).stem
    if "/" in ref:
        ref = ref.rsplit("/", 1)[-1]
    return slugify(ref, max_len=120)


def parse_declared_license(value: str | None) -> list[middleware.License] | None:
    if not value:
        return None
    license_value = value.strip()
    if not license_value:
        return None
    if re.fullmatch(r"[A-Za-z0-9.+-]+", license_value):
        return [middleware.License(type="declared", spdxID=license_value)]
    return [middleware.License(type="declared", name=license_value)]


def resolve_input_path(path: Path) -> Path:
    path = path.expanduser()
    if not path.exists() or not path.is_file():
        return path
    if path.suffix.lower() in scan_skill_dep.TEXT_EXTENSIONS:
        return path

    text = path.read_text(encoding="utf-8", errors="replace").strip()
    match = re.fullmatch(r"path\s*=\s*(.+)", text)
    if not match:
        return path
    target = Path(strip_quotes(match.group(1)))
    if not target.is_absolute():
        target = path.parent / target
    return target.expanduser()


def is_skill_markdown_file(path: Path) -> bool:
    if not path.is_file():
        return False
    name = path.name.lower()
    return name in SKILL_MARKDOWN_MARKERS or name.endswith(SKILL_MARKDOWN_SUFFIXES)


def is_skill_marker_file(path: Path) -> bool:
    return path.name.lower() in SKILL_MARKDOWN_MARKERS


def iter_skill_markdown_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if is_skill_markdown_file(path):
            yield path


def collect_skill_inputs(target: Path, limit: int | None = None) -> list[SkillInput]:
    target = resolve_input_path(target).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Input path does not exist: {target}")

    inputs: list[SkillInput] = []
    if target.is_file():
        if not is_skill_markdown_file(target):
            print(f"[WARNING] The provided file seems not to be skill.md: {target}")
        inputs.append(SkillInput(root=target.parent, source=target, is_file=True))
    else:
        for skill_file in iter_skill_markdown_files(target):
            if is_skill_marker_file(skill_file):
                inputs.append(SkillInput(root=target, source=skill_file.parent, is_file=False))
            else:
                inputs.append(SkillInput(root=target, source=skill_file, is_file=True))

    if limit is not None:
        inputs = inputs[:limit]
    return inputs


def scan_file_unit(root: Path, path: Path) -> list[scan_skill_dep.Finding]:
    findings: list[scan_skill_dep.Finding] = []
    if path.name == "package.json":
        scan_skill_dep.scan_package_json(root, path, path, findings)
    elif path.name == "requirements.txt":
        scan_skill_dep.scan_requirements(root, path, path, findings)
    elif path.name == "go.mod":
        scan_skill_dep.scan_go_mod(root, path, path, findings)
    elif path.suffix.lower() == ".toml":
        scan_skill_dep.scan_toml_manifest(root, path, path, findings)
    scan_skill_dep.scan_text_file(root, path, path, findings)
    return findings


def scan_skill_input(skill_input: SkillInput) -> list[scan_skill_dep.Finding]:
    if skill_input.is_file:
        return scan_file_unit(skill_input.root, skill_input.source)
    return scan_skill_dep.scan_skill(skill_input.root, skill_input.source)


def read_skill_text(skill_input: SkillInput) -> str:
    if skill_input.is_file:
        return scan_skill_dep.read_text(skill_input.source) or ""
    for marker in sorted(scan_skill_dep.SKILL_MARKERS):
        marker_path = skill_input.source / marker
        if marker_path.exists():
            return scan_skill_dep.read_text(marker_path) or ""
    return ""


def relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def make_skill_component(skill_input: SkillInput) -> middleware.Component:
    text = read_skill_text(skill_input)
    metadata = parse_frontmatter(text)
    name = metadata.get("name") or skill_name_from_path(skill_input.source)
    rel_source = relative_path(skill_input.root, skill_input.source)
    repo = metadata.get("repo") or repo_from_skillmd_filename(skill_input.source)
    declared_path = metadata.get("path") or rel_source
    content_hash = sha256_text(text) if text else sha256_text(rel_source)
    version = metadata_get(metadata, "version", "metadata.version") or "NOASSERTION"
    author = metadata_get(metadata, "author", "metadata.author")
    keywords = split_metadata_list(metadata_get(metadata, "keywords", "metadata.keywords", "triggers", "metadata.triggers"))
    properties = [
        make_property("skill:path", source_path_property(declared_path, rel_source)),
        make_property("skill:metadata_type", metadata_get(metadata, "type", "metadata.type")),
        make_property("skill:metadata_family", metadata_get(metadata, "family", "metadata.family")),
        make_property("skill:metadata_domain", metadata_get(metadata, "domain", "metadata.domain")),
        make_property("skill:metadata_scope", metadata_get(metadata, "scope", "metadata.scope")),
        make_property("skill:metadata_role", metadata_get(metadata, "role", "metadata.role")),
        make_property("skill:compatibility", metadata_get(metadata, "compatibility", "metadata.compatibility")),
    ]
    allowed_tools = metadata.get("allowed-tools")
    if allowed_tools:
        properties.append(make_property("skill:allowed_tools", allowed_tools))
    external_references = []
    if author and author.startswith(("http://", "https://")):
        external_references.append(middleware.ExternalReference(url=author, type="other", comment="skill author metadata"))

    return middleware.Component(
        type="application",
        name=name,
        version=version,
        ID=uuid_urn("skill", repo or rel_source, declared_path, name, content_hash),
        licenses=parse_declared_license(metadata.get("license")),
        checksum=[middleware.Hash(alg="SHA-256", value=content_hash)] if text else None,
        originator=individual_from_metadata(author),
        source_repo=source_repo_for_skill(repo, declared_path, rel_source),
        external_references=external_references or None,
        description=truncate(metadata.get("description", ""), MAX_DESCRIPTION_CHARS) or None,
        tags=keywords,
        properties=[prop for prop in properties if prop is not None] or None,
    )


def split_requirement(value: str, ecosystem: str) -> tuple[str, str | None]:
    raw = value.strip()
    if ecosystem == "npm":
        if raw.startswith("@"):
            index = raw.rfind("@")
            if index > 0 and "/" in raw[:index]:
                return raw[:index], raw[index + 1 :] or None
            return raw, None
        if "@" in raw:
            name, version = raw.split("@", 1)
            return name, version or None
        return raw, None

    if ecosystem == "pypi":
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9.*+!_-]+)$", raw)
        if match:
            return match.group(1), match.group(2)
        name = re.split(r"\s*(?:==|!=|~=|>=|<=|>|<)\s*", raw, maxsplit=1)[0]
        name = name.split("[", 1)[0].strip()
        return name or raw, None

    if ecosystem == "go":
        if "@" in raw:
            name, version = raw.rsplit("@", 1)
            return name, version or None
        parts = raw.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            return parts[0], parts[1]
        return raw, None

    if ecosystem in {"cargo", "dotnet", "ruby"}:
        if "@" in raw:
            name, version = raw.split("@", 1)
            return name, version or None
        parts = raw.split()
        if len(parts) >= 2:
            return parts[0], parts[1]
        return raw, None

    if ecosystem == "php":
        parts = raw.split(":", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return raw, None

    return raw, None


def purl_for(ecosystem: str, name: str, version: str | None) -> str | None:
    purl_type = PURL_TYPES.get(ecosystem)
    if not purl_type or not name:
        return None

    namespace = None
    package_name = name
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        namespace, package_name = name[1:].split("/", 1)
    elif ecosystem == "php" and "/" in name:
        namespace, package_name = name.split("/", 1)
    elif ecosystem == "go" and "/" in name:
        pieces = name.split("/")
        namespace, package_name = "/".join(pieces[:-1]), pieces[-1]

    if not package_name or any(token in package_name for token in "${}<>"):
        return None

    try:
        return PackageURL(
            type=purl_type,
            namespace=namespace,
            name=package_name,
            version=version,
        ).to_string()
    except ValueError:
        return None


def external_reference_for_resource(value: str, ecosystem: str) -> list[middleware.ExternalReference] | None:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https", "ssh"} and parsed.netloc:
        ref_type = "vcs" if ecosystem == "git" or parsed.netloc in scan_skill_dep.REPO_HOSTS else "distribution"
        return [middleware.ExternalReference(url=value, type=ref_type)]
    return None


def resource_name(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        path = parsed.path.strip("/")
        return f"{parsed.netloc}/{path}" if path else parsed.netloc
    return value


def remote_resource_component_type(value: str, ecosystem: str) -> str:
    if ecosystem == "docker":
        return "container"
    if value.startswith(("git@", "ssh://")):
        return "application"
    if value.startswith(("http://", "https://")) and scan_skill_dep.is_repo_url(value):
        return "application"
    return "file"


def github_blob_parts(url: str | None) -> tuple[str, str, str] | None:
    parsed = urlparse(str(url or ""))
    if parsed.netloc.lower() != "github.com":
        return None
    pieces = parsed.path.strip("/").split("/")
    if len(pieces) < 5 or pieces[2] != "blob":
        return None
    repo = f"{pieces[0]}/{pieces[1]}"
    branch = pieces[3]
    path = "/".join(pieces[4:])
    return repo, branch, path


def resolve_local_resource_url(source_repo: str | None, ref: str) -> str:
    clean_ref = normalize_resource_ref(ref)
    blob = github_blob_parts(source_repo)
    if not blob:
        return clean_ref
    repo, branch, source_path = blob
    source_dir = Path(source_path).parent.as_posix()
    resolved = posixpath.normpath(posixpath.join(source_dir, clean_ref))
    return f"https://github.com/{repo}/blob/{branch}/{resolved}"


def normalize_resource_ref(ref: str) -> str:
    return str(ref or "").strip().strip("`'\"").split("#", 1)[0].split("?", 1)[0]


def add_local_resource_reference(component: middleware.Component, finding: scan_skill_dep.Finding) -> None:
    url = resolve_local_resource_url(component.source_repo, finding.value)
    refs = list(component.external_references or [])
    if any(ref.url == url for ref in refs):
        return
    refs.append(
        middleware.ExternalReference(
            url=url,
            type="other",
            comment="local file reference",
        )
    )
    component.external_references = refs


def is_dependency_local_resource(finding: scan_skill_dep.Finding) -> bool:
    return finding.ecosystem in {
        "executable-file",
        "manifest",
        "python-script",
        "node-script",
        "shell-script",
    }


REFERENCE_ANNOTATION_KINDS = {
    "external_reference",
    "local_resource",
    "metadata_reference",
    "package_reference",
}


def skill_dependency_context(finding: scan_skill_dep.Finding) -> str:
    return finding.skill_repo or finding.skill_name or finding.skill


def skill_dependency_external_references(finding: scan_skill_dep.Finding) -> list[middleware.ExternalReference] | None:
    value = finding.value.strip()
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https", "ssh"} and parsed.netloc:
        return [middleware.ExternalReference(url=value, type="vcs" if scan_skill_dep.is_repo_url(value) else "other")]
    return None


def skill_dependency_source_repo(finding: scan_skill_dep.Finding) -> str | None:
    value = finding.value.strip()
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https", "ssh"} and parsed.netloc:
        if parsed.netloc.lower() == "github.com":
            pieces = parsed.path.strip("/").split("/")
            if len(pieces) >= 2:
                return github_repo_url(f"{pieces[0]}/{pieces[1]}")
        return value
    return github_repo_url(finding.skill_repo)


def skill_dependency_properties(finding: scan_skill_dep.Finding) -> list[middleware.Extension] | None:
    value = finding.value.strip()
    if value.lower().endswith(("skill.md", ".md", ".mdc")):
        prop = make_property("skill:path", value)
        return [prop] if prop is not None else None
    return None


def service_type_for_finding(finding: scan_skill_dep.Finding) -> str:
    if finding.ecosystem in {"api", "mcp", "service", "webhook"}:
        return finding.ecosystem
    return "service"


def service_name_and_endpoint(finding: scan_skill_dep.Finding) -> tuple[str, str | None]:
    value = finding.value.strip()
    if value.startswith("mcp:"):
        return value.split(":", 1)[1].strip() or "mcp-service", None
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return resource_name(value), value
    return value, None


def service_group(endpoint: str | None, service_type: str) -> str | None:
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.netloc:
            return parsed.netloc.lower()
    if service_type == "mcp":
        return "mcp"
    return None


def service_external_references(endpoint: str | None) -> list[middleware.ExternalReference] | None:
    if not endpoint:
        return None
    return [middleware.ExternalReference(url=endpoint, type="other", comment="service endpoint")]


def service_properties(finding: scan_skill_dep.Finding, service_type: str) -> list[middleware.Extension] | None:
    properties = [
        make_property("skillbom.service_type", service_type),
        make_property("skillbom.service_source", f"{finding.source_file}:{finding.line}"),
        make_property("skillbom.service_evidence", finding.evidence),
    ]
    if service_type == "mcp":
        properties.append(make_property("skillbom.mcp_identifier", finding.value.removeprefix("mcp:")))
    return [prop for prop in properties if prop is not None] or None


def service_requires_auth(finding: scan_skill_dep.Finding) -> bool | None:
    if scan_skill_dep.SERVICE_AUTH_CONTEXT_PATTERN.search(finding.evidence):
        return True
    return None


def make_service(finding: scan_skill_dep.Finding) -> middleware.Service | None:
    if finding.kind != "service_call":
        return None
    service_type = service_type_for_finding(finding)
    name, endpoint = service_name_and_endpoint(finding)
    if not name:
        return None
    service_kwargs = {
        "ID": stable_id("service", service_type, name, endpoint or finding.value),
        "name": name,
        "group": service_group(endpoint, service_type),
        "endpoints": [endpoint] if endpoint else ([f"mcp://{slugify(name)}"] if service_type == "mcp" else None),
        "authenticated": service_requires_auth(finding),
        "description": truncate(finding.evidence, MAX_DESCRIPTION_CHARS) if finding.evidence else None,
        "externalReferences": service_external_references(endpoint),
        "properties": service_properties(finding, service_type),
        "x-trust-boundary": True,
    }
    return middleware.Service(**service_kwargs)


def service_key(finding: scan_skill_dep.Finding) -> tuple[str, str]:
    service_type = service_type_for_finding(finding)
    name, endpoint = service_name_and_endpoint(finding)
    return (service_type, endpoint or name.lower())


def relationship_type_for_service(finding: scan_skill_dep.Finding) -> str:
    return "USES_MCP" if service_type_for_finding(finding) == "mcp" else "USES_SERVICE"


def is_optional_dependency(finding: scan_skill_dep.Finding) -> bool:
    text = finding.evidence.lower()
    if (
        finding.kind in {"skill_reference", "skill_reference_note"}
        and scan_skill_dep.RELATED_SKILL_METADATA_PATTERN.search(finding.evidence)
    ):
        return True
    return bool(
        re.search(r"\boptional[-_ ]dependencies?\b", text)
        or re.search(r"\boptional(?:ly)?\s+(?:skill|dependency|depends?|requires?)\b", text)
    )


def make_dependency_component(finding: scan_skill_dep.Finding) -> middleware.Component | None:
    if finding.kind in {"install_command", "manifest_dependency", "code_import"}:
        name, version = split_requirement(finding.value, finding.ecosystem)
        purl = purl_for(finding.ecosystem, name, version)
        component = middleware.Component(
            type="library",
            name=name,
            version=version,
            ID=purl or readable_id("package", finding.ecosystem, name, version or finding.value),
            purl=purl,
        )
        return component

    if finding.kind == "remote_resource":
        name = resource_name(finding.value)
        return middleware.Component(
            type=remote_resource_component_type(finding.value, finding.ecosystem),
            name=name,
            ID=readable_id("resource", finding.ecosystem, name),
            download_location=finding.value if finding.value.startswith(("http://", "https://")) else None,
            external_references=external_reference_for_resource(finding.value, finding.ecosystem),
        )

    if finding.kind == "local_resource":
        if not is_dependency_local_resource(finding):
            return None
        return middleware.Component(
            type="file",
            name=finding.value,
            ID=uuid_urn("local_file", finding.skill_repo or finding.skill_name or finding.skill, finding.value),
        )

    if finding.kind in {"skill_reference", "skill_reference_note"}:
        normalized_ref = normalize_skill_ref(finding.value)
        context = skill_dependency_context(finding)
        return middleware.Component(
            type="application",
            name=normalized_ref,
            ID=uuid_urn("skill", context, normalized_ref, finding.value),
            source_repo=skill_dependency_source_repo(finding),
            external_references=skill_dependency_external_references(finding),
            properties=skill_dependency_properties(finding),
        )

    return None


def dependency_key(finding: scan_skill_dep.Finding) -> tuple[str, str, str]:
    if finding.kind in {"install_command", "manifest_dependency", "code_import"}:
        name, version = split_requirement(finding.value, finding.ecosystem)
        return ("package", finding.ecosystem, f"{name}@{version or ''}")
    if finding.kind == "remote_resource":
        return ("resource", finding.ecosystem, finding.value)
    if finding.kind == "local_resource":
        context = finding.skill_repo or finding.skill_name or finding.skill
        return ("local-resource", context, finding.value)
    if finding.kind in {"skill_reference", "skill_reference_note"}:
        context = skill_dependency_context(finding)
        return ("skill", context, normalize_skill_ref(finding.value))
    return (finding.kind, finding.ecosystem, finding.value)


def relationship_type_for_finding(finding: scan_skill_dep.Finding) -> str:
    return "DEPENDS_ON"


def relationship_comment_for_finding(finding: scan_skill_dep.Finding) -> str:
    return finding_comment(finding)


def relationship_comment(
    comments: list[str],
    optional: bool,
) -> str:
    if optional:
        directive = "; skillbom:optional=true"
        comment = truncate(" | ".join(comments[:3]), MAX_COMMENT_CHARS - len(directive))
        return f"{comment}{directive}"
    comment = truncate(" | ".join(comments[:3]), MAX_COMMENT_CHARS)
    return comment


def finding_comment(finding: scan_skill_dep.Finding) -> str:
    pieces = [
        f"source={finding.source_file}:{finding.line}",
    ]
    if finding.risks:
        pieces.append(f"risks={','.join(finding.risks)}")
    if finding.evidence:
        pieces.append(f"evidence={truncate(finding.evidence, 260)}")
    return truncate("; ".join(pieces), MAX_COMMENT_CHARS)


def build_annotation(
    finding: scan_skill_dep.Finding,
    subject_id: str,
    annotator: middleware.Component,
    timestamp: str,
) -> middleware.Annotation:
    if finding.kind == "risky_command_pattern":
        annotation_type = "risk-signal"
    elif finding.kind in REFERENCE_ANNOTATION_KINDS:
        annotation_type = "reference"
    else:
        annotation_type = "dependency-risk"
    text = finding_comment(finding)
    return middleware.Annotation(
        type=annotation_type,
        ID=stable_id("annotation", subject_id, finding.source_file, finding.line, finding.kind, finding.value),
        subjects=[subject_id],
        timestamp=timestamp,
        annotator=[annotator],
        text=text,
    )


def make_creator_component() -> middleware.Component:
    tool_purl = PackageURL(type="generic", name="SIT", version="1.0").to_string()
    return middleware.Component(
        type="library",
        name="SIT",
        version="1.0",
        ID=tool_purl,
        purl=tool_purl,
        licenses=[middleware.License(type='declared', spdxID='MulanPubL-2.0')],
    )
        


def _build_skill_bom_parts(
    input_path: Path,
    *,
    limit: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
) -> tuple[middleware.Middleware, list[middleware.Service]]:
    skill_inputs = collect_skill_inputs(input_path, limit=limit)
    if not skill_inputs:
        raise ValueError(f"No skill inputs found under {input_path}")

    timestamp = utc_now()
    creator = make_creator_component()
    components: list[middleware.Component] = []
    services: list[middleware.Service] = []
    annotations: list[middleware.Annotation] = []
    component_by_key: dict[tuple[str, str, str], middleware.Component] = {}
    service_by_key: dict[tuple[str, str], middleware.Service] = {}
    relationship_comments: dict[tuple[str, str, str], list[str]] = {}
    relationship_optional: dict[tuple[str, str, str], bool] = {}

    for skill_input in skill_inputs:
        skill_component = make_skill_component(skill_input)
        components.append(skill_component)
        findings = scan_skill_input(skill_input)

        for finding in findings:
            if finding.kind in REFERENCE_ANNOTATION_KINDS or finding.kind == "risky_command_pattern" or finding.risks:
                annotations.append(build_annotation(finding, skill_component.ID, creator, timestamp))
            if finding.kind == "local_resource":
                add_local_resource_reference(skill_component, finding)

            service = make_service(finding)
            if service is not None:
                key = service_key(finding)
                existing_service = service_by_key.get(key)
                if existing_service is None:
                    service_by_key[key] = service
                    services.append(service)
                    existing_service = service
                rel_key = (relationship_type_for_service(finding), skill_component.ID, existing_service.ID)
                relationship_comments.setdefault(rel_key, []).append(relationship_comment_for_finding(finding))
                relationship_optional.setdefault(rel_key, False)
                continue

            dependency_component = make_dependency_component(finding)
            if dependency_component is None:
                continue

            key = dependency_key(finding)
            existing = component_by_key.get(key)
            if existing is None:
                component_by_key[key] = dependency_component
                components.append(dependency_component)
                existing = dependency_component
            rel_key = (relationship_type_for_finding(finding), skill_component.ID, existing.ID)
            relationship_comments.setdefault(rel_key, []).append(relationship_comment_for_finding(finding))
            optional = is_optional_dependency(finding)
            if rel_key not in relationship_optional:
                relationship_optional[rel_key] = optional
            elif not optional:
                relationship_optional[rel_key] = False

    relationships = [
        middleware.Relationship(
            type=rel_type,
            sourceID=source_id,
            targetID=target_id,
            comment=relationship_comment(comments, relationship_optional.get(rel_key, False)),
        )
        for rel_key, comments in sorted(relationship_comments.items())
        for rel_type, source_id, target_id in [rel_key]
    ]

    resolved_input = resolve_input_path(input_path).resolve()
    bom = middleware.Middleware(
        doc_ID=f"urn:uuid:{uuid4()}",
        doc_name=f"Skill SBOM for {resolved_input.name}",
        doc_namespace=namespace,
        license_list_version=LICENSE_LIST_VERSION,
        timestamp=timestamp,
        licenses=[middleware.License(type="declared", spdxID="CC0-1.0")],
        creator=[creator],
        components=components,
        relationship=relationships or None,
        annotations=annotations or None,
    )
    return bom, services


def build_skill_bom(
    input_path: Path,
    *,
    limit: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
) -> middleware.Middleware:
    bom, _ = _build_skill_bom_parts(input_path, limit=limit, namespace=namespace)
    return bom


def build_skill_bom_with_services(
    input_path: Path,
    *,
    limit: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
) -> tuple[middleware.Middleware, list[middleware.Service]]:
    return _build_skill_bom_parts(input_path, limit=limit, namespace=namespace)


def dump_middleware(bom: middleware.Middleware) -> dict:
    return bom.model_dump(mode="json", by_alias=True, exclude_none=True)


def dump_skillbom(
    bom: middleware.Middleware,
    services: list[middleware.Service] | None = None,
) -> dict:
    if not services:
        return Middleware2SkillBOM(bom).middleware2skillbom()
    payload = bom.model_dump(mode="json", by_alias=True, exclude_none=True)
    payload["services"] = [
        service.model_dump(mode="json", by_alias=True, exclude_none=True)
        for service in services
    ]
    return Middleware2SkillBOM(payload).middleware2skillbom()


def write_bom(
    bom: middleware.Middleware,
    output_path: Path | None,
    services: list[middleware.Service] | None = None,
) -> None:
    data = dump_skillbom(bom, services=services)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if output_path is None or str(output_path) == "-":
        print(text)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a SkillBOM for agent skill Markdown files.")
    # parser.add_argument(
    #     "input",
    #     nargs="?",
    #     type=Path,
    #     default=DEFAULT_INPUT,
    #     help="Project directory containing one or more SKILL.md files, a single SKILL.md file, or a pointer file like 'path = ...'.",
    # )
    parser.add_argument("-i", "--input", type=Path, required=True, help="Project directory containing one or more SKILL.md files, or a single SKILL.md file.")
    parser.add_argument("-o", "--output", type=Path, help="Output JSON path. Defaults to stdout.")
    parser.add_argument("--limit", type=int, default=None, help="Only analyze the first N discovered skills.")
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE, help="Document namespace for the generated SBOM.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        bom, services = build_skill_bom_with_services(
            args.input,
            limit=args.limit,
            namespace=args.namespace,
        )
        write_bom(bom, args.output, services=services)
    except Exception as exc:
        print(f"Failed to generate skill SBOM: {exc}", file=sys.stderr)
        return 2

    if args.output:
        data = dump_skillbom(bom, services=services)
        print(
            "Skill SBOM written: "
            f"{args.output} "
            f"(components={len(data.get('components', []))}, "
            f"services={len(data.get('services', []))}, "
            f"relationships={len(data.get('relationship', []))})",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
