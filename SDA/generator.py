from __future__ import annotations

import json
import posixpath
import re
import tempfile
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .analyze_skill_sbom import DEFAULT_NAMESPACE, build_skill_bom_with_services
from .enrichment import EnrichmentOptions, enrich_skillbom
from .schema import SkillBOM
from .skillbom_conversion import Middleware2SkillBOM


JsonDict = dict[str, Any]


def _slug(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        return "unknown"
    return text[:max_len].strip("-") or "unknown"


def _append_property(properties: list[JsonDict], key: str, value: object | None) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    if any(prop.get("key") == key for prop in properties):
        return
    properties.append({"key": key, "value": text})


def _github_repo_url(repo: str | None, source_url: str | None = None) -> str | None:
    if source_url:
        parsed = urlparse(source_url)
        if parsed.netloc.lower() == "github.com":
            pieces = parsed.path.strip("/").split("/")
            if len(pieces) >= 2:
                return f"https://github.com/{pieces[0]}/{pieces[1]}"
    repo_text = str(repo or "").strip().strip("/")
    if repo_text:
        return f"https://github.com/{repo_text}"
    return None


def _resolve_local_ref_from_source(source_ref: str | None, ref: str) -> str:
    parsed = urlparse(str(source_ref or ""))
    if parsed.netloc.lower() != "github.com" or "/blob/" not in parsed.path:
        return ref
    pieces = parsed.path.strip("/").split("/")
    if len(pieces) < 5 or pieces[2] != "blob":
        return ref
    repo = f"{pieces[0]}/{pieces[1]}"
    branch = pieces[3]
    source_path = "/".join(pieces[4:])
    source_dir = posixpath.dirname(source_path)
    target_path = posixpath.normpath(posixpath.join(source_dir, ref))
    return f"https://github.com/{repo}/blob/{branch}/{target_path}"


def _rewrite_local_file_references(skill_component: JsonDict, source_ref: str | None) -> None:
    refs = []
    changed = False
    for ref in skill_component.get("external_references") or []:
        if not isinstance(ref, dict):
            refs.append(ref)
            continue
        if ref.get("comment") != "local file reference":
            refs.append(ref)
            continue
        url = str(ref.get("url") or "")
        if url.startswith(("http://", "https://")):
            refs.append(ref)
            continue
        updated = dict(ref)
        updated["url"] = _resolve_local_ref_from_source(source_ref, url)
        refs.append(updated)
        changed = True
    if changed:
        skill_component["external_references"] = refs


def _record_source_name(
    *,
    repo: str | None = None,
    source_path: str | None = None,
    index: int | None = None,
) -> str:
    repo_text = str(repo or "").strip()
    if "/" in repo_text:
        owner, project = repo_text.split("/", 1)
        name_part = f"{_slug(owner)}_{_slug(project)}"
    else:
        path = Path(source_path or "SKILL.md")
        skill_name = path.parent.name if path.name.lower() == "skill.md" else path.stem
        name_part = f"{_slug(repo_text)}_{_slug(skill_name)}"
    prefix = f"{index:06d}_" if index is not None else ""
    return f"{prefix}{name_part}_SKILL.md"


def _enrich_skillbom_source_metadata(
    skillbom: JsonDict,
    *,
    repo: str | None = None,
    source_path: str | None = None,
    source_url: str | None = None,
    content_hash: str | None = None,
    stars: int | None = None,
    source: str | None = None,
) -> JsonDict:
    if source_path:
        skillbom["doc_name"] = f"Skill SBOM for {source_path}"

    components = skillbom.get("components") or []
    if not components:
        return skillbom

    skill_component = components[0]
    source_ref = _github_repo_url(repo, source_url)
    if source_ref:
        skill_component["source_repo"] = source_ref
        refs = list(skill_component.get("external_references") or [])
        if not any(ref.get("url") == source_ref for ref in refs):
            refs.append(
                {
                    "url": source_ref,
                    "type": "vcs",
                    "comment": "source repository",
                }
            )
        skill_component["external_references"] = refs
        _rewrite_local_file_references(skill_component, source_ref)
    properties = list(skill_component.get("properties") or [])
    _append_property(properties, "skill:path", source_path)
    if properties:
        skill_component["properties"] = properties
    if content_hash and not skill_component.get("checksum"):
        skill_component["checksum"] = [{"alg": "SHA-256", "value": content_hash}]

    return SkillBOM(**skillbom).model_dump(mode="json", by_alias=True, exclude_none=True)


def generate_skillbom(
    input_path: str | Path,
    *,
    limit: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
    skill_db: str | Path | None = None,
    run_env: str | Path | None = None,
    report_path: str | Path | None = None,
) -> JsonDict:
    """Analyze agent skill files and return a SkillBOM document as a dict."""
    middleware_bom, services = build_skill_bom_with_services(
        Path(input_path),
        limit=limit,
        namespace=namespace,
    )
    middleware_payload = middleware_bom.model_dump(mode="json", by_alias=True, exclude_none=True)
    if services:
        middleware_payload["services"] = [
            service.model_dump(mode="json", by_alias=True, exclude_none=True)
            for service in services
        ]
    skillbom = Middleware2SkillBOM(middleware_payload).middleware2skillbom()
    return enrich_skillbom(
        skillbom,
        options=EnrichmentOptions(
            skill_db=Path(skill_db) if skill_db else None,
            run_env=Path(run_env) if run_env else None,
            report_path=Path(report_path) if report_path else None,
        ),
    )


def generate_skillbom_model(
    input_path: str | Path,
    *,
    limit: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
    skill_db: str | Path | None = None,
    run_env: str | Path | None = None,
    report_path: str | Path | None = None,
) -> SkillBOM:
    """Analyze agent skill files and return a validated SkillBOM model."""
    return SkillBOM(
        **generate_skillbom(
            input_path,
            limit=limit,
            namespace=namespace,
            skill_db=skill_db,
            run_env=run_env,
            report_path=report_path,
        )
    )


def generate_skillbom_from_text(
    content: str,
    *,
    repo: str | None = None,
    source_path: str | None = None,
    source_url: str | None = None,
    content_hash: str | None = None,
    stars: int | None = None,
    source: str | None = None,
    index: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
    skill_db: str | Path | None = None,
    run_env: str | Path | None = None,
    report_path: str | Path | None = None,
) -> JsonDict:
    """Generate a SkillBOM from in-memory skill Markdown content."""
    source_name = _record_source_name(repo=repo, source_path=source_path, index=index)
    with tempfile.TemporaryDirectory(prefix="skillbom-generator-") as temp_dir:
        input_path = Path(temp_dir) / source_name
        input_path.write_text(content, encoding="utf-8", errors="replace")
        skillbom = generate_skillbom(
            input_path,
            namespace=namespace,
            skill_db=skill_db,
            run_env=run_env,
            report_path=report_path,
        )

    return _enrich_skillbom_source_metadata(
        skillbom,
        repo=repo,
        source_path=source_path,
        source_url=source_url,
        content_hash=content_hash,
        stars=stars,
        source=source,
    )


def generate_skillbom_from_record(
    record: Mapping[str, Any],
    *,
    index: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
    skill_db: str | Path | None = None,
    run_env: str | Path | None = None,
    report_path: str | Path | None = None,
) -> JsonDict:
    """Generate a SkillBOM from one SkillMD JSONL record."""
    content = record.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("SkillMD record does not contain non-empty 'content'")

    stars = record.get("stars")
    return generate_skillbom_from_text(
        content,
        repo=str(record.get("repo") or "") or None,
        source_path=str(record.get("path") or "") or None,
        source_url=str(record.get("html_url") or "") or None,
        content_hash=str(record.get("content_hash") or "") or None,
        stars=stars if isinstance(stars, int) else None,
        source=str(record.get("source") or "") or None,
        index=index,
        namespace=namespace,
        skill_db=skill_db,
        run_env=run_env,
        report_path=report_path,
    )


def write_skillbom(
    skillbom: Mapping[str, Any] | SkillBOM,
    output_path: str | Path | None = None,
    *,
    indent: int = 2,
) -> None:
    """Write a SkillBOM document to a JSON file or stdout when output_path is '-'."""
    data = (
        skillbom.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(skillbom, SkillBOM)
        else dict(skillbom)
    )
    text = json.dumps(data, ensure_ascii=False, indent=indent)

    if output_path is None or str(output_path) == "-":
        print(text)
        return

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def generate_and_write_skillbom(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    limit: int | None = None,
    namespace: str = DEFAULT_NAMESPACE,
    skill_db: str | Path | None = None,
    run_env: str | Path | None = None,
    report_path: str | Path | None = None,
) -> JsonDict:
    """Generate a SkillBOM, write it, and return the generated dict."""
    skillbom = generate_skillbom(
        input_path,
        limit=limit,
        namespace=namespace,
        skill_db=skill_db,
        run_env=run_env,
        report_path=report_path,
    )
    write_skillbom(skillbom, output_path)
    return skillbom
