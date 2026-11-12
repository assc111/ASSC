from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .labels import JsonDict, normalize_package_name, package_identity, parse_package_ref
from .merge import merge_package_component


REPO_ROOT = Path(__file__).resolve().parents[2]
SIT_ROOT = REPO_ROOT / "SIT"
if str(SIT_ROOT) not in sys.path:
    sys.path.insert(0, str(SIT_ROOT))

try:  # noqa: E402
    from SIT.tool.generate.analyze_sbom import analyze_env
    from SIT.tool.generate.meta.utils import IDManager, str2license
except Exception:  # pragma: no cover - enrichment remains best-effort
    analyze_env = None  # type: ignore[assignment]
    IDManager = None  # type: ignore[assignment]
    str2license = None  # type: ignore[assignment]


_RUN_ENV_CACHE: dict[Path, "PythonEnvironmentIndex"] = {}
_PACKAGE_CACHE: dict[tuple[str, str, str], JsonDict | None] = {}


class PythonEnvironmentIndex:
    def __init__(self, env_path: str | Path | None) -> None:
        self.components: dict[str, JsonDict] = {}
        if not env_path or analyze_env is None:
            return
        try:
            pkg_metas, _pkg2import = analyze_env(str(Path(env_path).expanduser().resolve()))
        except Exception:
            return
        if not pkg_metas:
            return
        for meta in pkg_metas:
            component = dump_model(meta.get("component")) if isinstance(meta, dict) else {}
            name = normalize_package_name("pypi", component.get("name"))
            if name:
                self.components[name] = component

    def get(self, name: str) -> JsonDict | None:
        return self.components.get(normalize_package_name("pypi", name))


def enrich_package_components(
    skillbom: JsonDict,
    *,
    run_env: str | Path | None = None,
) -> dict[str, int]:
    stats = {
        "package_components": 0,
        "package_components_enriched": 0,
        "pypi_components": 0,
        "pypi_components_enriched": 0,
    }
    python_index = cached_run_env(run_env)
    for component in skillbom.get("components") or []:
        if not isinstance(component, dict):
            continue
        parsed = parse_package_ref(component)
        if not parsed:
            continue
        stats["package_components"] += 1
        ecosystem, name, _version = parsed
        if ecosystem == "pypi":
            stats["pypi_components"] += 1
        enriched = enrich_package_component(component, python_index=python_index)
        if not enriched:
            continue
        source = "SIT" if ecosystem == "pypi" else f"{ecosystem}-metadata"
        merge_package_component(component, enriched, source=source)
        stats["package_components_enriched"] += 1
        if ecosystem == "pypi":
            stats["pypi_components_enriched"] += 1
    return stats


def enrich_package_component(
    component: JsonDict,
    *,
    python_index: PythonEnvironmentIndex,
) -> JsonDict | None:
    parsed = parse_package_ref(component)
    if not parsed:
        return None
    ecosystem, name, version = parsed
    cache_key = (ecosystem, normalize_package_name(ecosystem, name), str(version or ""))
    use_cache = not (ecosystem == "pypi" and python_index.components)
    if use_cache and cache_key in _PACKAGE_CACHE:
        return _PACKAGE_CACHE[cache_key]
    if ecosystem == "pypi":
        enriched = enrich_pypi_package(name, version, python_index)
    else:
        enriched = registry_metadata(ecosystem, name, version)
    if use_cache:
        _PACKAGE_CACHE[cache_key] = enriched
    return enriched


def enrich_pypi_package(
    name: str,
    version: str | None,
    python_index: PythonEnvironmentIndex,
) -> JsonDict | None:
    env_component = python_index.get(name)
    if env_component:
        return env_component
    return pypi_identity(name, version)


def pypi_identity(name: str, version: str | None) -> JsonDict:
    component: JsonDict = {
        "type": "library",
        "name": name,
        "version": version,
        "ID": pypi_id(name, version),
        "purl": pypi_id(name, version),
        "external_references": [
            {
                "url": f"https://pypi.org/project/{quote(name)}/",
                "type": "distribution",
                "comment": "package registry",
            }
        ],
    }
    return {key: value for key, value in component.items() if value}


def pypi_id(name: str, version: str | None) -> str:
    if IDManager is not None:
        try:
            return IDManager.get_pkgID(pkgtype="pypi", name=name, version=version)
        except Exception:
            pass
    suffix = f"@{version}" if version else ""
    return f"pkg:pypi/{name}{suffix}"


def registry_metadata(ecosystem: str, name: str, version: str | None) -> JsonDict | None:
    registry_urls = {
        "npm": f"https://www.npmjs.com/package/{quote(name, safe='@/')}",
        "cargo": f"https://crates.io/crates/{quote(name)}",
        "golang": f"https://pkg.go.dev/{quote(name, safe='/')}",
        "nuget": f"https://www.nuget.org/packages/{quote(name)}",
        "composer": f"https://packagist.org/packages/{quote(name, safe='/')}",
        "gem": f"https://rubygems.org/gems/{quote(name)}",
        "brew": f"https://formulae.brew.sh/formula/{quote(name)}",
        "docker": f"https://hub.docker.com/r/{quote(name, safe='/')}",
    }
    url = registry_urls.get(ecosystem)
    if not url:
        return None
    package_type, package_name, package_version = ecosystem, name, version
    purl = f"pkg:{package_type}/{package_name}{'@' + package_version if package_version else ''}"
    return {
        "type": "library",
        "name": name,
        "version": version,
        "ID": purl,
        "purl": purl,
        "external_references": [
            {
                "url": url,
                "type": "distribution",
                "comment": "package registry",
            }
        ],
    }


def checksums_from_sit(value: Any) -> list[JsonDict]:
    values = value if isinstance(value, list) else [value]
    checksums: list[JsonDict] = []
    for item in values:
        text = str(item or "")
        if ":" not in text:
            continue
        alg, checksum = text.split(":", 1)
        if alg and checksum:
            checksums.append({"alg": alg, "value": checksum})
    return checksums


def dump_model(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, list):
        return [dump_model(item) for item in value if dump_model(item) is not None]
    if isinstance(value, dict):
        return {key: dump_model(item) for key, item in value.items() if dump_model(item) is not None}
    return value


def cached_run_env(env_path: str | Path | None) -> PythonEnvironmentIndex:
    if not env_path:
        return PythonEnvironmentIndex(None)
    resolved = Path(env_path).expanduser().resolve()
    existing = _RUN_ENV_CACHE.get(resolved)
    if existing is not None:
        return existing
    index = PythonEnvironmentIndex(resolved)
    _RUN_ENV_CACHE[resolved] = index
    return index
