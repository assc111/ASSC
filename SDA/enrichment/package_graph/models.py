from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from packageurl import PackageURL

from ..labels import JsonDict


HTTP_TIMEOUT_SECONDS = 2


@dataclass(frozen=True)
class PackageDependency:
    ecosystem: str
    name: str
    version: str | None = None
    version_spec: str | None = None
    dependency_type: str = "dependencies"
    scope: str | None = "runtime"
    optional: bool = False
    source: str = ""


def fetch_json(url: str) -> JsonDict | None:
    request = Request(url, headers={"User-Agent": "skillbom-generator"})
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            payload = response.read()
    except (HTTPError, URLError, TimeoutError, OSError):
        return None
    try:
        data = json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def run_json_command(command: list[str]) -> JsonDict | None:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def purl_for(ecosystem: str, name: str, version: str | None = None) -> str:
    package_type = {
        "brew": "brew",
        "cargo": "cargo",
        "composer": "composer",
        "conda": "conda",
        "gem": "gem",
        "golang": "golang",
        "npm": "npm",
        "nuget": "nuget",
        "pypi": "pypi",
    }.get(ecosystem, ecosystem)
    namespace = None
    package_name = name
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        namespace, package_name = name[1:].split("/", 1)
    elif ecosystem in {"composer", "golang"} and "/" in name:
        parts = name.split("/")
        namespace, package_name = "/".join(parts[:-1]), parts[-1]
    try:
        return PackageURL(
            type=package_type,
            namespace=namespace,
            name=package_name,
            version=version,
        ).to_string()
    except ValueError:
        suffix = f"@{version}" if version else ""
        return f"pkg:{package_type}/{quote(name, safe='@/')}{suffix}"


def dependency_component(dep: PackageDependency) -> JsonDict:
    version = dep.version or exact_version(dep.version_spec)
    purl = purl_for(dep.ecosystem, dep.name, version)
    component: JsonDict = {
        "type": "library",
        "name": dep.name,
        "ID": purl,
        "purl": purl,
    }
    if version:
        component["version"] = version
    return component


def exact_version(version_spec: str | None) -> str | None:
    spec = str(version_spec or "").strip()
    if not spec:
        return None
    if any(token in spec for token in "<>~=^*|, ;"):
        return None
    return spec
