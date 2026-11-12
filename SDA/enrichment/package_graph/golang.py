from __future__ import annotations

from urllib.parse import quote

from .models import PackageDependency, fetch_json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def go_proxy_escape(value: str) -> str:
    result = []
    for char in value:
        if "A" <= char <= "Z":
            result.append("!" + char.lower())
        else:
            result.append(char)
    return "".join(result)


def fetch_text(url: str) -> str | None:
    try:
        with urlopen(Request(url, headers={"User-Agent": "skillbom-generator"}), timeout=5) as response:
            return response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError):
        return None


def resolve(name: str, version: str | None = None) -> list[PackageDependency]:
    escaped = go_proxy_escape(name)
    selected = version
    if not selected:
        latest = fetch_json(f"https://proxy.golang.org/{quote(escaped, safe='/!')}/@latest")
        if latest:
            selected = latest.get("Version")
    if not selected:
        return []
    gomod = fetch_text(f"https://proxy.golang.org/{quote(escaped, safe='/!')}/@v/{quote(str(selected))}.mod")
    if not gomod:
        return []
    return parse_go_mod(gomod)


def parse_go_mod(text: str) -> list[PackageDependency]:
    deps: list[PackageDependency] = []
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_require:
            continue
        pieces = line.split()
        if len(pieces) < 2:
            continue
        deps.append(
            PackageDependency(
                ecosystem="golang",
                name=pieces[0],
                version_spec=pieces[1],
                dependency_type="require",
                scope="runtime",
                source="go-proxy",
            )
        )
    return deps
