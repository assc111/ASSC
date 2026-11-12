#!/usr/bin/env python3
"""
Scan agent skills for possible supply-chain dependencies.

This is intentionally lightweight: it uses only the Python standard library and
looks for evidence that a skill may install packages, download remote resources,
execute setup commands, or reference other skill documents.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import shlex
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None


THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
SIT_ROOT = REPO_ROOT / "SIT"
if str(SIT_ROOT) not in sys.path:
    sys.path.insert(0, str(SIT_ROOT))

try:
    from SIT.tool.generate.meta.utils import get_packages as sit_get_packages  # noqa: E402
    from SIT.tool.generate.meta.utils import pyfile_depends as sit_pyfile_depends  # noqa: E402
except Exception:  # pragma: no cover - SIT optional when this scanner is reused elsewhere
    sit_get_packages = None
    sit_pyfile_depends = None


TEXT_EXTENSIONS = {
    ".md",
    ".mdc",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".py",
    ".js",
    ".ts",
}

SKILL_MARKERS = {
    "SKILL.md",
    "skill.md",
    "skill.json",
    "skill.yaml",
    "skill.yml",
}

MAX_FILE_BYTES = 2_000_000


INSTALL_PATTERNS = [
    ("pypi", re.compile(r"\b(?:python(?:3)?\s+-m\s+)?pip(?:3)?\s+install\s+([^\n;&|`]+)", re.I)),
    ("pypi", re.compile(r"\bpipx\s+install\s+([^\n;&|`]+)", re.I)),
    ("pypi", re.compile(r"\buv\s+pip\s+install\s+([^\n;&|`]+)", re.I)),
    ("pypi", re.compile(r"\buv\s+add\s+([^\n;&|`]+)", re.I)),
    ("pypi", re.compile(r"\buv\s+tool\s+install\s+([^\n;&|`]+)", re.I)),
    ("pypi", re.compile(r"\bpoetry\s+add\s+([^\n;&|`]+)", re.I)),
    ("npm", re.compile(r"\b(?:npm\s+(?:install|i)|yarn\s+add|pnpm\s+add|bun\s+add)\s+([^\n;&|`]+)", re.I)),
    ("npm", re.compile(r"\bnpx\s+([@/\w.-]+)", re.I)),
    ("go", re.compile(r"\bgo\s+(?:install|get)\s+([^\n;&|`]+)", re.I)),
    ("cargo", re.compile(r"\bcargo\s+(?:install|add)\s+([^\n;&|`]+)", re.I)),
    ("conda", re.compile(r"\b(?:conda|mamba|micromamba)\s+install\s+([^\n;&|`]+)", re.I)),
    ("system", re.compile(r"\b(?:apt-get|apt|yum|dnf|apk)\s+install\s+([^\n;&|`]+)", re.I)),
    ("homebrew", re.compile(r"\bbrew\s+install\s+([^\n;&|`]+)", re.I)),
    ("ruby", re.compile(r"\bgem\s+install\s+([^\n;&|`]+)", re.I)),
    ("php", re.compile(r"\bcomposer\s+require\s+([^\n;&|`]+)", re.I)),
    ("dotnet", re.compile(r"\bdotnet\s+add\s+package\s+([^\n;&|`]+)", re.I)),
    ("docker", re.compile(r"\bdocker\s+pull\s+([^\n;&|`]+)", re.I)),
    ("git", re.compile(r"\bgit\s+clone\s+([^\n;&|`]+)", re.I)),
]

DOWNLOAD_PATTERNS = [
    ("curl", re.compile(r"\bcurl\b[^\n`]*?(https?://[^\s\"')]+)", re.I)),
    ("wget", re.compile(r"\bwget\b[^\n`]*?(https?://[^\s\"')]+)", re.I)),
    ("powershell", re.compile(r"\b(?:Invoke-WebRequest|iwr)\b[^\n`]*?(https?://[^\s\"')]+)", re.I)),
    ("url", re.compile(r"https?://[^\s\"'<>)]{4,}", re.I)),
]

SERVICE_URL_PATTERN = re.compile(r"https?://[^\s`\"'<>),，。；、）】》]{4,}", re.I)

SERVICE_URL_CONTEXT_PATTERN = re.compile(
    r"\b(?:"
    r"api|apis|api[-_ ]?url|endpoint|endpoints|base[-_ ]?url|site[-_ ]?url|site\s+root|"
    r"webhook|webhooks|graphql|rest|rpc|sse|dsn|oauth|saas|"
    r"hosted\s+service|external\s+service"
    r")\b",
    re.I,
)

SERVICE_RUNTIME_URL_CONTEXT_PATTERN = re.compile(
    r"\b(?:"
    r"api[-_ ]?url|endpoint|endpoints|base[-_ ]?url|site[-_ ]?url|site\s+root|"
    r"webhook|webhooks|curl\b|mcp[-_ ]?endpoint|mcp[-_ ]?server"
    r")\b",
    re.I,
)

SERVICE_HTTP_CLIENT_CONTEXT_PATTERN = re.compile(
    r"fetch\s*\(|axios\.|requests?\.(?:get|post|put|patch|delete|request)\s*\(|"
    r"httpx\.(?:get|post|put|patch|delete|request)\s*\(|aiohttp\.|urllib\.request|"
    r"\b[A-Za-z_][\w.]*\.(?:get|post|put|patch|delete|request)\s*\(|"
    r"\bsignedFetch\s*\(|\bnew\s+Uri\s*\(|\bURL\s*\(\s*string\s*:|\bBaseAddress\b|"
    r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+https?://|"
    r"\b(?:--url|url)\s*[:=]?\s*https?://|"
    r"\b[A-Z0-9_]*API_URL\s*=",
    re.I,
)

SERVICE_AUTH_CONTEXT_PATTERN = re.compile(
    r"\b(?:api[-_ ]?key|secret|token|bearer|oauth|auth|credential|dsn|webhook[-_ ]?secret)\b",
    re.I,
)

SERVICE_TYPE_PATTERNS = [
    ("mcp", re.compile(r"\bmcp\b|mcpservers?|mcp__", re.I)),
    ("webhook", re.compile(r"\bwebhooks?\b", re.I)),
    ("api", re.compile(r"\b(?:api|graphql|rest|rpc|endpoint|oauth)\b", re.I)),
]

MCP_TOOL_PATTERN = re.compile(r"\bmcp__([A-Za-z0-9.-]+(?:_[A-Za-z0-9.-]+)*)(?:__[A-Za-z0-9_.-]+)?\b")
MCP_SERVER_DECL_PATTERN = re.compile(
    r"\b(?:mcp[-_ ]?servers?|mcp[-_ ]?server|(?:required|optional|preferred)\s+mcp\s+server)\b(?:[*_`\s-]{0,12})[:=]\s*[`'\"]?(@?[A-Za-z0-9_.@/-]+)",
    re.I,
)
MCP_NAMED_SERVER_PATTERN = re.compile(r"\b([A-Za-z0-9_.-]{3,40})\s+MCP\s+server\b", re.I)
MCP_SERVER_BOUNDARY_PATTERN = re.compile(
    r"\bMCP\s+server\s+(?:named|called|`)?([A-Za-z0-9_.-]{3,40})`?",
    re.I,
)
MCP_PACKAGE_PATTERN = re.compile(
    r"\b(?:npx|uvx|docker\s+run|pipx\s+run)\s+([@/\w.-]*mcp[\w./@-]*)",
    re.I,
)

KNOWN_API_SERVICE_PATTERN = re.compile(
    r"\b("
    r"openai|anthropic|github|gitlab|slack|discord|notion|stripe|sentry|"
    r"posthog|supabase|firebase|google|gemini|deepseek|perplexity|huggingface|"
    r"hugging[-_ ]face|pinecone|qdrant|weaviate|aws|azure"
    r")\s+(?:api|sdk|service|client)\b",
    re.I,
)

GENERIC_API_SERVICE_PATTERN = re.compile(
    r"\b([A-Z][A-Za-z0-9_.-]{1,30}(?:\s+[A-Z][A-Za-z0-9_.-]{1,30}){0,2})\s+"
    r"(?:REST\s+|GraphQL\s+|HTTP\s+)?API\b"
)

API_KEY_SERVICE_PATTERN = re.compile(r"\b([A-Z][A-Z0-9]{1,24})_(?:API[_-]?KEY|ACCESS[_-]?TOKEN|TOKEN|SECRET)\b")

SERVICE_NAME_STOP_WORDS = {
    "a",
    "an",
    "and",
    "api",
    "app",
    "auth",
    "backend",
    "configuration",
    "config",
    "connection",
    "cookie",
    "endpoint",
    "external",
    "for",
    "frontend",
    "gateway",
    "host",
    "http",
    "integration",
    "jwt",
    "local",
    "named",
    "optional",
    "package",
    "preferred",
    "public",
    "refresh",
    "required",
    "rest",
    "secret",
    "server",
    "service",
    "setup",
    "start",
    "the",
    "token",
    "tool",
    "tools",
    "using",
    "your",
    "with",
}

MCP_SERVICE_BOUNDARY_WORDS = {
    "blocks",
    "connection",
    "directly",
    "documentation",
    "exposes",
    "integration",
    "must",
    "optional",
    "package",
    "pattern",
    "permissions",
    "preferred",
    "provides",
    "required",
    "returns",
    "rules",
    "start",
    "that",
    "usually",
    "when",
}

SKILL_REF_PATTERNS = [
    re.compile(r"\b(?:related[-_]?skills?|similar[-_]?skills|see[-_]?also|enhances)\s*[:=]\s*\[?([^\]\n]+)", re.I),
    re.compile(r"`([A-Za-z0-9][A-Za-z0-9_.-]{2,})`\s+skill\b", re.I),
    re.compile(r"\buse\s+([A-Za-z0-9][A-Za-z0-9_.-]{2,})\s+skill\b", re.I),
    re.compile(r"\b(?:skill|skills)\s*[:=]\s*\[?([^\]\n]+)", re.I),
    re.compile(r"\b(?:requires?|depends(?:\s+on)?|dependencies?)\s*[:=]\s*\[?([^\]\n]+)", re.I),
    re.compile(r"\[[^\]]+\]\(([^)]*(?:SKILL\.md|skill\.md)(?:#[^)]*)?)\)", re.I),
    re.compile(r"\[[^\]]*(?:skill|Skill|SKILL)[^\]]*\]\(([^)]+)\)"),
    re.compile(r"((?:\.\.?/|[\w.-]+/)[^\s`\])|]*?(?:SKILL|skill)\.md(?:#[^\s`\])|]+)?)"),
    re.compile(r"([./\w-]*(?:skills?|\.claude/skills|\.cursor/rules)[./\w-]*(?:SKILL\.md|skill\.md|\.md|\.mdc))"),
]

LOCAL_MARKDOWN_REF_PATTERNS = [
    re.compile(r"`([^`]+?\.(?:md|mdc)(?:#[^`]*)?)`", re.I),
    re.compile(r"\[[^\]]+\]\(([^)]+?\.(?:md|mdc)(?:#[^)]*)?)\)", re.I),
]

LOCAL_RUNTIME_COMMAND_PATTERNS = [
    ("python-script", re.compile(r"\bpython(?:3)?[ \t]+((?:\./)?(?:scripts?|bin|tools)/[^\s`\"'<>]+)", re.I)),
    ("node-script", re.compile(r"\bnode[ \t]+((?:\./)?(?:scripts?|bin|tools)/[^\s`\"'<>]+)", re.I)),
    ("shell-script", re.compile(r"\b(?:bash|sh|zsh)[ \t]+((?:\./)?(?:scripts?|bin|tools)/[^\s`\"'<>]+)", re.I)),
    ("uv-run-script", re.compile(r"\buv[ \t]+run(?:[ \t]+--[\w.-]+)*(?:[ \t]+--)?[ \t]+((?:\./)?(?:scripts?|bin|tools)/[^\s`\"'<>]+)", re.I)),
]

LOCAL_EXECUTABLE_REF_PATTERN = re.compile(
    r"(?<![\w/.-])((?:\./)?(?:scripts?|bin|tools)/[^\s`\"'<>]+\.(?:py|js|mjs|cjs|ts|tsx|sh|bash|zsh|ps1))\b",
    re.I,
)

LOCAL_MANIFEST_REF_PATTERNS = [
    re.compile(r"\b(?:pip(?:3)?|python(?:3)?\s+-m\s+pip|uv\s+pip)\s+install\s+(?:-[^\S\n]*r|-r|--requirement)[ \t]+([^\s`\"'<>]+)", re.I),
    re.compile(r"\b(?:npm\s+(?:ci|install|i)|pnpm\s+install|yarn\s+install|bun\s+install)\s*(?:$|[#`])", re.I),
    re.compile(r"\bpoetry\s+install\b", re.I),
]

DOCKER_RUN_PATTERN = re.compile(r"\bdocker\s+run\s+([^\n;&|`]+)", re.I)

LOCAL_DOC_CONTEXT_PATTERN = re.compile(
    r"\b(?:load|read|reference|references|source|sources|consult|include|see|open|use)\b",
    re.I,
)

REFERENCE_URL_CONTEXT_PATTERN = re.compile(
    r"\b(?:resources?|documentation|docs?|references?|handbook|guide|article|articles|paper|papers|sources?|credits?|attribution|original repository|alternative)\b",
    re.I,
)

REFERENCE_METADATA_KEYS = {
    "author",
    "authors",
    "compatibility",
    "domain",
    "enhances",
    "family",
    "keywords",
    "related-skill",
    "related-skills",
    "references",
    "rigor",
    "role",
    "scope",
    "see-also",
    "similar-skills",
    "source",
    "sources",
    "sources-pdf",
    "sources-web",
    "type",
}

SERVICE_METADATA_KEYS = {
    "api",
    "api-base-url",
    "api-url",
    "base-url",
    "callback-url",
    "dsn",
    "endpoint",
    "endpoints",
    "host",
    "mcp",
    "mcp-server",
    "mcp-servers",
    "server-url",
    "service",
    "service-url",
    "services",
    "url",
    "webhook",
    "webhook-url",
}

JS_IMPORT_PATTERN = re.compile(
    r"""
    (?:import|export)\s+(?:type\s+)?(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]
    |require\(\s*['"]([^'"]+)['"]\s*\)
    |import\(\s*['"]([^'"]+)['"]\s*\)
    """,
    re.I | re.X,
)

PYTHON_IMPORT_ALIASES = {
    "PIL": "Pillow",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
}

PYTHON_STDLIB_MODULES = set(getattr(sys, "stdlib_module_names", set())) | {
    "__future__",
    "typing",
}

NODE_BUILTIN_MODULES = {
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "crypto",
    "dgram",
    "dns",
    "events",
    "fs",
    "http",
    "https",
    "module",
    "net",
    "os",
    "path",
    "process",
    "querystring",
    "readline",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "vm",
    "zlib",
}

RISK_RULES = [
    ("remote-shell-pipe", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh|python|python3|node)\b", re.I)),
    ("powershell-remote-exec", re.compile(r"\b(?:iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b", re.I)),
    ("obfuscation", re.compile(r"\b(?:base64\s+-d|base64\s+--decode|eval\s+|Invoke-Expression|iex\b)", re.I)),
    ("privileged-install", re.compile(r"\bsudo\b", re.I)),
    ("chmod-exec", re.compile(r"\bchmod\s+\+x\b", re.I)),
]

SELF_SKILL_INSTALL_PATTERNS = [
    re.compile(r"\b(?:skill|skills)\s+install\b", re.I),
    re.compile(r"\b(?:install|add|copy|download|clone)\s+(?:this|the)\s+(?:agent\s+)?skill\b", re.I),
    re.compile(r"\b(?:claude|codex|cursor|gemini|qwen)\s+(?:code\s+)?(?:skill|skills)\s+(?:install|add)\b", re.I),
    re.compile(r"/(?:skill|skills)\s+(?:install|add)\b", re.I),
]

PINNED_VERSION_PATTERN = re.compile(r"([=@~^<>]=?|==)\s*[\w.*+-]+")

PACKAGE_STOP_WORDS = {
    "#",
    "add",
    "added",
    "and",
    "check",
    "command",
    "core",
    "dependency",
    "dependencies",
    "dependencies.",
    "dev",
    "environment",
    "extras",
    "for",
    "from",
    "include",
    "included",
    "install",
    "installs",
    "linux",
    "locally",
    "macos",
    "manually",
    "npm",
    "of",
    "only",
    "optional",
    "or",
    "package",
    "package-name",
    "python",
    "run",
    "running",
    "saves",
    "server",
    "start",
    "to",
    "variables",
    "with",
}

PLACEHOLDER_VALUES = {
    "app",
    "image",
    "image-name",
    "image:tag",
    "myapp",
    "my-image",
    "owner/repo",
    "repo",
    "repo-url",
    "repository-url",
    "some-package",
    "source",
    "that",
    "the",
    "this",
    "esta",
    "essa",
    "este",
    "url",
    "user/repo",
    "username/myapp",
    "your-repo",
}

NON_SKILL_REF_VALUES = {
    "a",
    "an",
    "any",
    "current",
    "every",
    "false",
    "given",
    "installed",
    "my",
    "none",
    "null",
    "off-by-default",
    "prompt-accepting",
    "risk-level",
    "true",
    "user-invocable",
    "your",
}

SCHEMA_SKILL_REF_VALUES = {
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
    "skills",
    "version",
}

CONFIG_SKILL_REF_PATTERN = re.compile(
    r"(?:api[-_]?key|secret|token|password|passwd|credential|access[-_]?key|"
    r"private[-_]?key|signer[-_]?key|wallet[-_]?address|router[-_]?key|"
    r"base[-_]?url|endpoint|webhook|dsn|connection[-_]?string|service[-_]?key|"
    r"openai[-_]?model|model|language|output[-_]?folder|user[-_]?name|"
    r"recommended[-_]?owner|provider|host|port|\.com)$",
    re.I,
)

OPTION_VALUE_FLAGS = {
    "-b",
    "-c",
    "-i",
    "-o",
    "-r",
    "-t",
    "-w",
    "--branch",
    "--cache",
    "--constraint",
    "--depth",
    "--env",
    "--env-file",
    "--entrypoint",
    "--filter",
    "--hostname",
    "--index-url",
    "--label",
    "--mount",
    "--name",
    "--network",
    "--platform",
    "--prefix",
    "--publish",
    "--registry",
    "--requirement",
    "--target",
    "--user",
    "--volume",
    "--workspace",
    "--workdir",
    "-e",
    "-p",
    "-u",
    "-v",
}

NO_VALUE_FLAGS = {
    "--bare",
    "--depth=1",
    "--force",
    "--global",
    "--location",
    "--mirror",
    "--no-checkout",
    "--no-save",
    "--production",
    "--quiet",
    "--recursive",
    "--recurse-submodules",
    "--save",
    "--save-dev",
    "--single-branch",
    "--rm",
    "--user",
    "-D",
    "-G",
    "-U",
    "-d",
    "-g",
    "-i",
    "-it",
    "-q",
    "-y",
}

DOWNLOAD_FILE_EXTENSIONS = (
    ".appimage",
    ".bin",
    ".bz2",
    ".deb",
    ".dmg",
    ".exe",
    ".gz",
    ".jar",
    ".msi",
    ".pkg",
    ".ps1",
    ".rpm",
    ".sh",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tgz",
    ".txz",
    ".whl",
    ".xz",
    ".zip",
)

PACKAGE_REGISTRY_HOSTS = {
    "crates.io",
    "deno.land",
    "docs.astral.sh",
    "go.dev",
    "hex.pm",
    "packagist.org",
    "pkg.go.dev",
    "pypi.org",
    "rubygems.org",
    "www.npmjs.com",
}

REPO_HOSTS = {
    "bitbucket.org",
    "github.com",
    "gitlab.com",
}

DOCUMENTATION_URL_HOSTS = {
    "blog.vllm.ai",
    "developers.figma.com",
    "inertiajs.com",
    "learn.microsoft.com",
    "react.dev",
    "vitejs.dev",
}

GENERIC_REPO_SEGMENTS = {
    "my-lib",
    "my-repo",
    "myapp",
    "project",
    "repo",
    "repository",
    "your-repo",
}

GENERIC_REPO_OWNERS = {
    "example",
    "features",
    "login",
    "marketplace",
    "me",
    "myorg",
    "new",
    "notifications",
    "org",
    "organizations",
    "owner",
    "settings",
    "sponsors",
    "topics",
    "username",
    "user",
    "you",
}

SIMPLE_SKILL_STOP_WORDS = {
    "appropriate",
    "bash",
    "bins",
    "comments",
    "doc",
    "docs",
    "documentation",
    "editing",
    "env",
    "false",
    "formatting",
    "main",
    "markdown",
    "readme",
    "reference",
    "references",
    "setup",
    "skill",
    "skill-md",
    "skills",
    "that",
    "the",
    "this",
    "true",
    "unknown",
    "when",
}

NON_SKILL_REF_SUFFIXES = {
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

SKILL_DEPENDENCY_CONTEXT_PATTERN = re.compile(
    r"\b(?:"
    r"depend(?:s|ency|encies)?|requires?|use|uses|invoke|call|run|execute|"
    r"delegate|delegates|handoff|hand[- ]?off|route|routes|orchestrate|compose|chain|"
    r"coordinate|load|install|import"
    r")\b",
    re.I,
)

SKILL_REFERENCE_ONLY_CONTEXT_PATTERN = re.compile(
    r"\b(?:"
    r"see|see also|reference|references|docs?|documentation|guide|handbook|example|"
    r"index|catalog|catalogue|list of|similar|related|alternative|inspired by|credit"
    r")\b",
    re.I,
)

EXPLICIT_SKILL_DOC_PATTERN = re.compile(r"(?i)(?:^|[/\\])(?:SKILL|skill)\.md(?:$|[#?\s`'\"<>)]|\|)")

RELATED_SKILL_METADATA_PATTERN = re.compile(
    r"\b(?:related[-_]skill|related[-_]skills|similar[-_]skills|enhances)\s*[:=]",
    re.I,
)

SEE_ALSO_METADATA_PATTERN = re.compile(r"\bsee[-_]also\s*[:=]", re.I)


@dataclass
class Finding:
    skill: str
    skill_id: str
    skill_name: str
    skill_repo: str
    skill_path: str
    kind: str
    ecosystem: str
    value: str
    source_file: str
    line: int
    evidence: str
    risks: list[str]


@dataclass
class SkillRecordSummary:
    skill_id: str
    skill_name: str
    repo: str
    path: str
    html_url: str
    packages: list[str]
    downloads: list[str]
    skill_refs: list[str]
    risky_patterns: list[str]


@dataclass(frozen=True)
class SkillIdentity:
    skill: str
    skill_id: str
    name: str
    repo: str
    path: str


# Adapted from SIT/SIT/tool/generate/meta/utils.py::ImportAnalyzer and
# pyfile_depends. The local adapter avoids importing the full SIT schema stack, 
# while preserving SIT's distinction between unconditional and conditional
# Python imports.
class SITStyleImportAnalyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.all_imports: list[tuple[str, int]] = []
        self.conditional_imports: list[tuple[str, int]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top_name = alias.name.split(".")[0]
            self.all_imports.append((top_name, node.lineno))
            if self.is_in_conditional(node):
                self.conditional_imports.append((top_name, node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module.split(".")[0] if node.module else None
        if module and node.level == 0:
            self.all_imports.append((module, node.lineno))
            if self.is_in_conditional(node):
                self.conditional_imports.append((module, node.lineno))
        self.generic_visit(node)

    def is_in_conditional(self, node: ast.AST) -> bool:
        parent = getattr(node, "parent", None)
        while parent:
            if isinstance(parent, (ast.If, ast.Try, ast.FunctionDef)):
                return True
            parent = getattr(parent, "parent", None)
        return False


def sit_style_pyfile_depends_from_code(source_code: str) -> tuple[list[str], list[str], dict[str, int]]:
    if "\x00" in source_code:
        source_code = source_code.replace("\x00", "")
    try:
        tree = ast.parse(source_code)
    except (SyntaxError, ValueError):
        return [], [], {}

    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node

    analyzer = SITStyleImportAnalyzer()
    analyzer.visit(tree)
    all_imports = sorted({name for name, _ in analyzer.all_imports})
    conditional_imports = sorted({name for name, _ in analyzer.conditional_imports})
    line_by_import: dict[str, int] = {}
    for name, line_no in analyzer.all_imports:
        line_by_import.setdefault(name, line_no)
    return all_imports, conditional_imports, line_by_import


def safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", text, re.S)
    if not match:
        return {}

    metadata: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if not line.strip() or line.startswith((" ", "\t", "-")):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and value:
            metadata[key] = value
    return metadata


def parse_frontmatter_lines(text: str) -> list[tuple[str, str, int, str]]:
    span = frontmatter_span(text)
    if not span:
        return []

    fm_text = text[span[0]:span[1]]
    lines = fm_text.splitlines()
    entries: list[tuple[str, str, int, str]] = []
    parent_key = ""
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped in {"---", ""} or stripped.startswith(("-", "#")):
            continue
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        normalized_key = key.strip().lower().replace("_", "-")
        if not normalized_key:
            continue
        if line[:1].isspace() and parent_key:
            normalized_key = f"{parent_key}.{normalized_key}"
        elif not line[:1].isspace():
            parent_key = normalized_key if not value.strip() else ""
        cleaned_value = value.strip().strip("'\"")
        if cleaned_value:
            entries.append((normalized_key, cleaned_value, idx, line))
    return entries


def metadata_reference_key(key: str) -> str | None:
    normalized = key.lower().replace("_", "-")
    leaf = normalized.rsplit(".", 1)[-1]
    if normalized in REFERENCE_METADATA_KEYS or leaf in REFERENCE_METADATA_KEYS:
        return normalized
    if leaf.startswith("sources-") or leaf.startswith("related-"):
        return normalized
    return None


def metadata_service_key(key: str) -> str | None:
    normalized = key.lower().replace("_", "-")
    leaf = normalized.rsplit(".", 1)[-1]
    if normalized in SERVICE_METADATA_KEYS or leaf in SERVICE_METADATA_KEYS:
        return normalized
    return None


def is_skill_reference_metadata_key(key: str) -> bool:
    leaf = key.lower().replace("_", "-").rsplit(".", 1)[-1]
    return leaf in {
        "enhances",
        "related-skill",
        "related-skills",
        "see-also",
        "similar-skills",
    }


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


def first_skill_text(skill_root: Path) -> str:
    if skill_root.is_file():
        return read_text(skill_root) or ""
    for marker in sorted(SKILL_MARKERS):
        marker_path = skill_root / marker
        if marker_path.exists():
            return read_text(marker_path) or ""
    return ""


def identify_skill(root: Path, skill_root: Path) -> SkillIdentity:
    rel_skill = safe_relative(skill_root, root)
    text = first_skill_text(skill_root)
    metadata = parse_frontmatter(text)
    name = metadata.get("name") or skill_name_from_path(skill_root)
    repo = metadata.get("repo") or repo_from_skillmd_filename(skill_root)
    path = metadata.get("path") or rel_skill
    readable = f"{repo}:{name}" if repo else f"{rel_skill}:{name}"
    return SkillIdentity(
        skill=rel_skill,
        skill_id=readable,
        name=name,
        repo=repo,
        path=path,
    )


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def discover_skill_roots(root: Path) -> list[Path]:
    if root.is_file():
        return [root]

    marked = []
    for marker in SKILL_MARKERS:
        marked.extend(p.parent for p in root.rglob(marker))
    roots = sorted(set(marked))
    if roots:
        return roots

    immediate_dirs = [p for p in root.iterdir() if p.is_dir()]
    if immediate_dirs:
        return sorted(immediate_dirs)
    markdown_files = [
        p for p in root.iterdir()
        if p.is_file() and (p.suffix.lower() in {".md", ".mdc"} or p.name in SKILL_MARKERS)
    ]
    if markdown_files:
        return sorted(markdown_files)
    return [root]


def iter_candidate_files(skill_root: Path) -> Iterable[Path]:
    for path in skill_root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "Cargo.lock", "go.sum"}:
            yield path
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {
            "requirements.txt",
            "Dockerfile",
            "Makefile",
            "go.mod",
            "pom.xml",
        }:
            yield path


def split_shell_args(raw: str) -> list[str]:
    """Parse one command argument tail without treating prose comments as deps."""
    try:
        return shlex.split(raw, comments=True, posix=True)
    except ValueError:
        fallback = re.split(r"\s+#", raw, maxsplit=1)[0]
        return re.split(r"\s+", fallback.strip())


def strip_wrapping(value: str) -> str:
    cleaned = value.strip().strip("`'\"")
    cleaned = cleaned.strip(",;")
    changed = True
    while changed:
        previous = cleaned
        cleaned = cleaned.strip().strip("`'\"")
        cleaned = cleaned.strip(",;")
        while cleaned and cleaned[0] in "([{":
            cleaned = cleaned[1:].strip()
        while cleaned and cleaned[-1] in ",.;)}":
            cleaned = cleaned[:-1].strip()
        if cleaned.endswith("]") and "[" not in cleaned:
            cleaned = cleaned[:-1].strip()
        cleaned = cleaned.strip().strip("`'\"")
        changed = cleaned != previous
    return cleaned


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        return ""
    return text[:max_len].strip("-")


def is_placeholder_value(value: str) -> bool:
    normalized = value.strip().strip("`'\"").lower()
    normalized = normalized.strip("<>[]{}()")
    if not normalized:
        return True
    if normalized in PLACEHOLDER_VALUES or normalized in PACKAGE_STOP_WORDS:
        return True
    if re.fullmatch(r"[\W_]+|\d+\.?", normalized):
        return True
    if any(marker in value for marker in ["${", "$(", "{{", "}}", "<", ">", "{", "}"]):
        return True
    if normalized.startswith(("your-", "my-", "example-", "sample-")):
        return True
    if normalized.endswith(("-name", "-url", "_url")):
        return True
    if "example.com" in normalized or "localhost" in normalized:
        return True
    return False


def is_valid_git_target(value: str) -> bool:
    if is_placeholder_value(value) or is_local_or_self_target(value):
        return False
    if value.startswith(("git@", "ssh://")):
        return not any(owner in value.lower() for owner in ["owner/", "user/", "username/", "you/"])
    if value.startswith(("http://", "https://")):
        return is_repo_url(value) or value.endswith(".git")
    return bool(re.fullmatch(r"[\w.-]+/[\w.-]+(?:\.git)?", value)) and not is_generic_repo_path(value)


def is_valid_docker_image(value: str) -> bool:
    if is_placeholder_value(value):
        return False
    if value.startswith("-") or value.startswith("$"):
        return False
    if value == "hello-world":
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?", value))


def is_valid_package_name(value: str, ecosystem: str) -> bool:
    if is_placeholder_value(value) or is_local_or_self_target(value):
        return False
    if value.startswith(("http://", "https://")):
        return ecosystem == "git" and is_valid_git_target(value)
    lowered = value.lower()
    if lowered in PACKAGE_STOP_WORDS:
        return False
    if ecosystem == "npm":
        if lowered in {"npm", "run", "scripts", "skills", "tsc"}:
            return False
        return bool(re.fullmatch(r"(?:@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9][A-Za-z0-9._-]*)(?:@[A-Za-z0-9._~^<>=+-]+)?", value))
    if ecosystem == "pypi":
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?(?:(?:==|!=|~=|>=|<=|>|<)[A-Za-z0-9.*+!_-]+)?", value))
    if ecosystem == "go":
        return bool(re.fullmatch(r"[\w.-]+(?:/[\w.-]+)+(?:@[\w.+-]+)?", value))
    if ecosystem == "cargo":
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*(?:@[\w.+-]+)?", value))
    if ecosystem == "php":
        return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?::[\w.*~^<>=+-]+)?", value))
    if ecosystem == "dotnet":
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:@[\w.+-]+)?", value))
    if ecosystem == "docker":
        return is_valid_docker_image(value)
    if ecosystem == "conda":
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*(?:[=<>!~]+[\w.*+-]+)?", value))
    if ecosystem == "git":
        return is_valid_git_target(value)
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*", value))


def split_packages(raw: str, ecosystem: str) -> list[str]:
    tokens = split_shell_args(raw)
    packages = []
    skip_next = False
    for token in tokens:
        if not token or skip_next:
            skip_next = False
            continue
        if token in {"install", "add", "require"}:
            continue
        if token in NO_VALUE_FLAGS:
            continue
        if token.startswith("-"):
            option_name = token.split("=", 1)[0]
            if token in OPTION_VALUE_FLAGS or option_name in OPTION_VALUE_FLAGS:
                skip_next = "=" not in token
            continue
        cleaned = strip_wrapping(token)
        if is_valid_package_name(cleaned, ecosystem):
            packages.append(cleaned)
    return packages


def normalize_url(value: str) -> str:
    return value.strip().strip("`'\"").rstrip("`.,;，。；、）】》")


def normalize_local_reference(value: str) -> str:
    ref = strip_wrapping(value).replace("\\", "/")
    ref = ref.split("#", 1)[0].split("?", 1)[0].strip()
    while ref.startswith("./"):
        ref = ref[2:].strip()
    return ref


def is_valid_local_doc_ref(value: str, evidence: str) -> bool:
    ref = normalize_local_reference(value)
    if not ref or is_placeholder_value(ref):
        return False
    if ref.startswith(("http://", "https://", "ssh://")):
        return False
    if any(token in ref for token in [" ", "\t", "${", "$(", "{{", "}}", "<", ">", "{", "}", "*", "?"]):
        return False
    path = Path(ref)
    if path.name.lower() == "skill.md":
        return False
    if path.suffix.lower() not in {".md", ".mdc"}:
        return False
    normalized = ref.lower().lstrip("./")
    if normalized.startswith(("references/", "reference/", "docs/", "doc/")):
        return True
    if "/" not in ref and not ref.startswith(("../", "./")):
        return False
    return LOCAL_DOC_CONTEXT_PATTERN.search(evidence) is not None


def is_placeholder_local_path(value: str) -> bool:
    normalized = normalize_local_reference(value).lower()
    if is_placeholder_value(normalized):
        return True
    if any(segment in normalized for segment in [
        "script_name",
        "script-name",
        "your_script",
        "your-script",
        "example_script",
        "sample_script",
    ]):
        return True
    path = Path(normalized)
    if path.stem in {"script", "tool", "file", "path", "name"}:
        return True
    return False


def is_valid_local_runtime_ref(value: str) -> bool:
    ref = normalize_local_reference(value)
    if not ref or is_placeholder_local_path(ref):
        return False
    if ref.startswith(("http://", "https://", "ssh://")):
        return False
    if any(token in ref for token in [" ", "\t", "${", "$(", "{{", "}}", "<", ">", "{", "}", "*", "?"]):
        return False
    path = Path(ref)
    if path.suffix.lower() not in {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1"}:
        return False
    return "/" in ref or ref.startswith(("./", "../"))


def is_valid_local_manifest_ref(value: str) -> bool:
    ref = normalize_local_reference(value)
    if not ref or is_placeholder_local_path(ref):
        return False
    if ref.startswith(("http://", "https://", "ssh://")):
        return False
    if any(token in ref for token in [" ", "\t", "${", "$(", "{{", "}}", "<", ">", "{", "}"]):
        return False
    name = Path(ref).name.lower()
    return name in {
        "requirements.txt",
        "requirements-dev.txt",
        "constraints.txt",
        "package.json",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "pnpm-lock.yaml",
        "yarn.lock",
        "package-lock.json",
        "bun.lockb",
    } or name.startswith("requirements-") and name.endswith(".txt")


def docker_run_image(raw: str) -> str | None:
    tokens = split_shell_args(raw)
    skip_next = False
    for token in tokens:
        if not token or skip_next:
            skip_next = False
            continue
        if token in NO_VALUE_FLAGS or re.fullmatch(r"-[itd]+", token):
            continue
        if token.startswith("-"):
            option_name = token.split("=", 1)[0]
            if token in OPTION_VALUE_FLAGS or option_name in OPTION_VALUE_FLAGS:
                skip_next = "=" not in token
            continue
        cleaned = strip_wrapping(token)
        if "=" in cleaned and "/" not in cleaned and ":" not in cleaned:
            continue
        if is_valid_docker_image(cleaned):
            return cleaned
    return None


def parsed_url(value: str):
    try:
        return urlparse(value)
    except ValueError:
        return None


def is_placeholder_url(value: str) -> bool:
    if any(marker in value for marker in ["${", "$(", "{{", "}}", "<", ">", "{", "}", "[", "]"]):
        return True
    parsed = parsed_url(value)
    if parsed is None or not parsed.scheme or not parsed.netloc:
        return True
    host = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    if host in {"artifact", "target", "localhost", "0.0.0.0", "::1"} or host.startswith("localhost:"):
        return True
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
        return True
    if host == "example.com" or host.endswith(".example.com") or host.endswith(".localhost"):
        return True
    if host.startswith(("your", "myapp", "test")) or host in {"app.com", "site.com", "shop.com"}:
        return True
    if any(token in path for token in ["video_id", "/xxx", "...", ":path"]):
        return True
    return False


def is_generic_repo_path(value: str) -> bool:
    parts = [part.removesuffix(".git").lower() for part in value.strip("/").split("/") if part]
    if len(parts) < 2:
        return True
    owner, repo = parts[0], parts[1]
    return owner in GENERIC_REPO_OWNERS or repo in GENERIC_REPO_SEGMENTS


def is_repo_url(value: str) -> bool:
    parsed = parsed_url(value)
    if parsed is None:
        return False
    host = (parsed.hostname or parsed.netloc).lower()
    if host not in REPO_HOSTS:
        return False
    segments = [segment for segment in parsed.path.strip("/").split("/") if segment]
    if len(segments) < 2:
        return False
    if is_generic_repo_path("/".join(segments[:2])):
        return False
    if len(segments) == 2 or segments[1].endswith(".git"):
        return True
    return segments[2] in {"releases", "archive"} or segments[-1].endswith(DOWNLOAD_FILE_EXTENSIONS)


def is_package_registry_url(value: str) -> bool:
    parsed = parsed_url(value)
    if parsed is None:
        return False
    host = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    if host not in PACKAGE_REGISTRY_HOSTS:
        return False
    if host == "www.npmjs.com":
        return path.startswith("/package/")
    if host == "pypi.org":
        return path.startswith("/project/")
    if host == "crates.io":
        return path.startswith("/crates/")
    if host == "rubygems.org":
        return path.startswith("/gems/")
    if host == "packagist.org":
        return path.startswith("/packages/")
    return True


def is_dependency_url(value: str, evidence: str, kind: str) -> bool:
    normalized = normalize_url(value)
    if is_placeholder_url(normalized):
        return False
    parsed = parsed_url(normalized)
    if parsed is None:
        return False
    path = parsed.path.lower()
    lower_evidence = evidence.lower()
    if re.search(r"\b(resources?|documentation|docs?|handbook|guide|article|alternative|credits?|attribution|original repository)\b", lower_evidence):
        return False
    if path.endswith(DOWNLOAD_FILE_EXTENSIONS):
        return True
    if parsed.netloc.lower() == "raw.githubusercontent.com":
        return True
    if is_repo_url(normalized) or is_package_registry_url(normalized):
        return re.search(r"\b(install|clone|download|dependency|dependencies|package|requires?)\b", lower_evidence) is not None
    if kind in {"curl", "wget", "powershell"}:
        if re.search(r"\b(install|bootstrap|setup)\b", lower_evidence):
            return True
        if re.search(r"\|\s*(bash|sh|zsh|python|python3|node)\b", lower_evidence):
            return True
    return False


def service_type_for_evidence(value: str, evidence: str) -> str:
    text = f"{value} {evidence}"
    parsed = parsed_url(value)
    if parsed is not None and parsed.path and re.search(r"(?:^|/)mcp(?:/|$)", parsed.path, re.I):
        return "mcp"
    for service_type, pattern in SERVICE_TYPE_PATTERNS:
        if pattern.search(text):
            return service_type
    return "service"


def has_service_url_context(evidence: str) -> bool:
    return SERVICE_URL_CONTEXT_PATTERN.search(evidence) is not None or SERVICE_HTTP_CLIENT_CONTEXT_PATTERN.search(evidence) is not None


def has_runtime_service_url_context(evidence: str) -> bool:
    return SERVICE_RUNTIME_URL_CONTEXT_PATTERN.search(evidence) is not None or SERVICE_HTTP_CLIENT_CONTEXT_PATTERN.search(evidence) is not None


def is_api_like_service_url(value: str, evidence: str) -> bool:
    parsed = parsed_url(value)
    host_path = ""
    if parsed is not None:
        host_path = f"{parsed.netloc} {parsed.path}"
    return re.search(r"(?:^|[./_-])(?:api|graphql|oauth)(?:[./_\s-]|$)|api\.", f"{host_path} {evidence}", re.I) is not None


def is_documentation_service_url(value: str) -> bool:
    parsed = parsed_url(value)
    if parsed is None:
        return False
    host = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    if host in DOCUMENTATION_URL_HOSTS:
        return True
    return any(segment in path for segment in ["/docs/", "/documentation/", "/reference/", "/guide/"])


def is_placeholder_service_url_allowed(value: str, evidence: str) -> bool:
    parsed = parsed_url(value)
    if parsed is None or not parsed.scheme or not parsed.netloc:
        return False
    host = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    if any(marker in value for marker in ["${", "$(", "{{", "}}", "<", ">", "{", "}", "[", "]"]):
        return SERVICE_RUNTIME_URL_CONTEXT_PATTERN.search(evidence) is not None or is_api_like_service_url(value, evidence)
    if host in {"artifact", "target"}:
        return is_api_like_service_url(value, evidence)
    if parsed.path and re.search(r"(?:^|/)mcp(?:/|$)", parsed.path, re.I):
        return True
    if host == "example.com" or host.endswith(".example.com"):
        return has_service_url_context(evidence) and is_api_like_service_url(value, evidence)
    if (
        host in {"localhost", "0.0.0.0", "::1"}
        or host.startswith("localhost:")
        or host.startswith("127.")
        or host.startswith("10.")
        or host.startswith("192.168.")
        or host.endswith(".localhost")
        or host.startswith(("your", "myapp", "test"))
        or host in {"app.com", "site.com", "shop.com"}
    ):
        return SERVICE_RUNTIME_URL_CONTEXT_PATTERN.search(evidence) is not None or is_api_like_service_url(value, evidence)
    if any(token in path for token in ["video_id", "/xxx", "...", ":path"]):
        return has_runtime_service_url_context(evidence)
    return False


def is_service_url(value: str, evidence: str) -> bool:
    normalized = normalize_url(value)
    if is_placeholder_url(normalized) and not is_placeholder_service_url_allowed(normalized, evidence):
        return False
    if is_dependency_url(normalized, evidence, "url"):
        return False
    if is_repo_url(normalized) and not has_runtime_service_url_context(evidence):
        return False
    parsed = parsed_url(normalized)
    if parsed is not None and parsed.netloc.lower() in {"github.com", "raw.githubusercontent.com"}:
        return False
    if parsed is not None and parsed.path and re.search(r"(?:^|/)mcp(?:/|$)", parsed.path, re.I):
        return True
    if is_documentation_service_url(normalized) and not has_runtime_service_url_context(evidence):
        return False
    if REFERENCE_URL_CONTEXT_PATTERN.search(evidence):
        if re.search(r"\bwebhooks?\b", evidence, re.I):
            return True
        if not has_runtime_service_url_context(evidence):
            return False
    if REFERENCE_URL_CONTEXT_PATTERN.search(evidence) and not has_service_url_context(evidence):
        return False
    return has_service_url_context(evidence)


def normalize_service_value(value: str) -> str:
    return strip_wrapping(value).strip().rstrip(".,;")


def normalize_service_label(value: str) -> str:
    text = normalize_service_value(value).lower()
    text = re.sub(r"^(?:the|a|an)\s+", "", text)
    text = re.sub(r"[^a-z0-9@./:_-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text


def is_valid_service_label(value: str) -> bool:
    label = normalize_service_label(value)
    if not label or label in SERVICE_NAME_STOP_WORDS:
        return False
    if len(label) < 3:
        return False
    if is_placeholder_value(label):
        return False
    return True


def service_value_from_api_key(token: str) -> str | None:
    provider = normalize_service_label(token.strip("_"))
    if not is_valid_service_label(provider):
        return None
    return f"{provider}-api"


def is_valid_mcp_service_label(value: str) -> bool:
    label = normalize_service_label(value)
    if not label:
        return False
    if len(label) < 3:
        return False
    if label in MCP_SERVICE_BOUNDARY_WORDS:
        return True
    if label in SERVICE_NAME_STOP_WORDS:
        return False
    if is_placeholder_value(label):
        return False
    return True


def mcp_service_values(evidence: str) -> list[str]:
    values: list[str] = []
    for match in MCP_TOOL_PATTERN.finditer(evidence):
        candidate = normalize_service_label(match.group(1))
        if is_valid_mcp_service_label(candidate):
            values.append(f"mcp:{candidate}")
    for pattern in (MCP_SERVER_DECL_PATTERN, MCP_NAMED_SERVER_PATTERN, MCP_SERVER_BOUNDARY_PATTERN, MCP_PACKAGE_PATTERN):
        for match in pattern.finditer(evidence):
            candidate = normalize_service_label(match.group(1))
            if is_valid_mcp_service_label(candidate):
                values.append(f"mcp:{candidate}")
    return compact_values(values, limit=10)


def candidate_skill_refs(raw: str, evidence: str) -> list[str]:
    raw = raw.strip().strip("[]")
    pieces = re.split(r"\s*,\s*|\s*;\s*", raw)
    candidates: list[str] = []
    for piece in pieces:
        piece = re.split(r"\s+[—–]\s+|\s+-\s+", piece, maxsplit=1)[0]
        value = strip_wrapping(piece)
        value = value.lstrip("-* ").strip()
        if is_valid_skill_ref(value, evidence):
            candidates.append(value)
    return candidates


def normalize_skill_reference_value(value: str) -> str:
    ref = strip_wrapping(value)
    ref = ref.replace("\\", "/")
    ref = ref.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    lower = ref.lower()
    if lower.endswith("/skill.md"):
        ref = ref[: -len("/skill.md")]
    elif lower.endswith((".md", ".mdc")):
        ref = Path(ref).stem
    if "/" in ref:
        ref = ref.rsplit("/", 1)[-1]
    return slugify(ref, max_len=120)


def is_valid_skill_ref(value: str, evidence: str) -> bool:
    if not value or is_placeholder_value(value):
        return False
    lower = value.lower()
    evidence_lower = evidence.lower()
    if lower in NON_SKILL_REF_VALUES or lower in SCHEMA_SKILL_REF_VALUES:
        return False
    if CONFIG_SKILL_REF_PATTERN.search(value):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", value):
        return False
    if lower in SIMPLE_SKILL_STOP_WORDS or value.startswith(("#", "|", "```")):
        return False
    if any(token in value for token in [" ", "\t", ":", "=", "*/"]):
        return False
    normalized_path = value.replace("\\", "/").lower()
    suffix = Path(normalized_path).suffix
    if suffix in NON_SKILL_REF_SUFFIXES:
        return False
    if value.startswith(("http://", "https://")):
        return bool(re.search(r"(^|/)(?:skills?|\.claude/skills|\.cursor/rules)/", value, re.I)) or re.search(r"/skill\.md$", value, re.I) is not None
    if re.search(r"(^|/)(?:skills?|\.claude/skills|\.cursor/rules)/.+/(?:SKILL|skill)\.md$", value):
        return True
    if re.search(r"(^|/)skill\.md$", value, re.I):
        return True
    if "/references/" in normalized_path or normalized_path.endswith(("/reference.md", "/references.md")):
        return False
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,63}", value):
        return False
    if RELATED_SKILL_METADATA_PATTERN.search(evidence):
        return True
    if "-" in value or "_" in value or "." in value:
        return True
    return bool(re.search(rf"\b{re.escape(value)}\b\s+skill\b", evidence_lower))


def is_recordable_skill_ref_context(evidence: str) -> bool:
    lower = evidence.lower()
    has_explicit_skill_doc = EXPLICIT_SKILL_DOC_PATTERN.search(evidence) is not None
    if re.search(r"\b(?:skills?|requires?|dependencies?)\s*[:=]", lower):
        return True
    if RELATED_SKILL_METADATA_PATTERN.search(evidence):
        return True
    if SEE_ALSO_METADATA_PATTERN.search(evidence):
        return True
    if has_explicit_skill_doc:
        return True
    has_dependency_context = SKILL_DEPENDENCY_CONTEXT_PATTERN.search(lower) is not None
    has_reference_only_context = SKILL_REFERENCE_ONLY_CONTEXT_PATTERN.search(lower) is not None
    if has_reference_only_context and not has_dependency_context:
        return True
    return has_dependency_context


def is_dependency_skill_ref_context(evidence: str) -> bool:
    return is_recordable_skill_ref_context(evidence)


def is_commandish_line(line: str) -> bool:
    stripped = line.strip().strip("`")
    stripped = re.sub(r"^\s*(?:[-*]|\d+[.)])\s*", "", stripped).strip()
    stripped = stripped.removeprefix("$ ").removeprefix("> ").strip()
    return bool(re.match(
        r"^(?:sudo\s+)?(?:curl|wget|chmod|base64|eval|iwr|Invoke-WebRequest|Invoke-Expression|python3?|node|bash|sh|zsh)\b",
        stripped,
        re.I,
    )) or bool(re.search(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh|python|python3|node)\b", stripped, re.I))


def is_shell_code_block(language: str, code: str) -> bool:
    if language in {"bash", "sh", "shell", "zsh", "console", "terminal"}:
        return True
    if language:
        return False
    for line in code.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if is_commandish_line(stripped):
            return True
        if any(pattern.search(stripped) for _, pattern in INSTALL_PATTERNS):
            return True
        if DOCKER_RUN_PATTERN.search(stripped):
            return True
        if any(pattern.search(stripped) for pattern in LOCAL_MANIFEST_REF_PATTERNS):
            return True
    return False


LINE_BREAK_PATTERN = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")


def line_break_count(text: str, start: int = 0, end: int | None = None) -> int:
    return sum(1 for _ in LINE_BREAK_PATTERN.finditer(text, start, len(text) if end is None else end))


def line_number(text: str, offset: int) -> int:
    return line_break_count(text, 0, offset) + 1


def line_at_offset(text: str, offset: int) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    line_no = line_number(text, offset)
    return lines[line_no - 1]


def blank_preserving_lines(value: str) -> str:
    return "\n" * line_break_count(value)


def frontmatter_span(text: str) -> tuple[int, int] | None:
    if not text.startswith("---"):
        return None
    match = re.match(r"^---\s*\n.*?\n---\s*(?:\n|$)", text, re.S)
    if not match:
        return None
    return match.span()


def iter_code_blocks(text: str) -> Iterable[tuple[str, str, int, tuple[int, int]]]:
    pattern = re.compile(r"^```[ \t]*([A-Za-z0-9_+.-]*)[^\n]*\n(.*?)^```[ \t]*$", re.M | re.S)
    for match in pattern.finditer(text):
        language = (match.group(1) or "").strip().lower()
        code = match.group(2)
        start_line = line_number(text, match.start(2))
        yield language, code, start_line, match.span()


def mask_ranges(text: str, ranges: Iterable[tuple[int, int]]) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in sorted(ranges):
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(blank_preserving_lines(text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def is_non_dependency_skill_metadata_line(line: str) -> bool:
    key, sep, _ = line.strip().partition(":")
    if not sep:
        return False
    normalized_key = key.strip().lower().replace("_", "-")
    return normalized_key in {
        "related-skill",
        "related-skills",
        "enhances",
        "similar-skills",
        "see-also",
    }


def npm_package_from_module_spec(value: str) -> str | None:
    spec = value.strip()
    if not spec or spec.startswith((".", "/", "#")):
        return None
    if spec.startswith("node:"):
        return None
    if any(token in spec for token in ["${", "$(", "{{", "}}", "<", ">"]):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        if len(parts) < 2:
            return None
        package = "/".join(parts[:2])
    else:
        package = spec.split("/", 1)[0]
    if package in NODE_BUILTIN_MODULES:
        return None
    if is_valid_package_name(package, "npm"):
        return package
    return None


def pypi_package_from_module_name(value: str) -> str | None:
    top_level = value.split(".", 1)[0].strip()
    if not top_level or top_level in PYTHON_STDLIB_MODULES:
        return None
    if sit_get_packages is not None:
        try:
            packages = sit_get_packages(top_level)
        except Exception:
            packages = None
        if packages:
            for package in sorted(packages):
                if is_valid_package_name(package, "pypi"):
                    return package
    package = PYTHON_IMPORT_ALIASES.get(top_level, top_level)
    if is_valid_package_name(package, "pypi"):
        return package
    return None


def scan_javascript_imports(code: str) -> Iterable[tuple[str, int, str]]:
    for match in JS_IMPORT_PATTERN.finditer(code):
        module_spec = next((group for group in match.groups() if group), "")
        package = npm_package_from_module_spec(module_spec)
        if package:
            yield package, line_number(code, match.start()), line_at_offset(code, match.start())


def scan_python_imports(code: str) -> Iterable[tuple[str, int, str]]:
    lines = code.splitlines()
    fallback_imports, _, line_by_import = sit_style_pyfile_depends_from_code(code)

    sit_imports: list[str] | None = None
    if sit_pyfile_depends is not None:
        temp_path = ""
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".py", encoding="utf-8", delete=False) as temp_file:
                temp_file.write(code)
                temp_path = temp_file.name
            sit_imports, _ = sit_pyfile_depends(temp_path)
        except Exception:
            sit_imports = None
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except OSError:
                    pass

    import_names = sit_imports if sit_imports is not None else fallback_imports
    for imported_name in import_names:
        package = pypi_package_from_module_name(imported_name)
        if not package:
            continue
        line_no = line_by_import.get(imported_name, 1)
        evidence = lines[line_no - 1] if 0 < line_no <= len(lines) else imported_name
        yield package, line_no, evidence


def code_block_ecosystem(language: str, source: Path) -> str | None:
    if language in {"js", "jsx", "javascript", "mjs", "cjs", "ts", "tsx", "typescript"}:
        return "npm"
    if language in {"py", "python", "python3"}:
        return "pypi"
    if not language:
        if source.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            return "npm"
        if source.suffix.lower() == ".py":
            return "pypi"
    return None


def is_reference_package_line(line: str, in_alternative_section: bool) -> bool:
    lower = line.lower()
    return in_alternative_section or "(alternative" in lower or " alternative" in lower


def is_self_skill_install_line(line: str) -> bool:
    normalized = line.strip()
    return any(pattern.search(normalized) for pattern in SELF_SKILL_INSTALL_PATTERNS)


def is_local_or_self_target(value: str) -> bool:
    normalized = value.strip().strip("'\"")
    return normalized in {".", "./", "..", "../"} or normalized.startswith(("./", "../"))


def is_unpinned_install_line(line: str) -> bool:
    if is_self_skill_install_line(line):
        return False
    lower = line.lower()
    if not any(marker in lower for marker in [
        "pip install",
        "pip3 install",
        "python -m pip install",
        "python3 -m pip install",
        "pipx install",
        "npm install",
        "npm i ",
        "yarn add",
        "pnpm add",
        "bun add",
        "go install",
        "go get",
        "cargo install",
        "cargo add",
        "apt install",
        "apt-get install",
        "brew install",
    ]):
        return False
    return PINNED_VERSION_PATTERN.search(line) is None


def risks_for_line(line: str, value: str) -> list[str]:
    risks = []
    for name, pattern in RISK_RULES:
        if pattern.search(line):
            risks.append(name)
    if value.startswith(("http://", "https://")) and "sha256" not in line.lower():
        risks.append("remote-resource-no-visible-hash")
    if is_unpinned_install_line(line):
        risks.append("version-not-clearly-pinned")
    return sorted(set(risks))


def add_finding(findings: list[Finding], skill_root: Path, root: Path, kind: str, ecosystem: str,
                value: str, source: Path, line: int, evidence: str) -> None:
    identity = identify_skill(root, skill_root)
    if kind in {"skill_reference", "skill_reference_note"} and normalize_skill_reference_value(value) == slugify(identity.name, max_len=120):
        return
    if kind in {"external_reference", "metadata_reference", "package_reference", "service_call", "skill_reference_note"}:
        risks = []
    else:
        risks = risks_for_line(evidence, value)
    findings.append(
        Finding(
            skill=identity.skill,
            skill_id=identity.skill_id,
            skill_name=identity.name,
            skill_repo=identity.repo,
            skill_path=identity.path,
            kind=kind,
            ecosystem=ecosystem,
            value=value.strip(),
            source_file=safe_relative(source, root),
            line=line,
            evidence=evidence.strip()[:500],
            risks=risks,
        )
    )


def scan_text_file(root: Path, skill_root: Path, path: Path, findings: list[Finding]) -> None:
    text = read_text(path)
    if text is None:
        return

    code_blocks = list(iter_code_blocks(text))
    code_ranges = [span for _, _, _, span in code_blocks]
    fm_span = frontmatter_span(text)
    dependency_mask_ranges = code_ranges + ([fm_span] if fm_span else [])
    dependency_text = mask_ranges(text, dependency_mask_ranges)
    skill_ref_text = mask_ranges(text, code_ranges)

    seen_download_urls: set[str] = set()
    seen_local_resources: set[str] = set()
    seen_code_imports: set[tuple[str, str]] = set()
    seen_package_refs: set[str] = set()
    seen_external_refs: set[str] = set()
    seen_metadata_refs: set[tuple[str, str]] = set()
    seen_services: set[tuple[str, str]] = set()

    def add_service(value: str, service_type: str, line_no: int, evidence: str) -> None:
        normalized = normalize_service_value(value)
        if not normalized:
            return
        key = (service_type, normalized.lower())
        if key in seen_services:
            return
        seen_services.add(key)
        add_finding(findings, skill_root, root, "service_call", service_type, normalized, path, line_no, evidence)

    for key, value, line_no, evidence in parse_frontmatter_lines(text):
        service_key = metadata_service_key(key)
        if service_key:
            for match in SERVICE_URL_PATTERN.finditer(value):
                normalized_url = normalize_url(match.group(0))
                if is_service_url(normalized_url, evidence):
                    add_service(normalized_url, service_type_for_evidence(normalized_url, evidence), line_no, evidence)
            for service_value in mcp_service_values(f"{key}: {value}"):
                add_service(service_value, "mcp", line_no, evidence)

        reference_key = metadata_reference_key(key)
        if not reference_key:
            continue
        if is_skill_reference_metadata_key(reference_key):
            for skill_ref in candidate_skill_refs(value, evidence):
                add_finding(findings, skill_root, root, "skill_reference_note", "skill", skill_ref, path, line_no, evidence)
            continue
        metadata_key = (reference_key, value)
        if metadata_key in seen_metadata_refs:
            continue
        seen_metadata_refs.add(metadata_key)
        add_finding(findings, skill_root, root, "metadata_reference", "metadata", f"{reference_key}: {value}", path, line_no, evidence)

    def scan_install_patterns(content: str, base_line: int = 1) -> None:
        for pattern_ecosystem, pattern in INSTALL_PATTERNS:
            for match in pattern.finditer(content):
                line_no = base_line + line_number(content, match.start()) - 1
                evidence = line_at_offset(content, match.start()) or match.group(0)
                if is_self_skill_install_line(evidence):
                    continue
                packages = split_packages(match.group(1), pattern_ecosystem)
                for package in packages:
                    if is_local_or_self_target(package):
                        continue
                    add_finding(findings, skill_root, root, "install_command", pattern_ecosystem, package, path, line_no, evidence)
                    if pattern_ecosystem in {"git", "docker"}:
                        if package.startswith(("http://", "https://")):
                            seen_download_urls.add(normalize_url(package))
                        add_finding(findings, skill_root, root, "remote_resource", pattern_ecosystem, package, path, line_no, evidence)

    def add_local_resource(value: str, ecosystem: str, line_no: int, evidence: str) -> None:
        ref = normalize_local_reference(value)
        if ref in seen_local_resources:
            return
        seen_local_resources.add(ref)
        add_finding(findings, skill_root, root, "local_resource", ecosystem, ref, path, line_no, evidence)

    def scan_local_runtime_resources(content: str, base_line: int = 1) -> None:
        for ecosystem, pattern in LOCAL_RUNTIME_COMMAND_PATTERNS:
            for match in pattern.finditer(content):
                line_no = base_line + line_number(content, match.start()) - 1
                evidence = line_at_offset(content, match.start()) or match.group(0)
                ref = normalize_local_reference(match.group(1))
                if not is_valid_local_runtime_ref(ref):
                    continue
                add_local_resource(ref, ecosystem, line_no, evidence)

        for match in LOCAL_EXECUTABLE_REF_PATTERN.finditer(content):
            line_no = base_line + line_number(content, match.start()) - 1
            evidence = line_at_offset(content, match.start()) or match.group(0)
            ref = normalize_local_reference(match.group(1))
            if not is_valid_local_runtime_ref(ref):
                continue
            add_local_resource(ref, "executable-file", line_no, evidence)

    def scan_local_manifest_resources(content: str, base_line: int = 1) -> None:
        for pattern in LOCAL_MANIFEST_REF_PATTERNS:
            for match in pattern.finditer(content):
                line_no = base_line + line_number(content, match.start()) - 1
                evidence = line_at_offset(content, match.start()) or match.group(0)
                if is_self_skill_install_line(evidence):
                    continue
                if match.groups():
                    refs = [normalize_local_reference(group) for group in match.groups() if group]
                elif re.search(r"\bpoetry\s+install\b", match.group(0), re.I):
                    refs = ["pyproject.toml"]
                else:
                    refs = ["package.json"]
                for ref in refs:
                    if not is_valid_local_manifest_ref(ref):
                        continue
                    add_local_resource(ref, "manifest", line_no, evidence)

    def scan_docker_run_resources(content: str, base_line: int = 1) -> None:
        lines = content.splitlines()
        index = 0
        while index < len(lines):
            start_index = index
            command = lines[index].strip()
            index += 1
            continuation_count = 0
            while command.rstrip().endswith("\\") and index < len(lines) and continuation_count < 8:
                command = command.rstrip()[:-1].rstrip() + " " + lines[index].strip()
                index += 1
                continuation_count += 1
            for match in DOCKER_RUN_PATTERN.finditer(command):
                image = docker_run_image(match.group(1))
                if not image:
                    continue
                line_no = base_line + start_index
                add_finding(findings, skill_root, root, "remote_resource", "docker", image, path, line_no, command)

    scan_install_patterns(dependency_text)
    scan_local_runtime_resources(dependency_text)
    scan_local_manifest_resources(dependency_text)
    scan_docker_run_resources(dependency_text)
    for language, code, start_line, _ in code_blocks:
        if is_shell_code_block(language, code):
            scan_install_patterns(code, start_line)
            scan_local_runtime_resources(code, start_line)
            scan_local_manifest_resources(code, start_line)
            scan_docker_run_resources(code, start_line)

    code_units: list[tuple[str, str, int]] = [(language, code, start_line) for language, code, start_line, _ in code_blocks]
    if not code_units and path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"}:
        code_units.append(("", text, 1))

    for language, code, start_line in code_units:
        ecosystem = code_block_ecosystem(language, path)
        if ecosystem == "npm":
            imports = scan_javascript_imports(code)
        elif ecosystem == "pypi":
            imports = scan_python_imports(code)
        else:
            continue
        for package, relative_line, evidence in imports:
            key = (ecosystem, package)
            if key in seen_code_imports:
                continue
            seen_code_imports.add(key)
            add_finding(findings, skill_root, root, "code_import", ecosystem, package, path, start_line + relative_line - 1, evidence)

    in_alternative_section = False
    for line_no, line in enumerate(dependency_text.splitlines(), start=1):
        stripped = line.strip()
        lower = stripped.lower()
        if re.match(r"^#{1,6}\s+", stripped):
            in_alternative_section = "alternative libraries" in lower
        elif "alternative libraries" in lower:
            in_alternative_section = True
        elif in_alternative_section and not stripped:
            in_alternative_section = False

        if not is_reference_package_line(line, in_alternative_section):
            continue

        candidates = re.findall(r"`([^`]+)`", line)
        candidates.extend(label for label, _ in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", line))
        for candidate in candidates:
            package = strip_wrapping(candidate)
            if package in seen_package_refs:
                continue
            if not is_valid_package_name(package, "npm"):
                continue
            seen_package_refs.add(package)
            add_finding(findings, skill_root, root, "package_reference", "npm", package, path, line_no, line)

    for download_kind, pattern in DOWNLOAD_PATTERNS:
        for match in pattern.finditer(dependency_text):
            value = match.group(1) if match.groups() else match.group(0)
            line_no = line_number(dependency_text, match.start())
            evidence = line_at_offset(dependency_text, match.start()) or value
            if is_self_skill_install_line(evidence):
                continue
            normalized_url = normalize_url(value)
            if normalized_url in seen_download_urls:
                continue
            if not is_dependency_url(normalized_url, evidence, download_kind):
                continue
            seen_download_urls.add(normalized_url)
            add_finding(findings, skill_root, root, "remote_resource", download_kind, normalized_url, path, line_no, evidence)

    for _, pattern in DOWNLOAD_PATTERNS:
        for match in pattern.finditer(dependency_text):
            value = match.group(1) if match.groups() else match.group(0)
            normalized_url = normalize_url(value)
            if normalized_url in seen_download_urls or normalized_url in seen_external_refs:
                continue
            line_no = line_number(dependency_text, match.start())
            evidence = line_at_offset(dependency_text, match.start()) or value
            if not REFERENCE_URL_CONTEXT_PATTERN.search(evidence):
                continue
            if is_placeholder_url(normalized_url):
                continue
            seen_external_refs.add(normalized_url)
            add_finding(findings, skill_root, root, "external_reference", "url", normalized_url, path, line_no, evidence)

    for match in SERVICE_URL_PATTERN.finditer(text):
        normalized_url = normalize_url(match.group(0))
        line_no = line_number(text, match.start())
        evidence = line_at_offset(text, match.start()) or normalized_url
        if not is_service_url(normalized_url, evidence):
            continue
        add_service(normalized_url, service_type_for_evidence(normalized_url, evidence), line_no, evidence)

    for line_no, line in enumerate(text.splitlines(), start=1):
        if is_self_skill_install_line(line):
            continue
        for service_value in mcp_service_values(line):
            add_service(service_value, "mcp", line_no, line)
        for match in KNOWN_API_SERVICE_PATTERN.finditer(line):
            add_service(f"{match.group(1).lower().replace(' ', '-')}-api", "api", line_no, line)
        for match in GENERIC_API_SERVICE_PATTERN.finditer(line):
            label = normalize_service_label(match.group(1))
            if not is_valid_service_label(label):
                continue
            add_service(f"{label}-api", "api", line_no, line)
        for match in API_KEY_SERVICE_PATTERN.finditer(line):
            service_value = service_value_from_api_key(match.group(1))
            if service_value:
                add_service(service_value, "api", line_no, line)

    for pattern in SKILL_REF_PATTERNS:
        for match in pattern.finditer(skill_ref_text):
            line_no = line_number(skill_ref_text, match.start())
            evidence = line_at_offset(skill_ref_text, match.start()) or match.group(1)
            if is_self_skill_install_line(evidence):
                continue
            if not is_recordable_skill_ref_context(evidence):
                continue
            for value in candidate_skill_refs(match.group(1), evidence):
                add_finding(findings, skill_root, root, "skill_reference", "skill", value, path, line_no, evidence)

    for line_no, line in enumerate(dependency_text.splitlines(), start=1):
        if is_self_skill_install_line(line):
            continue
        for pattern in LOCAL_MARKDOWN_REF_PATTERNS:
            for match in pattern.finditer(line):
                ref = normalize_local_reference(match.group(1))
                if ref in seen_local_resources:
                    continue
                if not is_valid_local_doc_ref(ref, line):
                    continue
                add_local_resource(ref, "file", line_no, line)

    for name, pattern in RISK_RULES:
        for match in pattern.finditer(dependency_text):
            line_no = line_number(dependency_text, match.start())
            evidence = line_at_offset(dependency_text, match.start()) or match.group(0)
            if not is_commandish_line(evidence):
                continue
            add_finding(findings, skill_root, root, "risky_command_pattern", "shell", name, path, line_no, evidence)


def compact_values(values: Iterable[str], limit: int = 20) -> list[str]:
    seen = set()
    compact = []
    for value in values:
        value = value.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        compact.append(value)
        if len(compact) >= limit:
            break
    return compact


def scan_skill_content(content: str) -> dict[str, list[str]]:
    packages = []
    downloads = []
    skill_refs = []
    risky_patterns = []
    seen_download_urls: set[str] = set()

    for ecosystem, pattern in INSTALL_PATTERNS:
        for match in pattern.finditer(content):
            evidence = line_at_offset(content, match.start()) or match.group(0)
            if is_self_skill_install_line(evidence):
                continue
            parsed_packages = split_packages(match.group(1), ecosystem)
            for package in parsed_packages:
                if is_local_or_self_target(package):
                    continue
                packages.append(f"{ecosystem}:{package}")
            if parsed_packages and is_unpinned_install_line(evidence):
                risky_patterns.append("version-not-clearly-pinned")
            if ecosystem in {"git", "docker"}:
                for package in parsed_packages:
                    if package.startswith(("http://", "https://")):
                        seen_download_urls.add(normalize_url(package))
                    downloads.append(f"{ecosystem}:{package}")

    for download_kind, pattern in DOWNLOAD_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            evidence = line_at_offset(content, match.start()) or value
            if is_self_skill_install_line(evidence):
                continue
            normalized_url = normalize_url(value)
            if normalized_url in seen_download_urls:
                continue
            if not is_dependency_url(normalized_url, evidence, download_kind):
                continue
            seen_download_urls.add(normalized_url)
            downloads.append(f"{download_kind}:{normalized_url}")

    for pattern in SKILL_REF_PATTERNS:
        for match in pattern.finditer(content):
            evidence = line_at_offset(content, match.start()) or match.group(1)
            if is_self_skill_install_line(evidence):
                continue
            if not is_recordable_skill_ref_context(evidence):
                continue
            for value in candidate_skill_refs(match.group(1), evidence):
                skill_refs.append(value)

    for line in content.splitlines():
        if is_self_skill_install_line(line):
            continue
        if not is_commandish_line(line):
            continue
        for name, pattern in RISK_RULES:
            if pattern.search(line):
                risky_patterns.append(name)

    return {
        "packages": compact_values(packages),
        "downloads": compact_values(downloads),
        "skill_refs": compact_values(skill_refs),
        "risky_patterns": compact_values(risky_patterns),
    }


def record_identity(row: dict) -> str:
    content_hash = str(row.get("content_hash") or "")
    repo = str(row.get("repo") or "unknown-repo")
    path = str(row.get("path") or "unknown-path")
    short_hash = content_hash[:16] if content_hash else "nohash"
    return f"{repo}:{path}:{short_hash}"


def scan_hf_dataset(dataset_name: str, split: str, limit: int | None, max_examples: int | None) -> int:
    try:
        from datasets import load_dataset
    except ImportError:
        print("Missing dependency: datasets. Install it with `pip install datasets`.", file=sys.stderr)
        return 2

    dataset = load_dataset(dataset_name, split=split)
    if limit is not None:
        dataset = dataset.select(range(min(limit, len(dataset))))

    summaries: list[SkillRecordSummary] = []
    total = 0
    with_any_dependency = 0
    with_packages = 0
    with_downloads = 0
    with_skill_refs = 0
    with_risky_patterns = 0

    package_ecosystem_counts: dict[str, int] = {}
    download_pattern_counts: dict[str, int] = {}
    risky_pattern_counts: dict[str, int] = {}

    from tqdm import tqdm
    
    for row in tqdm(dataset, desc="Scanning skills"):
        total += 1
        content = str(row.get("content") or "")
        extracted = scan_skill_content(content)

        has_packages = bool(extracted["packages"])
        has_downloads = bool(extracted["downloads"])
        has_skill_refs = bool(extracted["skill_refs"])
        has_risky = bool(extracted["risky_patterns"])

        if has_packages or has_downloads or has_skill_refs or has_risky:
            with_any_dependency += 1
        if has_packages:
            with_packages += 1
        if has_downloads:
            with_downloads += 1
        if has_skill_refs:
            with_skill_refs += 1
        if has_risky:
            with_risky_patterns += 1

        for item in extracted["packages"]:
            ecosystem = item.split(":", 1)[0]
            package_ecosystem_counts[ecosystem] = package_ecosystem_counts.get(ecosystem, 0) + 1
        for item in extracted["downloads"]:
            kind = item.split(":", 1)[0]
            download_pattern_counts[kind] = download_pattern_counts.get(kind, 0) + 1
        for item in extracted["risky_patterns"]:
            risky_pattern_counts[item] = risky_pattern_counts.get(item, 0) + 1

        if (has_packages or has_downloads or has_skill_refs or has_risky) and (
            max_examples is None or len(summaries) < max_examples
        ):
            summaries.append(
                SkillRecordSummary(
                    skill_id=f"{(total-1):06d}:{record_identity(row)}",
                    skill_name=parse_frontmatter(content).get("name") or "",
                    repo=str(row.get("repo") or ""),
                    path=str(row.get("path") or ""),
                    html_url=str(row.get("html_url") or ""),
                    packages=extracted["packages"],
                    downloads=extracted["downloads"],
                    skill_refs=extracted["skill_refs"],
                    risky_patterns=extracted["risky_patterns"],
                )
            )

    def pct(count: int) -> str:
        return f"{count} ({count / total * 100:.2f}%)" if total else "0 (0.00%)"

    print(f"Dataset: {dataset_name} [{split}]")
    print(f"Scanned skills: {total}")
    print(f"Skills with any dependency signal: {pct(with_any_dependency)}")
    print(f"Skills with package install signals: {pct(with_packages)}")
    print(f"Skills with download/remote-resource signals: {pct(with_downloads)}")
    print(f"Skills with other-skill reference signals: {pct(with_skill_refs)}")
    print(f"Skills with risky command patterns: {pct(with_risky_patterns)}")

    print("\nPackage ecosystem findings:")
    for key, value in sorted(package_ecosystem_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"- {key}: {value}")

    print("\nDownload-related findings:")
    for key, value in sorted(download_pattern_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"- {key}: {value}")

    print("\nRisky command pattern findings:")
    for key, value in sorted(risky_pattern_counts.items(), key=lambda item: item[1], reverse=True):
        print(f"- {key}: {value}")

    example_label = "all" if max_examples is None else str(max_examples)
    print(f"\nExample skills with dependency signals (up to {example_label}):")
    for summary in summaries:
        print(f"\n- {summary.skill_id}")
        if summary.skill_name:
            print(f"  name: {summary.skill_name}")
        if summary.html_url:
            print(f"  url: {summary.html_url}")
        if summary.packages:
            print(f"  packages: {', '.join(summary.packages)}")
        if summary.downloads:
            print(f"  downloads: {', '.join(summary.downloads)}")
        if summary.skill_refs:
            print(f"  skill_refs: {', '.join(summary.skill_refs)}")
        if summary.risky_patterns:
            print(f"  risky_patterns: {', '.join(summary.risky_patterns)}")

    return 0


def scan_package_json(root: Path, skill_root: Path, path: Path, findings: list[Finding]) -> None:
    text = read_text(path)
    if text is None:
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            add_finding(findings, skill_root, root, "manifest_dependency", "npm", f"{name}@{version}", path, 1, section)


def scan_requirements(root: Path, skill_root: Path, path: Path, findings: list[Finding]) -> None:
    text = read_text(path)
    if text is None:
        return
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        if not is_valid_package_name(stripped, "pypi"):
            continue
        add_finding(findings, skill_root, root, "manifest_dependency", "pypi", stripped, path, idx, line)


def scan_pyproject(root: Path, skill_root: Path, path: Path, findings: list[Finding]) -> None:
    if tomllib is None:
        return
    try:
        data = tomllib.loads(read_text(path) or "")
    except Exception:
        return

    project = data.get("project", {})
    for dep in project.get("dependencies", []) if isinstance(project, dict) else []:
        dep_value = str(dep)
        if is_valid_package_name(dep_value, "pypi"):
            add_finding(findings, skill_root, root, "manifest_dependency", "pypi", dep_value, path, 1, "project.dependencies")

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
    if isinstance(deps, dict):
        for name, version in deps.items():
            if name.lower() == "python":
                continue
            if is_valid_package_name(name, "pypi"):
                add_finding(findings, skill_root, root, "manifest_dependency", "pypi", f"{name} {version}", path, 1, "tool.poetry.dependencies")


def scan_go_mod(root: Path, skill_root: Path, path: Path, findings: list[Finding]) -> None:
    text = read_text(path)
    if text is None:
        return
    for idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("require "):
            add_finding(findings, skill_root, root, "manifest_dependency", "go", stripped.removeprefix("require ").strip(), path, idx, line)
        elif re.match(r"^[\w./-]+\s+v\d", stripped):
            add_finding(findings, skill_root, root, "manifest_dependency", "go", stripped, path, idx, line)


def scan_toml_manifest(root: Path, skill_root: Path, path: Path, findings: list[Finding]) -> None:
    if path.name == "pyproject.toml":
        scan_pyproject(root, skill_root, path, findings)
        return
    if path.name != "Cargo.toml" or tomllib is None:
        return
    try:
        data = tomllib.loads(read_text(path) or "")
    except Exception:
        return
    for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            add_finding(findings, skill_root, root, "manifest_dependency", "cargo", f"{name} {version}", path, 1, section)


def scan_skill(root: Path, skill_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if skill_root.is_file():
        scan_text_file(root, skill_root, skill_root, findings)
        return findings

    for path in iter_candidate_files(skill_root):
        if path.name == "package.json":
            scan_package_json(root, skill_root, path, findings)
        elif path.name == "requirements.txt":
            scan_requirements(root, skill_root, path, findings)
        elif path.name == "go.mod":
            scan_go_mod(root, skill_root, path, findings)
        elif path.suffix.lower() == ".toml":
            scan_toml_manifest(root, skill_root, path, findings)
        scan_text_file(root, skill_root, path, findings)
    return findings


def write_csv(path: Path, findings: list[Finding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(findings[0]).keys()) if findings else [
            "skill", "skill_id", "skill_name", "skill_repo", "skill_path",
            "kind", "ecosystem", "value", "source_file", "line", "evidence", "risks"
        ])
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["risks"] = ";".join(finding.risks)
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan agent skills for possible dependencies and supply-chain risk signals.")
    parser.add_argument("root", type=Path, nargs="?", help="Directory containing downloaded skills.")
    parser.add_argument("--hf-dataset", default="FayeZC/SkillMD-138K", help="HuggingFace dataset name, e.g. FayeZC/SkillMD-138K.")
    parser.add_argument("--split", default="train", help="Dataset split to scan when --hf-dataset is used.")
    parser.add_argument("--limit", type=int, default=None, help="Optional maximum number of skills to scan.")
    parser.add_argument("--examples", type=int, default=None, help="How many example skills with dependency signals to print. Use 0 to suppress examples.")
    parser.add_argument("--json", type=Path, dest="json_out", help="Write findings to JSON.")
    parser.add_argument("--csv", type=Path, dest="csv_out", help="Write findings to CSV.")
    args = parser.parse_args()

    if args.hf_dataset:
        return scan_hf_dataset(args.hf_dataset, args.split, args.limit, args.examples)

    if args.root is None:
        parser.error("root is required unless --hf-dataset is provided")

    root = args.root.expanduser().resolve()
    if not root.exists():
        print(f"Root does not exist: {root}", file=sys.stderr)
        return 2

    skill_roots = discover_skill_roots(root)
    if args.limit is not None:
        skill_roots = skill_roots[: args.limit]
    all_findings: list[Finding] = []
    for skill_root in skill_roots:
        all_findings.extend(scan_skill(root, skill_root))

    summary: dict[str, dict[str, int]] = {}
    for finding in all_findings:
        summary.setdefault(finding.skill, {})
        summary[finding.skill][finding.kind] = summary[finding.skill].get(finding.kind, 0) + 1

    print(f"Scanned skills: {len(skill_roots)}")
    print(f"Findings: {len(all_findings)}")
    print()
    for skill, counts in sorted(summary.items()):
        compact = ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
        print(f"- {skill}: {compact}")

    if args.json_out:
        args.json_out.write_text(json.dumps([asdict(f) for f in all_findings], indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nJSON written: {args.json_out}")
    if args.csv_out:
        write_csv(args.csv_out, all_findings)
        print(f"CSV written: {args.csv_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
