"""A sample's bytes must never leave this machine.

Submitting an unknown sample to a public service publishes it: it is stored
permanently, distributed to that service's antivirus partners, and made
downloadable by their paying customers, and it cannot be withdrawn. For anyone
holding a client's incident sample that is a disclosure event, and "the tool did
it automatically while looking for a report" is not a defence.

So the guarantee is not that the code avoids calling an upload endpoint. It is
that the package which talks to the internet has no route to a sample's bytes at
all, and no request it makes can carry a body beyond a digest. These tests parse
the package to check that, rather than trusting a docstring or a code review.

They are deliberately blunt. A legitimate future change that trips one of them
should have to justify itself here, in a file about publishing malware, rather
than pass unnoticed inside a diff about something else.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

INTEL_PACKAGE = Path("src/reverse_engineering/intel")

# Keyword arguments that make an HTTP request carry a payload. `data=` is
# excluded: it is how a form-encoded query is sent, and it is checked separately
# below to confirm it only ever carries literal query fields.
_BODY_KWARGS = frozenset({"files", "content", "json"})

# The request-shaped functions whose keyword arguments are inspected.
_REQUEST_CALLS = frozenset({"post", "put", "patch", "request", "stream", "send"})

# Names that would give this package a route to a local file's bytes.
_FILESYSTEM_NAMES = frozenset(
    {"open", "ArtifactStore", "default_artifacts_root", "read_bytes", "read_text", "Path"}
)


def _modules() -> list[tuple[Path, ast.Module]]:
    paths = sorted(INTEL_PACKAGE.rglob("*.py"))
    assert paths, "the intel package should exist and hold modules"
    return [(path, ast.parse(path.read_text(encoding="utf-8"))) for path in paths]


def _calls(tree: ast.Module) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def test_no_request_carries_a_body() -> None:
    """An upload needs somewhere to put the bytes. There is nowhere."""
    for path, tree in _modules():
        for call in _calls(tree):
            if _call_name(call) not in _REQUEST_CALLS:
                continue
            used = {keyword.arg for keyword in call.keywords if keyword.arg}
            offending = used & _BODY_KWARGS
            assert not offending, (
                f"{path} passes {sorted(offending)} to an HTTP call; "
                "that is how a sample would be uploaded"
            )


def test_form_data_carries_only_literal_query_fields() -> None:
    """``data=`` is how a hash query is sent. It must never become a body.

    Requiring a literal dict of literal strings means a variable holding sample
    bytes cannot be routed through it, and the reviewer can read the entire
    outbound payload in the call itself.
    """
    allowed_values = {"get_info", "get_file"}
    for path, tree in _modules():
        for call in _calls(tree):
            if _call_name(call) not in _REQUEST_CALLS:
                continue
            for keyword in call.keywords:
                if keyword.arg != "data":
                    continue
                assert isinstance(keyword.value, ast.Dict), (
                    f"{path} passes a non-literal data= payload to an HTTP call"
                )
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=True):
                    assert isinstance(key, ast.Constant), f"{path} uses a computed data= key"
                    # A value is either a fixed verb or the digest variable.
                    if isinstance(value, ast.Constant):
                        assert value.value in allowed_values, (
                            f"{path} sends an unexpected literal {value.value!r}"
                        )
                    else:
                        assert isinstance(value, ast.Name) and value.id == "sha256", (
                            f"{path} sends something other than the digest in data="
                        )


def test_the_outbound_package_cannot_read_a_local_file() -> None:
    """The strongest form of the guarantee: no route to the bytes.

    A module that cannot open a file cannot upload one, whatever a future
    endpoint change looks like. Downloaded bytes arrive from the network and are
    handed back to the caller; writing them to the store happens outside this
    package.
    """
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in _FILESYSTEM_NAMES:
                pytest.fail(f"{path} references {node.id}; the intel package must not touch disk")
            if isinstance(node, ast.Attribute) and node.attr in {"read_bytes", "read_text"}:
                pytest.fail(f"{path} calls {node.attr}; the intel package must not touch disk")


def test_no_upload_shaped_endpoint_is_named() -> None:
    """Belt and braces over the URL constants themselves.

    Only string literals are inspected, not the file's prose: the module
    docstrings explain at length why nothing is submitted anywhere, and a
    substring scan over raw source would flag the explanation.
    """
    forbidden = ("/upload", "upload_url", "/scan", "/submit", "/analyse", "/analyze")
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if "\n" in node.value:  # a docstring, not an endpoint
                continue
            lowered = node.value.lower()
            for fragment in forbidden:
                assert fragment not in lowered, (
                    f"{path} names an upload-shaped endpoint in {node.value!r}"
                )


def test_only_known_hosts_are_contacted() -> None:
    """Every outbound host is one of the three documented sources."""
    allowed = ("hashlookup.circl.lu", "mb-api.abuse.ch", "www.virustotal.com")
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if not node.value.startswith("http"):
                continue
            assert any(host in node.value for host in allowed), (
                f"{path} names an unexpected host in {node.value!r}"
            )


def test_the_sample_bytes_never_reach_the_intel_package() -> None:
    """The caller hands over a digest and nothing else.

    Every public entry point takes ``sha256`` as its first parameter. A function
    here accepting sample content would be the shape an upload needs.
    """
    forbidden_params = {"payload_path", "sample_path", "file_path", "artifact_path", "content"}
    for path, tree in _modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            names = {argument.arg for argument in node.args.args + node.args.kwonlyargs}
            offending = names & forbidden_params
            assert not offending, (
                f"{path}:{node.name} takes {sorted(offending)}; "
                "a public entry point here may only take a digest"
            )


# --- and nothing downloads except when a user asked for a digest --------------

SOURCE_ROOT = Path("src")

# The one place a download may be initiated from. A premium key can retrieve a
# real sample, so a second call site would mean malware landing on the analyst's
# disk without them naming a hash.
_FETCH_ENTRY_POINT = Path("src/reverse_engineering/tools/acquire_by_hash.py")

_DOWNLOAD_FUNCTIONS = frozenset({"fetch_sample", "download_malwarebazaar", "download_virustotal"})


def test_only_the_by_hash_tool_can_start_a_download() -> None:
    """A download happens because a user named a digest, or it does not happen.

    The reputation sweep asks questions; it never retrieves bytes. The
    path-based ingest reads local files; it never reaches the network at all.
    Both properties are only true while this stays a single call site.
    """
    callers: set[Path] = set()
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        if path == _FETCH_ENTRY_POINT or path.parent.name == "intel":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in _DOWNLOAD_FUNCTIONS:
                callers.add(path)

    assert not callers, (
        f"{sorted(str(p) for p in callers)} start a download; only "
        f"{_FETCH_ENTRY_POINT} may, and only after a user supplies a digest"
    )


def test_the_reputation_sweep_never_retrieves_bytes() -> None:
    """gather() answers "what is known about this digest", never "give it to me"."""
    tree = ast.parse(Path("src/reverse_engineering/intel/lookup.py").read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            assert _call_name(node) not in _DOWNLOAD_FUNCTIONS, (
                "the reputation sweep must not download a sample"
            )
        if isinstance(node, ast.ImportFrom):
            assert node.module != "reverse_engineering.intel.fetch", (
                "the reputation sweep must not import the download path"
            )


def test_the_path_based_ingest_never_reaches_the_network() -> None:
    """ "Analyze this file" is a local operation start to finish, apart from the
    reputation questions acquire_sample asks about the digest it computed."""
    source = Path("src/reverse_engineering/tools/acquire_sample.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            assert _call_name(node) not in _DOWNLOAD_FUNCTIONS, (
                "acquire_sample must never download; a path is resolved locally or not at all"
            )
