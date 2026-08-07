"""Tests for invocation-scoped sandbox identity resolution."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from arema.runtime.sessions import (
    SandboxIdentityError,
    SessionKeys,
    resolve_sandbox_case_id,
)
from reverse_engineering.tools import prepare_sandbox
from reverse_engineering.tools.deobfuscation import runtime as deobfuscation_runtime
from reverse_engineering.tools.ghidra import prepare_ghidra, toolset


class _State:
    def __init__(self, values: dict[str, object] | None = None) -> None:
        self.values = values or {}

    def get(self, key: str, default: object = None) -> object:
        return self.values.get(key, default)

    def __setitem__(self, key: str, value: object) -> None:
        self.values[key] = value


class _ReadOnlyState:
    def get(self, _key: str, default: object = None) -> object:
        return default


class _RejectingWriteState:
    def get(self, _key: str, default: object = None) -> object:
        return default

    def __setitem__(self, _key: str, _value: object) -> None:
        raise TypeError("state is read-only")


class _ExplodingGetterState:
    def get(self, _key: str, _default: object = None) -> object:
        raise RuntimeError("state getter exploded")

    def __setitem__(self, _key: str, _value: object) -> None:
        pass


class _ExplodingSetterLookupState:
    def get(self, _key: str, default: object = None) -> object:
        return default

    @property
    def __setitem__(self) -> object:
        raise RuntimeError("state setter lookup exploded")


class _ExplodingStateContext:
    @property
    def state(self) -> object:
        raise RuntimeError("context state lookup exploded")


class _ExplodingInvocationContext:
    state = _State()

    @property
    def invocation_id(self) -> object:
        raise RuntimeError("context invocation lookup exploded")


class _Context:
    def __init__(self, invocation_id: object, values: dict[str, object] | None = None) -> None:
        self.invocation_id = invocation_id
        self.state = _State(values)


def test_explicit_sandbox_case_id_is_preserved_exactly() -> None:
    context = _Context("dev-ui-run", {SessionKeys.SANDBOX_CASE_ID: "  cli-case-42  "})

    assert resolve_sandbox_case_id(context) == "  cli-case-42  "
    assert context.state.values == {SessionKeys.SANDBOX_CASE_ID: "  cli-case-42  "}


def test_dev_ui_context_derives_and_persists_stable_invocation_identity() -> None:
    context = _Context("dev-ui-invocation-42")
    expected = "inv-" + hashlib.sha256(b"dev-ui-invocation-42").hexdigest()[:32]

    assert resolve_sandbox_case_id(context) == expected
    assert resolve_sandbox_case_id(context) == expected
    assert context.state.values[SessionKeys.SANDBOX_CASE_ID] == expected


def test_distinct_invocation_ids_derive_distinct_sandbox_case_ids() -> None:
    first = _Context("invocation-a")
    second = _Context("invocation-b")

    assert resolve_sandbox_case_id(first) != resolve_sandbox_case_id(second)


def test_empty_invocation_id_raises_sandbox_identity_error() -> None:
    with pytest.raises(SandboxIdentityError):
        resolve_sandbox_case_id(_Context(""))


def test_rejected_sandbox_state_write_raises_chained_identity_error() -> None:
    context = SimpleNamespace(invocation_id="invocation", state=_RejectingWriteState())

    with pytest.raises(SandboxIdentityError, match="sandbox state is not writable") as error:
        resolve_sandbox_case_id(context)

    assert isinstance(error.value.__cause__, TypeError)


@pytest.mark.parametrize(
    "context",
    [
        _ExplodingStateContext(),
        SimpleNamespace(invocation_id="invocation", state=_ExplodingGetterState()),
        SimpleNamespace(invocation_id="invocation", state=_ExplodingSetterLookupState()),
        _ExplodingInvocationContext(),
    ],
)
def test_identity_access_exceptions_become_chained_sandbox_identity_errors(
    context: object,
) -> None:
    with pytest.raises(SandboxIdentityError, match="sandbox identity access failed") as error:
        resolve_sandbox_case_id(context)

    assert isinstance(error.value.__cause__, RuntimeError)


@pytest.mark.parametrize(
    "context",
    [
        None,
        SimpleNamespace(invocation_id=None, state=_State()),
        SimpleNamespace(invocation_id="   ", state=_State()),
        SimpleNamespace(invocation_id="invocation", state=_ReadOnlyState()),
        SimpleNamespace(invocation_id="invocation", state=None),
    ],
)
def test_unavailable_identity_or_writable_state_raises_sandbox_identity_error(
    context: object,
) -> None:
    with pytest.raises(SandboxIdentityError):
        resolve_sandbox_case_id(context)


def test_whitespace_only_explicit_case_id_falls_back_to_invocation_identity() -> None:
    context = _Context("invocation-blank", {SessionKeys.SANDBOX_CASE_ID: "  \t "})

    resolved = resolve_sandbox_case_id(context)

    assert resolved.startswith("inv-")
    assert context.state.values[SessionKeys.SANDBOX_CASE_ID] == resolved


def test_sandbox_backed_tools_share_one_imported_resolver_and_identity() -> None:
    context = _Context("shared-dev-ui-invocation")

    assert prepare_sandbox.resolve_sandbox_case_id is resolve_sandbox_case_id
    assert prepare_ghidra.resolve_sandbox_case_id is resolve_sandbox_case_id
    assert toolset.resolve_sandbox_case_id is resolve_sandbox_case_id
    assert deobfuscation_runtime.resolve_sandbox_case_id is resolve_sandbox_case_id
    assert {
        resolve_sandbox_case_id(context),
        prepare_sandbox.resolve_sandbox_case_id(context),
        prepare_ghidra.resolve_sandbox_case_id(context),
        toolset.resolve_sandbox_case_id(context),
        deobfuscation_runtime.resolve_sandbox_case_id(context),
    } == {context.state.values[SessionKeys.SANDBOX_CASE_ID]}
