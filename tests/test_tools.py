import time

import pytest

from secure_ai_agent_framework import (
    ToolError,
    ToolExecutionError,
    ToolPolicy,
    ToolRequest,
    ToolRunner,
    ToolSpec,
    ToolTimeoutError,
    UnknownToolError,
)


def runner(handler=lambda value: value):
    return ToolRunner((ToolSpec("echo", handler),))


def test_allowlist_and_names_are_fail_closed():
    tools = runner()
    assert tools.names() == ("echo",)
    with pytest.raises(UnknownToolError):
        tools.run(ToolRequest("missing"))


def test_validates_json_arguments_and_callable_arguments():
    assert runner(lambda value: {"value": value}).run(
        ToolRequest("echo", {"value": "ok"})
    ).output == {"value": "ok"}
    with pytest.raises(ToolError):
        runner().run(ToolRequest("echo", {"value": object()}))


def test_custom_validator_and_unexpected_handler_error_are_wrapped():
    spec = ToolSpec(
        "echo",
        lambda value: value,
        validator=lambda args: (_ for _ in ()).throw(ValueError()),
    )
    with pytest.raises(ToolError):
        ToolRunner((spec,)).run(ToolRequest("echo", {"value": 1}))
    with pytest.raises(ToolExecutionError):
        runner(lambda: 1 / 0).run(ToolRequest("echo"))


def test_dry_run_never_invokes_handler():
    called = False

    def handler():
        nonlocal called
        called = True

    result = ToolRunner((ToolSpec("danger", handler),)).run(
        ToolRequest("danger", dry_run=True)
    )
    assert result.simulated and result.status == "simulated" and not called


def test_network_and_subprocess_are_denied_by_default():
    with pytest.raises(ValueError):
        ToolRunner((ToolSpec("web", lambda: None, network=True),))
    with pytest.raises(ValueError):
        ToolRunner((ToolSpec("shell", lambda: None, subprocess=True),))


def test_capabilities_can_be_explicitly_enabled_but_timeout_is_still_bounded():
    policy = ToolPolicy(
        allow_network=True,
        allow_subprocess=True,
        default_timeout_seconds=1,
        max_timeout_seconds=2,
    )
    tools = ToolRunner((ToolSpec("web", lambda: "ok", network=True),), policy=policy)
    assert tools.run(ToolRequest("web")).output == "ok"
    with pytest.raises(ValueError):
        ToolRunner((ToolSpec("slow", lambda: None, timeout_seconds=3),), policy=policy)


def test_timeout_fails_closed():
    def slow():
        time.sleep(0.1)

    tools = ToolRunner(
        (ToolSpec("slow", slow, timeout_seconds=0.01),),
        ToolPolicy(default_timeout_seconds=0.01, max_timeout_seconds=1),
    )
    with pytest.raises(ToolTimeoutError):
        tools.run(ToolRequest("slow"))


def test_input_and_output_limits_are_enforced():
    policy = ToolPolicy(max_input_bytes=10, max_output_bytes=10)
    with pytest.raises(ToolError):
        ToolRunner((ToolSpec("echo", lambda value: value),), policy).run(
            ToolRequest("echo", {"value": "this is too large"})
        )
    with pytest.raises(ToolError):
        ToolRunner((ToolSpec("big", lambda: "this is too large"),), policy).run(
            ToolRequest("big")
        )


def test_duplicate_names_are_rejected():
    tools = runner()
    with pytest.raises(ValueError):
        tools.register(ToolSpec("echo", lambda: None))
