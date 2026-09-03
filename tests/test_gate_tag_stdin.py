from __future__ import annotations

from ai_repo_safety.gate import classify_pre_push_stdin, run_gate


def test_classify_pre_push_tag_ref() -> None:
    stdin = "refs/heads/main abcdef refs/tags/v0.1.9 000000\n"
    when, version = classify_pre_push_stdin(stdin)
    assert when == "tag"
    assert version == "0.1.9"


def test_classify_pre_push_branch_ref() -> None:
    stdin = "refs/heads/dev abcdef refs/heads/dev 000000\n"
    when, version = classify_pre_push_stdin(stdin)
    assert when == "push"
    assert version is None


def test_gate_auto_uses_tag_when_stdin_has_tag(tmp_path, monkeypatch) -> None:
    seen: list[str] = []

    def fake_run_tag(*args, **kwargs):
        seen.append("tag")

    monkeypatch.setattr("ai_repo_safety.gate._run_tag", lambda *a, **k: seen.append("tag"))
    monkeypatch.setattr("ai_repo_safety.gate._run_push", lambda *a, **k: seen.append("push"))
    code = run_gate(
        tmp_path,
        when="auto",
        stdin_text="refs/heads/main abc refs/tags/v0.1.9 def\n",
    )
    assert code == 0
    assert seen == ["tag"]
