"""Tests for ``auditor.harness_runner.build_child_env`` (PII / least-privilege).

The auditor is the control plane. The harness is what it monitors. These tests assert that
representative auditor-only secrets do NOT survive the allowlist filter, and that the harness's
legitimately-needed env IS forwarded. Adding a new auditor-only env var? Add a case here.
"""

from __future__ import annotations

from auditor.harness_runner import build_child_env


class TestSecretsAreStripped:
    """Anything the auditor uses for its own auth or DB access must NEVER reach the harness."""

    def test_jwt_signing_secret_dropped(self) -> None:
        out = build_child_env({"JWT_SECRET": "topsecret"}, {})
        assert "JWT_SECRET" not in out

    def test_database_credentials_dropped(self) -> None:
        out = build_child_env(
            {
                "POSTGRES_DSN": "postgresql+asyncpg://user:pw@host/db",
                "DATABASE_URL": "postgresql://user:pw@host/db",
                "DB_PASSWORD": "pw",
            },
            {},
        )
        assert "POSTGRES_DSN" not in out
        assert "DATABASE_URL" not in out
        assert "DB_PASSWORD" not in out

    def test_oidc_secrets_dropped(self) -> None:
        out = build_child_env(
            {"OIDC_CLIENT_SECRET": "abc", "OAUTH_CLIENT_SECRET": "def"}, {}
        )
        assert "OIDC_CLIENT_SECRET" not in out
        assert "OAUTH_CLIENT_SECRET" not in out

    def test_cloud_credentials_dropped(self) -> None:
        out = build_child_env(
            {
                "AWS_SECRET_ACCESS_KEY": "akey",
                "AWS_ACCESS_KEY_ID": "akid",
                "GCP_PROJECT": "proj",
                "AZURE_CLIENT_SECRET": "asec",
                "GOOGLE_APPLICATION_CREDENTIALS": "/path",
                "FLY_API_TOKEN": "tok",
            },
            {},
        )
        for key in (
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "GCP_PROJECT",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "FLY_API_TOKEN",
        ):
            assert key not in out, f"{key} should have been stripped"

    def test_infrastructure_endpoints_dropped(self) -> None:
        """The harness has no business talking to OPA, Redis, MinIO, or S3 directly - it talks
        to the auditor over IPC. Stripping these locks down the network surface."""
        out = build_child_env(
            {
                "OPA_URL": "http://127.0.0.1:8181",
                "REDIS_URL": "redis://127.0.0.1:6379/0",
                "MINIO_ROOT_PASSWORD": "minio123",
                "S3_BUCKET": "bucket",
            },
            {},
        )
        assert "OPA_URL" not in out
        assert "REDIS_URL" not in out
        assert "MINIO_ROOT_PASSWORD" not in out
        assert "S3_BUCKET" not in out

    def test_slack_webhook_dropped(self) -> None:
        """HITL notifications are routed via the auditor, not the harness."""
        out = build_child_env({"SLACK_WEBHOOK_URL": "https://hooks.slack.com/x"}, {})
        assert "SLACK_WEBHOOK_URL" not in out

    def test_arbitrary_secret_dropped(self) -> None:
        """The ``SECRET_*`` denylist prefix catches anything that follows the convention."""
        out = build_child_env({"SECRET_ANYTHING": "x"}, {})
        assert "SECRET_ANYTHING" not in out


class TestHarnessNeedsForwarded:
    """The harness's actual job needs these. Without them it can't talk to the LLM at all."""

    def test_anthropic_key_forwarded(self) -> None:
        out = build_child_env({"ANTHROPIC_API_KEY": "sk-ant-xxx"}, {})
        assert out["ANTHROPIC_API_KEY"] == "sk-ant-xxx"

    def test_litellm_routing_forwarded(self) -> None:
        out = build_child_env(
            {"LITELLM_BASE_URL": "http://127.0.0.1:4000", "LITELLM_API_KEY": "k"}, {}
        )
        assert out["LITELLM_BASE_URL"] == "http://127.0.0.1:4000"
        assert out["LITELLM_API_KEY"] == "k"

    def test_path_forwarded(self) -> None:
        """Without PATH the subprocess can't find anything on POSIX."""
        out = build_child_env({"PATH": "/usr/bin:/bin"}, {})
        assert out["PATH"] == "/usr/bin:/bin"

    def test_windows_basics_forwarded(self) -> None:
        """Python's import machinery breaks on Windows without these. Forward unconditionally
        so a Linux test process building env for a hypothetical Windows child still works."""
        windows_env = {
            "SYSTEMROOT": "C:\\Windows",
            "WINDIR": "C:\\Windows",
            "COMSPEC": "C:\\Windows\\System32\\cmd.exe",
            "PATHEXT": ".COM;.EXE;.BAT",
            "APPDATA": "C:\\Users\\x\\AppData\\Roaming",
            "LOCALAPPDATA": "C:\\Users\\x\\AppData\\Local",
        }
        out = build_child_env(windows_env, {})
        for key, value in windows_env.items():
            assert out[key] == value, f"{key} was dropped"

    def test_locale_forwarded_via_prefix(self) -> None:
        """LC_* is a prefix allowlist for locale variables."""
        out = build_child_env({"LC_ALL": "en_US.UTF-8", "LC_CTYPE": "en_US.UTF-8"}, {})
        assert out["LC_ALL"] == "en_US.UTF-8"
        assert out["LC_CTYPE"] == "en_US.UTF-8"


class TestOverrides:
    """The caller-supplied overrides apply last, after the allowlist filter."""

    def test_overrides_added(self) -> None:
        out = build_child_env({}, {"HARNESS_RUN_ID": "abc", "HARNESS_MODE": "agent"})
        assert out["HARNESS_RUN_ID"] == "abc"
        assert out["HARNESS_MODE"] == "agent"

    def test_overrides_not_filtered(self) -> None:
        """Caller-supplied overrides are the per-run vars they intentionally inject; we trust them
        verbatim. Even if a key starts with a denylist prefix, the override takes effect."""
        out = build_child_env({}, {"AWS_ACCESS_KEY_ID": "intentional"})
        assert out["AWS_ACCESS_KEY_ID"] == "intentional"

    def test_overrides_win_over_allowlist(self) -> None:
        out = build_child_env({"PATH": "from-parent"}, {"PATH": "from-override"})
        assert out["PATH"] == "from-override"


class TestNonAllowlistedNonSecretsAreDropped:
    """Defense by allowlist: random env vars we don't recognize are dropped. This is the rule
    that prevents tomorrow's secret-named-something-weird from leaking."""

    def test_unknown_var_dropped(self) -> None:
        out = build_child_env({"SOME_RANDOM_THING": "value"}, {})
        assert "SOME_RANDOM_THING" not in out

    def test_only_known_vars_in_output(self) -> None:
        out = build_child_env(
            {
                "PATH": "/bin",  # allowlisted
                "ANTHROPIC_API_KEY": "key",  # allowlisted
                "JWT_SECRET": "bad",  # denylisted
                "MYSTERY_VAR": "?",  # unknown
            },
            {},
        )
        assert set(out.keys()) == {"PATH", "ANTHROPIC_API_KEY"}
