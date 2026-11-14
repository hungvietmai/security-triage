"""Refuse to start a scan worker whose profiles or scanners differ from the pins.

Runs before Celery in the worker container: every file of every profile must match its hash,
and the installed Semgrep/CodeQL must be the versions in tools/pins.env and the profiles.
"""

import tempfile
from collections.abc import Iterable
from pathlib import Path

from app.core.config import get_settings
from app.scanners.process import ProcessRecord, ToolVersionCallable, invoke, tool_version
from app.scanners.profile import AnyProfile, ProfileError, load_any_profile


def read_pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            pins[key] = value
    return pins


def check_pins(profile: AnyProfile, pins: dict[str, str]) -> None:
    for language, config in profile.configs.items():
        expected = {
            "semgrep_version": pins["SEMGREP_VERSION"],
            "codeql_version": pins["CODEQL_VERSION"],
        }
        actual = {key: config[key] for key in expected}
        pack = config["codeql_bundle"][f"{language}_query_pack"]
        if actual != expected or pack != pins[f"CODEQL_{language.upper()}_QUERY_PACK"]:
            raise ProfileError(f"{language} profile config differs from tools/pins.env")


def check(
    root: Path,
    manifests: str | Iterable[str],
    *,
    tool_version_fn: ToolVersionCallable = tool_version,
) -> str:
    pins = read_pins(root / "tools/pins.env")
    profiles = [
        load_any_profile(root, manifest)
        for manifest in ([manifests] if isinstance(manifests, str) else manifests)
    ]
    for profile in profiles:
        check_pins(profile, pins)
    with tempfile.TemporaryDirectory() as folder:
        logs = Path(folder)
        steps: dict[str, ProcessRecord] = {}
        tool_version_fn(
            "semgrep",
            pins["SEMGREP_VERSION"],
            logs,
            "semgrep",
            steps,
            working_directory=logs,
            invoke_fn=invoke,
        )
        tool_version_fn(
            "codeql",
            pins["CODEQL_VERSION"],
            logs,
            "codeql",
            steps,
            working_directory=logs,
            invoke_fn=invoke,
        )
    loaded = ", ".join(f"{p.profile_id} sha256={p.manifest_sha256}" for p in profiles)
    return (
        f"Worker ready: profiles {loaded}, "
        f"semgrep {pins['SEMGREP_VERSION']}, codeql {pins['CODEQL_VERSION']}"
    )


if __name__ == "__main__":
    settings = get_settings()
    manifests = {settings.scan_profile, *settings.scan_profiles.values()}
    print(check(settings.triage_root, sorted(manifests)))
