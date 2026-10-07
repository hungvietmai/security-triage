"""Refuse to start a scan worker whose profile or scanners differ from the pins.

Runs before Celery in the worker container: every profile file must match its hash, and
the installed Semgrep/CodeQL must be the versions in tools/pins.env and the profile.
"""

import tempfile
from pathlib import Path

from app.core.config import get_settings
from app.scanners.process import ProcessRecord, ToolVersionCallable, invoke, tool_version
from app.scanners.profile import ProfileError, ScanProfile, load_profile


def read_pins(path: Path) -> dict[str, str]:
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            pins[key] = value
    return pins


def check_pins(profile: ScanProfile, pins: dict[str, str]) -> None:
    for language, config in profile.configs.items():
        expected = {
            "semgrep_version": pins["SEMGREP_VERSION"],
            "codeql_version": pins["CODEQL_VERSION"],
        }
        actual = {key: config[key] for key in expected}
        pack = config["codeql_bundle"][f"{language}_query_pack"]
        if actual != expected or pack != pins[f"CODEQL_{language.upper()}_QUERY_PACK"]:
            raise ProfileError(f"{language} profile config differs from tools/pins.env")


def check(root: Path, manifest: str, *, tool_version_fn: ToolVersionCallable = tool_version) -> str:
    profile = load_profile(root, manifest)
    pins = read_pins(root / "tools/pins.env")
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
    return (
        f"Worker ready: profile {profile.profile_id} sha256={profile.manifest_sha256}, "
        f"semgrep {pins['SEMGREP_VERSION']}, codeql {pins['CODEQL_VERSION']}"
    )


if __name__ == "__main__":
    settings = get_settings()
    print(check(settings.triage_root, settings.scan_profile))
