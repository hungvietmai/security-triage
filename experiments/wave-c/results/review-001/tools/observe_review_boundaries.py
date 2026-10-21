"""Post-hoc stdlib experiment on our own files, never on application source."""

import argparse
import datetime
import json
from pathlib import Path, PurePosixPath


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    relative = PurePosixPath(args.output)
    if relative.is_absolute() or ".." in relative.parts or "\\" in args.output:
        parser.error("Output must be a safe workspace-relative path")
    output = workspace.joinpath(*relative.parts)
    if not output.resolve().is_relative_to(workspace):
        parser.error("Output escapes workspace")
    output.mkdir(parents=True, exist_ok=False)
    rows = []

    def fixture(name):
        base = output / name
        allowed, outside = base / "allowed", base / "outside"
        allowed.mkdir(parents=True)
        outside.mkdir()
        (outside / "dashboard.html").write_text("OUTSIDE_SYNTHETIC_MARKER")
        return allowed, outside

    allowed, outside = fixture("full-target-regular")
    (allowed / "dashboard.html").write_text("INSIDE_SYNTHETIC_MARKER")
    candidate = (allowed / "dashboard.html").resolve()
    accepted = candidate.is_relative_to(allowed.resolve())
    rows.append({"case": "full-target-regular", "guard_accepts": accepted,
                 "read_marker": candidate.read_text() if accepted else None})

    allowed, outside = fixture("full-target-existing-link")
    (allowed / "dashboard.html").symlink_to(outside / "dashboard.html")
    candidate = (allowed / "dashboard.html").resolve()
    accepted = candidate.is_relative_to(allowed.resolve())
    rows.append({"case": "full-target-existing-link", "guard_accepts": accepted,
                 "read_marker": candidate.read_text() if accepted else None,
                 "concurrent_filesystem_change": False})

    allowed, outside = fixture("checked-parent-then-append")
    parent = allowed / "agent"
    parent.mkdir()
    (parent / "dashboard.html").symlink_to(outside / "dashboard.html")
    checked_parent = parent.resolve()
    parent_accepted = checked_parent.is_relative_to(allowed.resolve())
    used = checked_parent / "dashboard.html"
    rows.append({"case": "checked-parent-then-append", "parent_guard_accepts": parent_accepted,
                 "used_path_lexically_inside": used.is_relative_to(allowed.resolve()),
                 "used_path_canonically_inside": used.resolve().is_relative_to(allowed.resolve()),
                 "read_marker": used.read_text() if parent_accepted else None,
                 "concurrent_filesystem_change": False,
                 "assumption_required": "No pre-existing escaping child symlink (A-SYM), not merely no race"})

    allowed, outside = fixture("checked-parent-regular-child")
    parent = allowed / "agent"
    parent.mkdir()
    (parent / "dashboard.html").write_text("INSIDE_SYNTHETIC_MARKER")
    checked_parent = parent.resolve()
    accepted = checked_parent.is_relative_to(allowed.resolve())
    used = checked_parent / "dashboard.html"
    rows.append({"case": "checked-parent-regular-child", "parent_guard_accepts": accepted,
                 "used_path_canonically_inside": used.resolve().is_relative_to(allowed.resolve()),
                 "read_marker": used.read_text() if accepted else None})

    allowed, outside = fixture("replacement-after-canonical-check")
    original = allowed / "dashboard.html"
    original.write_text("INSIDE_SYNTHETIC_MARKER")
    checked = original.resolve()
    accepted = checked.is_relative_to(allowed.resolve())
    # This is only our newly created regular file, inside this new experiment directory.
    if not checked.resolve().is_relative_to(output.resolve()) or checked.is_symlink():
        raise ValueError("Refuse to replace an unexpected file")
    checked.unlink()
    checked.symlink_to(outside / "dashboard.html")
    rows.append({"case": "replacement-after-canonical-check", "guard_accepts_before_replacement": accepted,
                 "used_path_canonically_inside_after_replacement": checked.resolve().is_relative_to(allowed.resolve()),
                 "read_marker": checked.read_text() if accepted else None,
                 "simulated_post_check_filesystem_change": True,
                 "excluded_by_frozen_model": "TOCTOU"})

    report = {"created_at": datetime.datetime.now(datetime.UTC).isoformat(),
              "classification": "post-hoc source-informed synthetic boundary observations",
              "application_imported_or_executed": False, "scanner_executed": False,
              "outside_means": "Outside the synthetic allowed directory, still inside this new workspace experiment",
              "cases": rows,
              "limitations": "Mirrors selected Path operations only; not an end-to-end application exploit or independent validation"}
    with (output / "observations.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
