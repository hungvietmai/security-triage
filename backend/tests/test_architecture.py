"""Enforces the layering rules in backend/AGENTS.md by parsing imports."""

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"

# Modules that compose features; nothing below them may import them.
COMPOSITION = ("app.main", "app.models", "app.workers")
# Feature modules that must stay free of HTTP concerns.
HTTP_FREE = {"service.py", "models.py", "schemas.py"}


def imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def violations(files, is_violation) -> list[str]:
    return [
        f"{path.relative_to(APP.parent).as_posix()} -> {name}"
        for path in files
        for name in imports(path)
        if is_violation(path, name)
    ]


def within(name: str, *packages: str) -> bool:
    return any(name == package or name.startswith(f"{package}.") for package in packages)


def feature_of(path: Path) -> str:
    return path.relative_to(APP / "features").parts[0]


def test_core_is_independent_of_features_and_composition():
    files = (APP / "core").rglob("*.py")
    assert violations(files, lambda _, name: within(name, "app.features", *COMPOSITION)) == []


def test_features_do_not_import_each_other_or_composition():
    def is_violation(path: Path, name: str) -> bool:
        if within(name, *COMPOSITION):
            return True
        return within(name, "app.features") and name.split(".")[2:3] not in (
            [],
            [feature_of(path)],
        )

    assert violations((APP / "features").rglob("*.py"), is_violation) == []


def test_services_models_and_schemas_stay_free_of_http():
    files = [path for path in (APP / "features").rglob("*.py") if path.name in HTTP_FREE]
    assert violations(files, lambda _, name: within(name, "fastapi", "starlette")) == []


def test_every_feature_model_module_is_registered():
    registered = set(imports(APP / "models.py"))
    feature_models = {
        f"app.features.{feature_of(path)}.models" for path in (APP / "features").glob("*/models.py")
    }
    assert feature_models, "no feature models found"
    assert feature_models - registered == set()
