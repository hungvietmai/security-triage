// Runs from backend/ for staged files under it (see ../.husky/pre-commit).
export default {
  "*.py": [
    "uv run ruff format",
    "uv run ruff check --fix",
    // mypy follows imports across the package, so check the whole project once.
    () => "uv run mypy",
  ],
};
