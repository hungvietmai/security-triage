"""Source line indexes scoped to one triage operation, never shared across scans."""

from collections.abc import Sequence


class SourceLines:
    def __init__(self) -> None:
        self._lines: dict[tuple[str, bool], list[str]] = {}

    def get(self, source: str, *, keepends: bool = False) -> Sequence[str]:
        key = (source, keepends)
        lines = self._lines.get(key)
        if lines is None:
            lines = source.splitlines(keepends=keepends)
            self._lines[key] = lines
        return lines
