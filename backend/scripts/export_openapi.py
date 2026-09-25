"""Write the API's OpenAPI document; the frontend generates its API types from it.

Usage: python -m scripts.export_openapi [OUTPUT_PATH]   (stdout when omitted)
"""

import json
import sys
from pathlib import Path

from app.main import app


def export() -> str:
    return json.dumps(app.openapi(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> None:
    if argv:
        # Explicit LF keeps the file identical to the Linux/CI export.
        Path(argv[0]).write_text(export(), encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(export())


if __name__ == "__main__":
    main(sys.argv[1:])
