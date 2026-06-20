"""Portable project-path discovery shared by command-line scripts."""

import os
from pathlib import Path


def find_project_root(start: Path | None = None) -> Path:
    """Return the repository root, with an optional environment override."""
    configured_root = os.environ.get("CSE713_ROOT")
    if configured_root:
        root = Path(configured_root).expanduser().resolve()
        if not root.is_dir():
            raise RuntimeError(f"CSE713_ROOT is not a directory: {root}")
        return root

    start_path = (start or Path(__file__)).resolve()
    base = start_path if start_path.is_dir() else start_path.parent
    for candidate in [base, *base.parents]:
        if (candidate / "Joern_llm_implement").is_dir() and (candidate / "README.md").is_file():
            return candidate

    raise RuntimeError(
        "Could not locate the project root. Set CSE713_ROOT to the repository directory."
    )


PROJECT_ROOT = find_project_root()
