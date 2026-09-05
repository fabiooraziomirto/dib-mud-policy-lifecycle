from __future__ import annotations

from pathlib import Path

import yaml


CODE_ROOT = Path(__file__).resolve().parents[2]


def test_config_yaml_loads_with_required_sections() -> None:
    config = yaml.safe_load((CODE_ROOT / "configs/default_hyperparams.yaml").read_text(encoding="utf-8"))
    for section in ("outputs", "experiments", "scoring", "baselines"):
        assert section in config


def test_repository_layout_has_expected_top_level_entries() -> None:
    code_root = CODE_ROOT
    repository_root = code_root.parent
    for entry in (
        "src/dib",
        "tests",
        "scripts",
        "configs/default_hyperparams.yaml",
        "requirements.txt",
    ):
        assert (code_root / entry).exists(), f"missing expected code entry: {entry}"
    assert (repository_root / "README.md").exists(), "missing expected repository entry: README.md"
    # The development repository keeps the numbered experiment tree; the released
    # artifact keeps the per-claim evidence tree. Exactly one of the two is present.
    development_layout = (repository_root / "experiments/18_openwrt_enforcement/docker-compose.yml").exists()
    artifact_layout = (repository_root / "openwrt/docker-compose.yml").exists() and (
        repository_root / "results"
    ).exists()
    assert development_layout or artifact_layout, "neither the development nor the artifact layout is present"


def test_dib_package_imports() -> None:
    import dib.core.models  # noqa: F401
    import dib.evaluation.dib  # noqa: F401
    import dib.registry.api  # noqa: F401
