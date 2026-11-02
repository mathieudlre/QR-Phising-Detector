from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


@pytest.fixture(autouse=True)
def environnement_isole(monkeypatch, tmp_path):
    """Aucun test n'appelle de service externe ni n'utilise un modèle local."""
    monkeypatch.setenv("ENABLE_EXTERNAL_LOOKUPS", "false")
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "absent.joblib"))


@pytest.fixture
def samples() -> Path:
    return SAMPLES
