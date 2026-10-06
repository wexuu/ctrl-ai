"""Test-wide environment: every suite reads the frozen configuration in tests/fixtures/config,
never the deployable files in config/, and never starts the background shadow check."""

import os
from pathlib import Path

FIXTURE_CONFIG = Path(__file__).resolve().parent / "fixtures" / "config"

for _name in ("policy", "models", "teams", "signatures", "mcp"):
    os.environ.setdefault(f"CTRL_AI_{_name.upper()}_FILE", str(FIXTURE_CONFIG / f"{_name}.yaml"))
os.environ.setdefault("CTRL_AI_SHADOW", "0")
# Masking needs a secret for the mask map; a fixed test value keeps the engine tests deterministic.
os.environ.setdefault("CTRL_AI_MASKING_SECRET", "ctrl-ai-test-masking-secret")
