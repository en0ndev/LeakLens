from pathlib import Path

from leaklens.config import load_config
from leaklens.models import DetectorSource, Severity


def test_config_loader_parses_custom_values(tmp_path: Path) -> None:
    cfg = tmp_path / "leaklens.yml"
    cfg.write_text(
        """
entropy_threshold: 4.8
severity_threshold: high
enabled_detectors: [regex, context]
ignored_paths: ["vendor/**"]
allowlist:
  values: ["safe_value"]
  patterns: ["^dummy_"]
rules:
  - name: custom_token
    regex: "ctok_[A-Za-z0-9]{16}"
    severity: medium
    confidence: 0.77
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = load_config(cfg)

    assert config.entropy_threshold == 4.8
    assert config.severity_threshold == Severity.HIGH
    assert config.enabled_detectors == {DetectorSource.REGEX, DetectorSource.CONTEXT}
    assert "vendor/**" in config.ignored_paths
    assert "safe_value" in config.allowlist_values
    assert config.custom_rules
