from leaklens.redaction import mask_in_line, mask_secret


def test_mask_secret_preserves_prefix_and_suffix() -> None:
    value = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
    masked = mask_secret(value)

    assert masked.startswith("ghp_")
    assert masked.endswith("ABCD")
    assert value not in masked


def test_mask_in_line_never_shows_full_secret() -> None:
    value = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    line = f'openai_key = "{value}"'
    preview = mask_in_line(line, value)

    assert value not in preview
    assert "openai_key" in preview
