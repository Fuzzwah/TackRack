from tackrack.infrastructure.redaction import sanitize


def test_type_annotations_are_not_credentials() -> None:
    text = "token: str | None = None\nauthorization = headers\n"
    assert sanitize(text) == (text, False)


def test_assigned_credentials_and_private_keys_are_withheld() -> None:
    text = 'api_key = "super-private-example-key"\npassword: unquotedLongSecret123\n'
    result, sensitive = sanitize(text)
    assert sensitive
    assert "super-private" not in result
    assert "unquotedLongSecret" not in result


def test_terminal_c0_c1_sequences_are_visible_data() -> None:
    rendered, _ = sanitize("\x1b[31mspoof\x9b0m")
    assert rendered == r"\u001b[31mspoof\u009b0m"
