"""Tests for hexpose.formats and hexpose.entropy."""

from __future__ import annotations

import pytest

from hexpose.entropy import entropy_label, high_entropy, shannon_entropy
from hexpose.formats import detect_format, is_binary


# ---------------------------------------------------------------------------
# entropy tests
# ---------------------------------------------------------------------------

def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy("") == 0.0


def test_entropy_uniform():
    # Single repeated byte -> entropy 0
    assert shannon_entropy(b"\x00" * 100) == pytest.approx(0.0)


def test_entropy_random_like():
    # Base64 alphabet string should have high entropy
    sample = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    e = shannon_entropy(sample)
    assert e > 5.0


def test_high_entropy_true():
    secret = "aB3$xK9!mN2@pL7#qR5%"
    assert high_entropy(secret, threshold=3.5)


def test_high_entropy_false():
    boring = "aaaaaaaaaaaaaaaaaaaaaa"
    assert not high_entropy(boring, threshold=3.5)


def test_entropy_label_very_high():
    data = bytes(range(256))
    assert entropy_label(data) == "very-high"


def test_entropy_label_very_low():
    assert entropy_label("aaaa") == "very-low"


def test_entropy_label_medium():
    # A short English sentence has moderate entropy (mid range)
    data = "the quick brown fox"
    label = entropy_label(data)
    assert label in ("low", "medium", "high")


# ---------------------------------------------------------------------------
# format detection tests
# ---------------------------------------------------------------------------

def test_detect_elf():
    assert detect_format(b"\x7fELF" + b"\x00" * 12) == "elf"


def test_detect_pe():
    assert detect_format(b"MZ" + b"\x00" * 14) == "pe"


def test_detect_zip():
    assert detect_format(b"PK\x03\x04" + b"\x00" * 12) == "zip"


def test_detect_raw():
    assert detect_format(b"hello world") == "raw"


def test_is_binary_true():
    data = bytes(range(256)) * 2
    assert is_binary(data)


def test_is_binary_false():
    data = b"This is plain ASCII text with no weird bytes.\n" * 10
    assert not is_binary(data)


def test_is_binary_empty():
    assert not is_binary(b"")
