# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pytest

from surfactant.regex import extract_fixed_prefixes


def test_extract_fixed_prefixes():
    # Test case 1: Regex with capture group and multiple prefixes
    regex1 = r"^(abc|def)\d+world"
    expected1 = ["abc", "def"]
    assert extract_fixed_prefixes(regex1) == expected1

    # Test case 2: Regex with escaped character
    regex2 = r"hello\.\d+world"
    expected2 = ["hello."]
    assert extract_fixed_prefixes(regex2) == expected2

    # Test case 3: Regex with character class
    regex3 = r"[xyz]123"
    expected3 = ["x123", "y123", "z123"]
    assert extract_fixed_prefixes(regex3) == expected3

    # Test case 4: Regex with no fixed prefix
    regex4 = r"\d+world"
    expected4 = []
    assert extract_fixed_prefixes(regex4) == expected4

    # Test case 5: Regex with starting '^'
    regex5 = r"^start123"
    expected5 = ["start123"]
    assert extract_fixed_prefixes(regex5) == expected5

    # Test case 6: Invalid regex pattern
    regex6 = r"^(abc"
    with pytest.raises(ValueError):
        extract_fixed_prefixes(regex6)

    # Test case 7: Regex with alphanumeric characters and special characters
    regex7 = r"prefix_123-abc"
    expected7 = ["prefix_123-abc"]
    assert extract_fixed_prefixes(regex7) == expected7

    # Test case 8: Regex with capture group followed by literal
    regex8 = r"^(foo|bar)baz"
    expected8 = ["foobaz", "barbaz"]
    assert extract_fixed_prefixes(regex8) == expected8

    # Test case 9: Regex with nested capture groups
    regex9 = r"^((foo|bar)baz)"
    expected9 = []
    assert extract_fixed_prefixes(regex9) == expected9

    # Test case 10: Regex with multiple capture groups
    regex10 = r"^(foo|bar)xyz(baz|qux)"
    expected10 = ["fooxyz", "barxyz"]
    assert extract_fixed_prefixes(regex10) == expected10

    # Test case 11: Regex with escaped backslash
    regex11 = r"prefix\\d+suffix"  # raw string so no \\ => \
    expected11 = ["prefix\\d"]  # regular string, so \\ => \
    assert extract_fixed_prefixes(regex11) == expected11
