# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pytest

from surfactant.utils.regex import extract_fixed_literals, extract_fixed_prefixes


def assert_order_independent(actual, expected):
    """
    Helper function to assert that two lists are equal, ignoring order.
    Also asserts that the second part of the tuple matches exactly.
    """
    assert set(actual[0]) == set(expected[0]), f"Expected {expected[0]}, but got {actual[0]}"
    assert actual[1] == expected[1], f"Expected {expected[1]}, but got {actual[1]}"


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


def test_extract_fixed_literals():
    # Test case 1: Regex with fixed literals
    regex1 = r"hello123world"
    expected1 = (["hello123world"], True)
    assert extract_fixed_literals(regex1) == expected1

    # Test case 2: Regex with alternation
    regex2 = r"^(foo|bar)baz"
    expected2 = (["foobaz", "barbaz"], True)
    assert_order_independent(extract_fixed_literals(regex2), expected2)

    # Test case 3: Regex with character class
    regex3 = r"[abc]123"
    expected3 = (["a123", "b123", "c123"], True)
    assert_order_independent(extract_fixed_literals(regex3), expected3)

    # Test case 4: Regex with no fixed literals
    regex4 = r"\d+world"
    expected4 = (["world"], False)
    assert extract_fixed_literals(regex4) == expected4

    # Test case 5: Regex with repetition
    regex5 = r"(abc){2,3}"
    expected5 = (["abcabc"], True)
    assert extract_fixed_literals(regex5) == expected5

    # Test case 6: Regex with nested capture groups
    regex6 = r"^((foo|bar)baz)"
    expected6 = (["foobaz", "barbaz"], True)
    assert_order_independent(extract_fixed_literals(regex6), expected6)

    # Test case 7: Regex with escaped characters
    regex7 = r"hello\.\d+world"
    expected7 = (["hello."], True)
    assert extract_fixed_literals(regex7) == expected7

    # Test case 8: Regex with anchors
    regex8 = r"^start123$"
    expected8 = (["start123"], True)
    assert extract_fixed_literals(regex8) == expected8

    # Test case 9: Regex with alternation and literals
    regex9 = r"(foo|bar)(baz|qux)"
    expected9 = (["foobaz", "fooqux", "barbaz", "barqux"], True)
    assert_order_independent(extract_fixed_literals(regex9), expected9)

    # Test case 10: Regex with invalid pattern
    regex10 = r"^(abc"
    expected10 = ([], False)
    assert extract_fixed_literals(regex10) == expected10

    # Test case 11: Regex with optional group
    regex11 = r"(foo)?bar"
    expected11 = (["bar", "foobar"], True)
    assert_order_independent(extract_fixed_literals(regex11), expected11)

    # Test case 12: Regex with range in character class
    regex12 = r"[a-c]123"
    expected12 = (["a123", "b123", "c123"], True)
    assert_order_independent(extract_fixed_literals(regex12), expected12)

    # Test case 13: Regex with repetition and fixed literals
    regex13 = r"(abc){2}"
    expected13 = (["abcabc"], True)
    assert extract_fixed_literals(regex13) == expected13

    # Test case 14: Regex with escaped backslash
    regex14 = r"prefix\\suffix"
    expected14 = (["prefix\\suffix"], True)
    assert extract_fixed_literals(regex14) == expected14

    # Test case 15: Regex with multiple fixed literals
    regex15 = r"hello123|world456"
    expected15 = (["hello123", "world456"], True)
    assert_order_independent(extract_fixed_literals(regex15), expected15)


def test_extract_fixed_literals_actual_cases():
    # Test case: rflow (only possible prefixes exceed max possibilities threshold of 10)
    rflow = "[0-9]\\.[0-9]+\\ Copyright\\ by\\ Nikki\\ Chumakov"
    expected_rflow = ([" Copyright by Nikki Chumakov"], False)
    assert extract_fixed_literals(rflow) == expected_rflow

    # Test case: miniupnpd
    miniupnpd = r"SERVER:.*UPnP\/[0-9](\.[0-9]+)+?\ MiniUPnPd\/[0-9](\.[0-9]+)+?"
    expected_miniupnpd = (["SERVER:"], True)
    assert extract_fixed_literals(miniupnpd) == expected_miniupnpd

    # Test case: nlohmann
    # Actually may be better to change this so it just recognizes "nlohmann[0-9]"..
    # may also be worth checking to see if upstream pattern is correct and not supposed to be "nlohman::"
    nlohmann = r"nlohmann[0-9]+json_abi_v[1-3]+_[0-9]+(_[0-9])?"
    expected_nlohmann = (
        [f"nlohmann{digit}json_abi_v" for digit in range(10)],
        True,
    )
    assert_order_independent(extract_fixed_literals(nlohmann), expected_nlohmann)

    # Test case: mkenv (an optional component)
    mkenv = "mk(env)?image\\ version\\ 20[0-9]+\\.[0-9]+"
    expected_mkenv = (["mkimage version 20", "mkenvimage version 20"], True)
    assert_order_independent(extract_fixed_literals(mkenv), expected_mkenv)

    # Test case: version with the dot in the capture group
    dot_in_capture_group = "gcc version\\ [0-9](\\.[0-9]+)+?"
    expected_dot_in_capture_group = (
        [f"gcc version {digit}" for digit in range(10)],
        True,
    )
    assert_order_independent(
        extract_fixed_literals(dot_in_capture_group), expected_dot_in_capture_group
    )

    # Test case: version with a dot outside the capture group
    dot_outside_capture_group = "gcc version\\ [0-9]\\.([0-9]+)"
    expected_dot_outside_capture_group = (
        [f"gcc version {digit}." for digit in range(10)],
        True,
    )
    assert_order_independent(
        extract_fixed_literals(dot_outside_capture_group), expected_dot_outside_capture_group
    )

    # Test case: chrony
    chrony = "chrony[cd]\\ \\(chrony\\)\\ version\\ [0-9]\\.[0-9]+"
    expected_chrony = (["chronyc (chrony) version ", "chronyd (chrony) version "], True)
    assert_order_independent(extract_fixed_literals(chrony), expected_chrony)
