# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pytest

from surfactant.utils.regex import (
    extract_fixed_literals,
    extract_fixed_prefixes,
    handle_escaped_literal,
)


class TestHandleEscapedLiteral:
    def test_basic_escaped_literals(self):
        assert handle_escaped_literal(r"\.", 0, 2) == (".", 2)
        assert handle_escaped_literal(r"\-", 0, 2) == ("-", 2)

    def test_special_escape_sequences(self):
        assert handle_escaped_literal(r"\a", 0, 2) == (None, 0)
        assert handle_escaped_literal(r"\n", 0, 2) == ("\n", 2)
        assert handle_escaped_literal(r"\r", 0, 2) == ("\r", 2)
        assert handle_escaped_literal(r"\t", 0, 2) == ("\t", 2)
        assert handle_escaped_literal(r"\v", 0, 2) == ("\v", 2)
        assert handle_escaped_literal(r"\f", 0, 2) == ("\f", 2)
        assert handle_escaped_literal(r"\0", 0, 2) == (None, 0)

    def test_control_characters(self):
        # Test redundant check issue where next_char is checked twice
        assert handle_escaped_literal(r"\cA", 0, 3) == (chr(ord("A") - ord("A") + 1), 3)
        assert handle_escaped_literal(r"\cZ", 0, 3) == (chr(ord("Z") - ord("A") + 1), 3)

        # Test lowercase control character (should return None, 0)
        assert handle_escaped_literal(r"\ca", 0, 3) == (None, 0)

    def test_hex_escapes(self):
        assert handle_escaped_literal(r"\x41", 0, 4) == ("A", 4)  # ASCII 65 = 'A'
        assert handle_escaped_literal(r"\x7A", 0, 4) == ("z", 4)  # ASCII 122 = 'z'

        # Test invalid hex sequence
        assert handle_escaped_literal(r"\xZZ", 0, 4) == (None, 0)

    def test_regex_special_chars(self):
        # These should all return (None, 0) as they're special regex entities
        assert handle_escaped_literal(r"\d", 0, 2) == (None, 0)
        assert handle_escaped_literal(r"\w", 0, 2) == (None, 0)
        assert handle_escaped_literal(r"\s", 0, 2) == (None, 0)
        assert handle_escaped_literal(r"\b", 0, 2) == (None, 0)

    def test_overlapping_character_sets(self):
        # Test "0" which appears in multiple conditions
        assert handle_escaped_literal(r"\0", 0, 2) == (
            None,
            0,
        )  # null char (potentially also backref though)

        # Test digit reference (should return None, 0)
        assert handle_escaped_literal(r"\1", 0, 2) == (None, 0)  # backreference

    def test_unicode(self):
        # Testing the incomplete Unicode support
        assert handle_escaped_literal(r"\u0041", 0, 6) == (
            None,
            0,
        )  # Should return "A" once implemented properly

        # Test curly brace Unicode format
        assert handle_escaped_literal(r"\u{0041}", 0, 8) == (None, 0)  # Not properly handled


class TestExtractFixedPrefixes:
    def test_basic_strings(self):
        assert extract_fixed_prefixes("abc") == ["abc"]
        assert extract_fixed_prefixes("Hello") == ["Hello"]
        assert extract_fixed_prefixes("abc123") == ["abc123"]

    def test_with_caret(self):
        assert extract_fixed_prefixes("^abc") == ["abc"]
        assert extract_fixed_prefixes("^Hello") == ["Hello"]

    def test_with_escaped_characters(self):
        assert extract_fixed_prefixes(r"abc\n") == ["abc\n"]
        assert extract_fixed_prefixes(r"\tHello") == ["\tHello"]
        assert extract_fixed_prefixes(r"\x41BC") == ["ABC"]

    def test_character_classes(self):
        result = extract_fixed_prefixes("[ab]cd")
        assert len(result) == 2
        assert "acd" in result and "bcd" in result

        result = extract_fixed_prefixes("[a-c]de")
        assert len(result) == 3
        assert "ade" in result and "bde" in result and "cde" in result

        # Test with negated class (should return empty list)
        assert not extract_fixed_prefixes("[^abc]")

    def test_character_class_with_escaped_chars(self):
        result = extract_fixed_prefixes(r"[\t\n]abc")
        assert len(result) == 2
        assert "\tabc" in result and "\nabc" in result

        # Test escaped literals within character class
        result = extract_fixed_prefixes(r"[\[\]]abc")
        assert len(result) == 2
        assert "[abc" in result and "]abc" in result

    def test_character_ranges(self):
        # Test with hyphen at different positions
        result = extract_fixed_prefixes("[-ab]")  # Literal hyphen at start
        assert len(result) == 3
        assert "-" in result and "a" in result and "b" in result

        result = extract_fixed_prefixes("[ab-]")  # Literal hyphen at end
        assert len(result) == 3
        assert "a" in result and "b" in result and "-" in result

    def test_capture_groups(self):
        assert extract_fixed_prefixes("(abc)") == ["abc"]

        # Test alternation in groups
        result = extract_fixed_prefixes("(abc|def)")
        assert len(result) == 2
        assert "abc" in result and "def" in result

        # Test non-alphanumeric content in groups (restricted handling)
        assert extract_fixed_prefixes("(abc|d!e)") == ["abc"]

        # Test nested groups (should return empty list)
        assert not extract_fixed_prefixes("(a(bc))")

        # Test non-capturing groups (should return empty list)
        assert not extract_fixed_prefixes("(?:abc)")

    def test_limited_prefix_extraction(self):
        # Test characters that are accepted (alphanumeric, underscore, hyphen)
        assert extract_fixed_prefixes("abc_def") == ["abc_def"]
        assert extract_fixed_prefixes("abc-def") == ["abc-def"]

        # Test characters that break prefix extraction
        assert extract_fixed_prefixes("abc.def") == ["abc"]
        assert extract_fixed_prefixes("abc!def") == ["abc"]

    def test_complex_patterns(self):
        result = extract_fixed_prefixes("^[aA]bc")
        assert len(result) == 2
        assert "abc" in result and "Abc" in result

        result = extract_fixed_prefixes("^(abc|def)123")
        assert len(result) == 2
        assert "abc123" in result and "def123" in result

    def test_special_regex_features(self):
        # Test with quantifiers
        assert extract_fixed_prefixes("abc+") == ["abc"]
        assert extract_fixed_prefixes("abc*") == ["abc"]

        # Test with special regex characters
        assert extract_fixed_prefixes("abc\\d") == ["abc"]
        assert not extract_fixed_prefixes("\\w+abc")

    def test_bounds_checking(self):
        # Empty pattern
        assert not extract_fixed_prefixes("")

        # Only special characters
        assert not extract_fixed_prefixes("\\d\\w\\s")

        # Invalid regex
        with pytest.raises(ValueError):
            extract_fixed_prefixes("[unclosed")

        with pytest.raises(ValueError):
            extract_fixed_prefixes("(unclosed")


# Test case that runs through a few cases, some of which may already be covered above
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


# Tests for the tree-based implementation of literal extraction, using Python's re parser below this point
def assert_order_independent(actual, expected):
    """
    Helper function to assert that two lists are equal, ignoring order.
    Also asserts that the second part of the tuple matches exactly.
    """
    assert set(actual[0]) == set(expected[0]), f"Expected {expected[0]}, but got {actual[0]}"
    assert actual[1] == expected[1], f"Expected {expected[1]}, but got {actual[1]}"


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
    expected5 = (["abcabc", "abcabcabc"], True)
    assert_order_independent(extract_fixed_literals(regex5), expected5)

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

    # Test case 16: Regex with comprehensive branching
    regex16 = r"he(l|[0-5])o"
    expected16 = (["helo", "he0o", "he1o", "he2o", "he3o", "he4o", "he5o"], True)
    assert_order_independent(extract_fixed_literals(regex16), expected16)

    # Test case 17: Regex with non-comprehensive branching
    regex17 = r"he(l|[0-5]+)o"
    expected17 = (["hel", "he0", "he1", "he2", "he3", "he4", "he5"], True)
    assert_order_independent(extract_fixed_literals(regex17), expected17)


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
    # Only guaranteed literals are "nlohmann[0-9]" due to infinite max repetitions of the numbers
    # may be worth checking to see if upstream pattern is correct and not supposed to be "nlohman::"
    nlohmann = r"nlohmann[0-9]+json_abi_v[1-3]+_[0-9]+(_[0-9])?"
    expected_nlohmann = (
        [f"nlohmann{digit}" for digit in range(10)],
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
