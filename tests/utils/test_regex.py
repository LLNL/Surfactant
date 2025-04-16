# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pytest

from surfactant.utils.regex import extract_fixed_prefixes, handle_escaped_literal


class TestHandleEscapedLiteral:
    def test_basic_escaped_literals(self):
        assert handle_escaped_literal(r"\a", 0, 2) == ("a", 2)
        assert handle_escaped_literal(r"\.", 0, 2) == (".", 2)
        assert handle_escaped_literal(r"\-", 0, 2) == ("-", 2)

    def test_special_escape_sequences(self):
        assert handle_escaped_literal(r"\n", 0, 2) == ("\n", 2)
        assert handle_escaped_literal(r"\r", 0, 2) == ("\r", 2)
        assert handle_escaped_literal(r"\t", 0, 2) == ("\t", 2)
        assert handle_escaped_literal(r"\v", 0, 2) == ("\v", 2)
        assert handle_escaped_literal(r"\f", 0, 2) == ("\f", 2)
        assert handle_escaped_literal(r"\0", 0, 2) == ("\0", 2)

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
        assert handle_escaped_literal(r"\0", 0, 2) == ("\0", 2)  # null char

        # Test digit reference (should return None, 0)
        assert handle_escaped_literal(r"\1", 0, 2) == (None, 0)  # backreference

    def test_incomplete_unicode(self):
        # Testing the incomplete Unicode support
        assert handle_escaped_literal(r"\u0041", 0, 6) == ("u", 2)  # Should return "u" not "A"

        # Test curly brace Unicode format
        assert handle_escaped_literal(r"\u{0041}", 0, 8) == ("u", 2)  # Not properly handled


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
        assert extract_fixed_prefixes("[^abc]") == []

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
        assert extract_fixed_prefixes("(a(bc))") == []

        # Test non-capturing groups (should return empty list)
        assert extract_fixed_prefixes("(?:abc)") == []

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
        assert extract_fixed_prefixes("\\w+abc") == []

    def test_bounds_checking(self):
        # Empty pattern
        assert extract_fixed_prefixes("") == []

        # Only special characters
        assert extract_fixed_prefixes("\\d\\w\\s") == []

        # Invalid regex
        with pytest.raises(ValueError):
            extract_fixed_prefixes("[unclosed")

        with pytest.raises(ValueError):
            extract_fixed_prefixes("(unclosed")
