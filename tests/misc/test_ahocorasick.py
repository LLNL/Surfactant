# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.utils.ahocorasick import AhoCorasick, build_regex_literal_matcher


def test_add_pattern_and_search():
    ac = AhoCorasick()
    ac.add_pattern("hello", 1, "hello")
    ac.add_pattern("world", 2, "world")
    ac.build_automaton()

    text = "hello world, hello again"
    results = ac.search(text)

    assert results[1] == [0, 13], f"Expected [0, 13], but got {results[1]}"
    assert results[2] == [6], f"Expected [6], but got {results[2]}"


def test_add_pattern_with_bytes():
    ac = AhoCorasick(is_bytes=True)
    ac.add_pattern(b"hello", 1, "hello")
    ac.add_pattern(b"world", 2, "world")
    ac.build_automaton()

    text = b"hello world, hello again"
    results = ac.search(text)

    assert results[1] == [0, 13], f"Expected [0, 13], but got {results[1]}"
    assert results[2] == [6], f"Expected [6], but got {results[2]}"


def test_build_regex_literal_matcher():
    patterns = {
        1: r"hello",
        2: r"world",
        3: r"^foo|bar",
    }
    ac = build_regex_literal_matcher(patterns, is_literal=True)

    text = "hello world, foo and bar"
    results = ac.search(text)

    assert results[1] == [0], f"Expected [0], but got {results[1]}"
    assert results[2] == [6], f"Expected [6], but got {results[2]}"
    assert 3 not in results, f"Expected no results for 3 but got {results}"


def test_no_match():
    ac = AhoCorasick()
    ac.add_pattern("test", 1, "test")
    ac.build_automaton()

    text = "no matches here"
    results = ac.search(text)

    assert results == {}, f"Expected an empty dictionary, but got {results}"


def test_prefix_handling():
    ac = AhoCorasick()
    ac.add_pattern("prefix", 1, "prefix")
    ac.add_pattern("prefix123", 2, "prefix123")
    ac.build_automaton()

    text = "prefix123 and prefix"
    results = ac.search(text)

    assert results[1] == [0, 14], f"Expected [0, 14], but got {results[1]}"
    assert results[2] == [0], f"Expected [0], but got {results[2]}"
