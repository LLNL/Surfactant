# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.utils.ahocorasick import AhoCorasick, AhoCorasickNode, build_regex_prefix_matcher

class TestAhoCorasick:
    def test_initialization(self):
        """Test initialization of the AhoCorasick automaton."""
        ac = AhoCorasick()
        self.assertFalse(ac.is_bytes)
        self.assertEqual(ac.encoding, 'utf-8')
        self.assertFalse(ac.built)
        self.assertEqual(ac.pattern_prefixes, {})
        
        ac_bytes = AhoCorasick(is_bytes=True, encoding='latin-1')
        self.assertTrue(ac_bytes.is_bytes)
        self.assertEqual(ac_bytes.encoding, 'latin-1')
    
    def test_add_pattern(self):
        """Test adding patterns to the automaton."""
        ac = AhoCorasick()
        ac.add_pattern("hello", 1, "hello")
        
        # Check that the pattern was added correctly
        node = ac.root
        for char in "hello":
            self.assertIn(char, node.goto)
            node = node.goto[char]
        self.assertEqual(node.out, [1])
        self.assertEqual(ac.pattern_prefixes, {1: "hello"})
    
    def test_add_pattern_bytes(self):
        """Test adding patterns with byte handling."""
        ac = AhoCorasick(is_bytes=True)
        ac.add_pattern(b"hello", 1, "hello")
        ac.add_pattern("world", 2, "world")  # Should be converted to bytes
        
        # Check pattern addition with bytes
        node = ac.root
        for byte in b"hello":
            self.assertIn(byte, node.goto)
            node = node.goto[byte]
        self.assertEqual(node.out, [1])
        
        # Check string converted to bytes
        node = ac.root
        for byte in b"world":
            self.assertIn(byte, node.goto)
            node = node.goto[byte]
        self.assertEqual(node.out, [2])
    
    def test_build_and_search_single_pattern(self):
        """Test building and searching with a single pattern."""
        ac = AhoCorasick()
        ac.add_pattern("hello", 1, "hello")
        ac.build_automaton()
        
        self.assertTrue(ac.built)
        
        # Test exact match
        results = ac.search("hello world")
        self.assertEqual(results, {1: [0]})
        
        # Test no match
        results = ac.search("hi there")
        self.assertEqual(results, {})
        
        # Test multiple occurrences
        results = ac.search("hello hello hello")
        self.assertEqual(results, {1: [0, 6, 12]})
    
    def test_search_multiple_patterns(self):
        """Test searching with multiple patterns."""
        ac = AhoCorasick()
        ac.add_pattern("he", 1, "he")
        ac.add_pattern("she", 2, "she")
        ac.add_pattern("his", 3, "his")
        ac.add_pattern("hers", 4, "hers")
        ac.build_automaton()
        
        results = ac.search("she said he told his and hers story")
        self.assertEqual(results[1], [9])  # "he"
        self.assertEqual(results[2], [0])  # "she"
        self.assertEqual(results[3], [15])  # "his"
        self.assertEqual(results[4], [24])  # "hers"
    
    def test_overlapping_patterns(self):
        """Test handling of overlapping patterns."""
        ac = AhoCorasick()
        ac.add_pattern("abcd", 1, "abcd")
        ac.add_pattern("bcd", 2, "bcd")
        ac.add_pattern("cd", 3, "cd")
        ac.build_automaton()
        
        results = ac.search("abcd")
        self.assertEqual(set(results.keys()), {1, 2, 3})
        self.assertEqual(results[1], [0])  # "abcd"
        self.assertEqual(results[2], [1])  # "bcd"
        self.assertEqual(results[3], [2])  # "cd"
    
    def test_bytes_search(self):
        """Test searching with bytes."""
        ac = AhoCorasick(is_bytes=True)
        ac.add_pattern(b"hello", 1, "hello")
        ac.build_automaton()
        
        # Test with bytes input
        results = ac.search(b"hello world")
        self.assertEqual(results, {1: [0]})
        
        # Test with string input that gets converted
        results = ac.search("hello world")
        self.assertEqual(results, {1: [0]})
    
    def test_empty_and_edge_cases(self):
        """Test edge cases."""
        ac = AhoCorasick()
        
        # Empty pattern should be ignored in build_regex_prefix_matcher
        # but let's test directly
        ac.add_pattern("", 1, "")
        ac.build_automaton()
        results = ac.search("any text")
        # Empty pattern may match at every position or not at all depending on implementation
        
        # Empty search text
        results = ac.search("")
        self.assertEqual(results, {})
        
        # Reset and test with non-empty pattern
        ac = AhoCorasick()
        ac.add_pattern("test", 1, "test")
        ac.build_automaton()
        results = ac.search("")
        self.assertEqual(results, {})
    
    def test_build_regex_prefix_matcher(self):
        """Test the build_regex_prefix_matcher function."""
        # Simple literal patterns
        patterns_dict = {
            1: "hello",
            2: "world"
        }
        
        ac = build_regex_prefix_matcher(patterns_dict)
        
        # Both patterns should be added as-is
        results = ac.search("hello world")
        self.assertEqual(set(results.keys()), {1, 2})
        self.assertEqual(results[1], [0])
        self.assertEqual(results[2], [6])
        
        # Test with regex patterns
        regex_patterns = {
            1: "hel+o",        # Should extract "hel" as prefix
            2: "wo(rld|w)"     # Should extract "wo" as prefix
        }
        
        ac = build_regex_prefix_matcher(regex_patterns)
        
        # Should match both patterns
        results = ac.search("hello world")
        self.assertEqual(set(results.keys()), {1, 2})
        
        # Complex regex with no fixed prefix should be skipped
        regex_patterns = {
            1: "hel+o",       # Should extract "hel" as prefix
            2: ".*(rld|w)"    # No fixed prefix
        }
        
        ac = build_regex_prefix_matcher(regex_patterns)
        
        # Should match only pattern 1
        results = ac.search("hello world")
        self.assertEqual(set(results.keys()), {1})