# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from typing import Dict, List, Set, Tuple, Any, Union, Optional
from surfactant.utils.regex import extract_fixed_prefixes

class AhoCorasickNode:
    """Node in the Aho-Corasick trie structure."""
    def __init__(self):
        self.goto = {}  # Goto function
        self.out = []   # Output function - list of pattern indices at this node
        self.fail = None  # Failure function
        self.depth = 0  # Depth of the node in the trie

class AhoCorasick:
    """Aho-Corasick automaton for fast multiple string matching."""
    def __init__(self, is_bytes: bool = False, encoding: str = 'utf-8'):
        self.root = AhoCorasickNode()
        self.built = False
        self.is_bytes = is_bytes  # Flag to indicate if this automaton works with bytes
        self.pattern_prefixes = {}  # Maps pattern_id -> prefix used
        self.encoding = encoding  # Encoding to use for string/bytes conversion
    
    def add_pattern(self, pattern: Union[str, bytes], pattern_id: Any, prefix: str) -> None:
        """
        Add a pattern to the trie.
        
        Args:
            pattern: A string or bytes pattern to add
            pattern_id: An identifier for this pattern
            prefix: The prefix string used for this pattern
        """
        # Ensure pattern is in the correct type (str or bytes)
        if self.is_bytes and isinstance(pattern, str):
            pattern = pattern.encode(self.encoding)
        elif not self.is_bytes and isinstance(pattern, bytes):
            pattern = pattern.decode(self.encoding, errors='ignore')
            
        node = self.root
        for i, char in enumerate(pattern):
            # For bytes, comparison char will be int values for the byte
            if char not in node.goto:
                node.goto[char] = AhoCorasickNode()
                node.goto[char].depth = i + 1
            node = node.goto[char]
        node.out.append(pattern_id)
        
        # Store the prefix used for this pattern_id
        self.pattern_prefixes[pattern_id] = prefix
    
    def build_automaton(self) -> None:
        """Build the Aho-Corasick automaton by computing failure functions."""
        queue = []
        # Set failure of all depth 1 nodes to root
        for char, node in self.root.goto.items():
            node.fail = self.root
            queue.append(node)
        
        # Build failure function for the rest
        while queue:
            current = queue.pop(0)
            for char, node in current.goto.items():
                queue.append(node)
                failure = current.fail
                while failure and char not in failure.goto:
                    failure = failure.fail
                if not failure:
                    node.fail = self.root
                else:
                    node.fail = failure.goto[char]
                    # Add output patterns from failure node
                    node.out.extend(node.fail.out)
        
        self.built = True
    
    def search(self, text: Union[str, bytes]) -> Dict[Any, List[int]]:
        """
        Search for patterns in the text and return matching pattern IDs with their positions.
        
        Args:
            text: A string or bytes to search in
            
        Returns:
            A dictionary mapping pattern IDs to lists of positions where prefixes were found
        """
        if not self.built:
            self.build_automaton()
        
        # Ensure text is in the correct type (str or bytes)
        if self.is_bytes and isinstance(text, str):
            text = text.encode(self.encoding)
        elif not self.is_bytes and isinstance(text, bytes):
            text = text.decode(self.encoding, errors='ignore')
        
        node = self.root
        results = {}
        
        for i in range(len(text)):
            # For bytes, char will be int value of the byte
            char = text[i]
            
            while node is not self.root and char not in node.goto:
                node = node.fail
            
            if char in node.goto:
                node = node.goto[char]
                if node.out:
                    for pattern_id in node.out:
                        if pattern_id not in results:
                            results[pattern_id] = []
                        # Store the start position by subtracting the node depth
                        prefix_length = len(self.pattern_prefixes.get(pattern_id, ''))
                        if self.is_bytes and isinstance(prefix := self.pattern_prefixes.get(pattern_id, ''), str):
                            prefix_length = len(prefix.encode(self.encoding))
                        
                        # Calculate the start position of the match
                        start_pos = max(0, i + 1 - prefix_length)
                        results[pattern_id].append(start_pos)
        
        return results

def build_regex_prefix_matcher(
    patterns_dict: Dict[Any, str], 
    is_bytes: bool = False, 
    encoding: str = 'utf-8'
) -> AhoCorasick:
    """
    Build an Aho-Corasick automaton for matching regex prefixes.
    
    Args:
        patterns_dict: Dictionary mapping pattern IDs to regex patterns
        is_bytes: Flag indicating if the automaton should work with bytes
        encoding: Character encoding to use for string/bytes conversion (default: utf-8)
        
    Returns:
        An Aho-Corasick automaton for prefix matching
    """
    ac = AhoCorasick(is_bytes=is_bytes, encoding=encoding)
    
    for pattern_id, pattern in patterns_dict.items():
        prefixes = extract_fixed_prefixes(pattern)
        
        for prefix in prefixes:
            if not prefix:  # Skip empty prefixes
                continue
            
            ac.add_pattern(prefix, pattern_id, prefix)
    
    ac.build_automaton()
    return ac
