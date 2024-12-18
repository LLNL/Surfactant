# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import re
from typing import List, Tuple


# pylint: disable=too-many-return-statements
def handle_escaped_literal(regex_pattern: str, i: int, length: int) -> Tuple[str, int]:
    """
    Handles escaped literals in a regex pattern and returns the character to be added to the prefix
    and the number of positions to advance the index by.

    Parameters:
    regex_pattern (str): The regex pattern being parsed.
    i (int): The current index in the regex pattern.
    length (int): The total length of the regex pattern.

    Returns:
    Tuple[str, int]: A tuple containing the character to be added to the prefix and the number of positions
           to advance the index by. Returns (None, 0) if parsing should stop.
    """
    next_char = regex_pattern[i + 1]
    # Try to catch all potential escape sequences with non-literal meaning
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions/Cheatsheet
    if next_char in "dDsSwWbBpPuk0123456789":
        return None, 0
    if next_char in "rntvf0":
        escape_sequences = {"r": "\r", "n": "\n", "t": "\t", "v": "\v", "f": "\f", "0": "\0"}
        return escape_sequences[next_char], 2
    if next_char == "c":
        if (
            i + 2 < length
            and regex_pattern[i + 1] == "c"
            and regex_pattern[i + 2].isalpha()
            and regex_pattern[i + 2].isupper()
        ):
            control_char = chr(ord(regex_pattern[i + 2]) - ord("A") + 1)
            return control_char, 3
        return None, 0
    if next_char == "x":
        if i + 3 < length and all(
            c in "0123456789abcdefABCDEF" for c in regex_pattern[i + 2 : i + 4]
        ):
            return chr(int(regex_pattern[i + 2 : i + 4], 16)), 4
        return None, 0
    # Should be able to handle '\uhhhh' case, however there is an additional \u{hhhh} and \u{hhhhh} syntax
    # that may be used if a flag is enabled, which complicates things a bit
    return next_char, 2


def extract_fixed_prefixes(regex_pattern: str) -> List[str]:
    """
    Extracts the fixed string prefixes from a regex pattern, including handling
    escaped characters, expanding character classes, and handling capture groups
    with multiple prefixes separated by '|'.

    Parameters:
    regex_pattern (str): The regex pattern from which to extract the prefixes.

    Returns:
    list: A list of fixed string prefixes, or an empty list if no fixed prefix exists.
    """
    # Compile the regex pattern to ensure it's valid
    try:
        re.compile(regex_pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}") from None

    prefixes = []
    i = 0
    length = len(regex_pattern)

    # Ignore starting '^'
    if i < length and regex_pattern[i] == "^":
        i += 1

    # Handle character class at the start
    if i < length and regex_pattern[i] == "[":
        i += 1
        char_class = []
        if i < length and regex_pattern[i] == "^":
            # If the character class is negated, we can't handle it -- return an empty prefix list
            return []
        while i < length and regex_pattern[i] != "]":
            if regex_pattern[i] == "\\" and i + 1 < length:
                if regex_pattern[i + 1] == "b":
                    char_class.append("\b")
                    i += 2
                else:
                    next_char, i_delta = handle_escaped_literal(regex_pattern, i, length)
                    # If it's a special character class, we can't handle it -- return empty prefix list
                    if next_char is None:
                        return []
                    char_class.append(next_char)
                    i += i_delta
            elif (
                regex_pattern[i] == "-"
                and char_class
                and i + 1 < length
                and regex_pattern[i + 1] != "]"
            ):
                # A hyphen means we need to handle a range of prefixes from the previous character to the next one
                start_char = char_class.pop()
                end_char = regex_pattern[i + 1]
                char_class.extend(chr(c) for c in range(ord(start_char), ord(end_char) + 1))
                i += 2
            else:
                char_class.append(regex_pattern[i])
                i += 1
        i += 1  # Skip the closing ']'
        # Generate prefixes for each character in the class
        for char in char_class:
            prefixes.append(char)
    # Handle capture group at the start
    elif i < length and regex_pattern[i] == "(":
        i += 1
        if i < length and regex_pattern[i] == "?":
            return []  # Return early if it starts with a '?'
        group_content = []
        while i < length and regex_pattern[i] != ")":
            if regex_pattern[i] == "\\" and i + 1 < length:
                next_char, i_delta = handle_escaped_literal(regex_pattern, i, length)
                if next_char is None:
                    return []  # special character class, we can't handle this form of regex
                group_content.append(next_char)
                i += i_delta
            elif regex_pattern[i] == "(":
                return []  # Return early if it contains a nested capture group
            else:
                group_content.append(regex_pattern[i])
                i += 1
        i += 1  # Skip the closing ')'
        # Split the group content by '|'
        for part in "".join(group_content).split("|"):
            # Only consider alphanumeric prefixes
            if part.isalnum():
                prefixes.append(part)

    # Handle regular fixed prefix extraction
    prefix = []
    while i < length:
        char = regex_pattern[i]
        if char == "\\" and i + 1 < length:
            next_char, i_delta = handle_escaped_literal(regex_pattern, i, length)
            if next_char is None:
                break
            prefix.append(next_char)
            i += i_delta
        elif char.isalnum() or char in "_-":
            prefix.append(char)
            i += 1
        else:
            break
    if prefix:
        prefixes = [p + "".join(prefix) for p in prefixes] if prefixes else ["".join(prefix)]

    return prefixes
