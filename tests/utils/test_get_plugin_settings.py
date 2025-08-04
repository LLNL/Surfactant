# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.utils.get_plugin_settings import extract_settings_from_docstring


def function_with_settings():
    """Function for testing: has a colon

    Config Options:
        test_function.option1 (str): Some option. [default="123"]
        test_function.option2 (int): Some other option. [default=123]
        test_function.option3 (int): Some long description that doesn't fit on
            a single line
        test_function.option4: Some option missing a type: and with a colon
    """


def test_extract_settings_from_docstring():
    assert function_with_settings.__doc__

    settings = extract_settings_from_docstring(function_with_settings.__doc__)
    assert len(settings) == 4

    assert settings[0].name == "test_function.option1"
    assert settings[0].type_ == "str"
    assert settings[0].description == "Some option."
    assert settings[0].default == '"123"'

    assert settings[1].name == "test_function.option2"
    assert settings[1].type_ == "int"
    assert settings[1].description == "Some other option."
    assert settings[1].default == "123"

    assert settings[2].name == "test_function.option3"
    assert settings[2].type_ == "int"
    assert settings[2].description == "Some long description that doesn't fit on a single line"
    assert settings[2].default is None

    assert settings[3].name == "test_function.option4"
    assert settings[3].type_ is None
    assert settings[3].description == "Some option missing a type: and with a colon"
    assert settings[3].default is None
