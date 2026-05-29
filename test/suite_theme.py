#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Theme system tests.

Validates that every bundled `theme.jsonc` under `resources/themes/*/`
loads cleanly against `resources/themes/theme.schema.json`.

Purpose: catch drift between `ThemeParser` and the schema.  If a
contributor adds a new section or key to the parser but forgets the
schema, the next bundled theme to use that key (or any negative test
that relies on `additionalProperties: false`) will fail this test.

`jsonschema` is an optional test dependency; tests self-skip when the
package is not installed so existing `pip install pytest pytest-xdist`
setups keep working.
'''

import json
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / 'resources' / 'themes' / 'theme.schema.json'
THEME_ROOT = REPO_ROOT / 'resources' / 'themes'


def _strip_jsonc(text):
    '''Strip // line comments, /* block */ comments, and trailing commas.

    Mirrors `ThemeParser::stripComments` in
    `ui/qt/utils/themes/theme_parser.cpp` (preserves strings, preserves
    newlines so JSON parse-error line numbers stay meaningful).
    '''
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                d = text[i]
                out.append(d)
                i += 1
                if d == '\\' and i < n:
                    out.append(text[i])
                    i += 1
                elif d == '"':
                    break
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            i += 2
            while i < n and text[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            i += 2
            while i + 1 < n and not (text[i] == '*' and text[i + 1] == '/'):
                if text[i] == '\n':
                    out.append('\n')
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    stripped = ''.join(out)
    # JSONC tolerates trailing commas; strict JSON does not.
    return re.sub(r',(\s*[}\]])', r'\1', stripped)


def _bundled_themes():
    return sorted(THEME_ROOT.glob('*/theme.jsonc'))


class TestThemeSchema:
    @pytest.mark.parametrize('theme_path', _bundled_themes(),
                             ids=lambda p: p.parent.name)
    def test_bundled_theme_matches_schema(self, theme_path):
        '''Every bundled theme.jsonc validates against theme.schema.json.'''
        jsonschema = pytest.importorskip('jsonschema')

        schema = json.loads(SCHEMA_PATH.read_text())
        data = json.loads(_strip_jsonc(theme_path.read_text()))
        jsonschema.Draft202012Validator(schema).validate(data)
