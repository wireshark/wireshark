#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Qt per-class font table tests.

FontManager (ui/qt/utils/font_manager.cpp) keeps a copy of the widget
classes Qt gives their own platform font, taken from Qt's private
QApplicationPrivate::initializeWidgetFontHash().  Qt offers no API to
enumerate that table, so the copy is checked here against the
QPlatformTheme::Font enumerators in the installed qpa/qplatformtheme.h:
every enumerator is either in the copy or in the exclusion set below.  A
new, renamed or removed enumerator in a later Qt fails the test.

The header is found through the WS_QT_QPA_HEADER environment variable, or
through Qt6Gui_DIR in the CMakeCache.txt of the build directory that holds
the program path.  The test is skipped when the header is not installed.
'''

import glob
import os
import re

import pytest

FONT_MANAGER_CPP = os.path.join(os.path.dirname(__file__), '..', 'ui', 'qt', 'utils', 'font_manager.cpp')

# QPlatformTheme::Font enumerators that Qt does not put into the widget font
# hash (Qt 6.12 initializeWidgetFontHash()).
EXCLUDED_ENUMERATORS = {
    # The application font itself, not a per-class entry.
    'SystemFont',
    # Read through QFontDatabase::systemFont(FixedFont), not a class font.
    'FixedFont',
    # Not mapped to a widget class by initializeWidgetFontHash().
    'GroupBoxTitleFont',
    'TabButtonFont',
    'EditorFont',
}


def read_class_font_table():
    '''Returns the (enumerator, class name) rows of platform_class_fonts[].'''
    with open(FONT_MANAGER_CPP, encoding='utf-8') as f:
        source = f.read()
    table = re.search(r'PlatformClassFont\s+platform_class_fonts\[\]\s*=\s*\{(.*?)\n\};', source, re.DOTALL)
    assert table, 'platform_class_fonts[] not found in font_manager.cpp'
    return re.findall(r'\{\s*"(\w+)"\s*,\s*"(\w+)"\s*\}', table.group(1))


def qt6gui_dir(program_path):
    '''Returns Qt6Gui_DIR from the build directory's CMakeCache.txt, or None.'''
    cache = os.path.join(program_path, '..', 'CMakeCache.txt')
    if not os.path.isfile(cache):
        return None
    with open(cache, encoding='utf-8', errors='replace') as f:
        for line in f:
            match = re.match(r'Qt6Gui_DIR:[A-Z]+=(.*)', line.strip())
            if match:
                return match.group(1)
    return None


def find_qpa_header(program_path):
    '''Returns the path of qpa/qplatformtheme.h, or None.'''
    env_header = os.environ.get('WS_QT_QPA_HEADER')
    if env_header:
        return env_header if os.path.isfile(env_header) else None

    gui_dir = qt6gui_dir(program_path)
    if not gui_dir:
        return None

    # Qt6Gui_DIR is <prefix>/lib[/<arch>]/cmake/Qt6Gui.  Look a few levels up
    # for the macOS framework headers (lib/QtGui.framework/Headers/<version>)
    # and the Linux include tree (include[/<arch>[/qt6]]/QtGui/<version>).
    patterns = (
        os.path.join('lib', 'QtGui.framework', 'Headers', '*', 'QtGui', 'qpa', 'qplatformtheme.h'),
        os.path.join('QtGui.framework', 'Headers', '*', 'QtGui', 'qpa', 'qplatformtheme.h'),
        os.path.join('include', 'QtGui', '*', 'QtGui', 'qpa', 'qplatformtheme.h'),
        os.path.join('include', '*', 'QtGui', '*', 'QtGui', 'qpa', 'qplatformtheme.h'),
        os.path.join('include', '*', '*', 'QtGui', '*', 'QtGui', 'qpa', 'qplatformtheme.h'),
    )
    for start in dict.fromkeys((gui_dir, os.path.realpath(gui_dir))):
        prefix = start
        for _ in range(4):
            prefix = os.path.dirname(prefix)
            for pattern in patterns:
                hits = sorted(glob.glob(os.path.join(prefix, pattern)))
                if hits:
                    return hits[-1]
    return None


def read_font_enumerators(header):
    '''Returns the QPlatformTheme::Font enumerators, without NFonts.'''
    with open(header, encoding='utf-8') as f:
        source = f.read()
    enum = re.search(r'enum\s+Font\s*\{(.*?)\}', source, re.DOTALL)
    assert enum, 'enum Font not found in ' + header
    body = re.sub(r'//[^\n]*|/\*.*?\*/', '', enum.group(1), flags=re.DOTALL)
    names = [item.split('=')[0].strip() for item in body.split(',')]
    return [name for name in names if name and name != 'NFonts']


def test_class_font_table_has_no_duplicates():
    '''Every enumerator and every class name appears once.'''
    rows = read_class_font_table()
    assert rows, 'platform_class_fonts[] is empty'
    enumerators = [row[0] for row in rows]
    class_names = [row[1] for row in rows]
    assert len(enumerators) == len(set(enumerators)), 'duplicate enumerator'
    assert len(class_names) == len(set(class_names)), 'duplicate class name'
    assert not set(enumerators) & EXCLUDED_ENUMERATORS, 'excluded enumerator in the table'


def test_class_font_table_matches_platform_theme(program_path):
    '''The table and the exclusion set cover exactly QPlatformTheme::Font.'''
    header = find_qpa_header(program_path)
    if not header:
        pytest.skip('qpa/qplatformtheme.h not found (set WS_QT_QPA_HEADER)')
    header_enumerators = read_font_enumerators(header)
    assert len(header_enumerators) == len(set(header_enumerators))

    table_enumerators = {row[0] for row in read_class_font_table()}
    unknown = table_enumerators - set(header_enumerators)
    assert not unknown, 'not in QPlatformTheme::Font: ' + ', '.join(sorted(unknown))
    missing = set(header_enumerators) - table_enumerators - EXCLUDED_ENUMERATORS
    assert not missing, 'new QPlatformTheme::Font enumerators: ' + ', '.join(sorted(missing))
    stale = EXCLUDED_ENUMERATORS - set(header_enumerators)
    assert not stale, 'excluded enumerators gone from Qt: ' + ', '.join(sorted(stale))
