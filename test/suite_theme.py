#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Theme system tests.

Validates that every bundled `theme.jsonc` under `resources/themes/*/`
loads cleanly against `resources/themes/theme.schema.json`, and that
the derived semantic tokens (SectionHeader, FieldBorder, HeaderBackground, hover
fills, filter validity tints, filter-busy fade) meet WCAG contrast targets
for every shipped theme in both light and dark modes.

The contrast assertions re-implement the relevant slice of
`ui/qt/utils/themes/color_math.cpp` and
`ui/qt/utils/themes/theme_token_handler.cpp` in Python so we can verify
the contract without launching Qt.  The reference QPalette values used
when a theme leaves a role unspecified mirror the SYSTEM_PALETTE
constant in
`analysis/welcome_page_theme_contrast/welcome_theme_contrast.html`, so
the assertions match what the mockup's WCAG readouts report for
variant C.

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

# Reference QPalette values used when a theme omits the role.  Matches
# SYSTEM_PALETTE in welcome_theme_contrast.html so the test asserts the
# same contract the mockup visualizes.  Real Qt defaults shift per
# platform/style, but the derivation contract is "produce something
# readable against whatever palette.base ends up being" — so the test
# pins a representative palette and asserts the derivation holds.
REFERENCE_PALETTE = {
    'light': {
        'base': '#ffffff',
        'text': '#000000',
        'window': '#ececec',
        'windowText': '#000000',
        'alternateBase': '#f5f5f5',
        'mid': '#a8a8a8',
        'midlight': '#d4d4d4',
        'shadow': '#5a5a5a',
    },
    'dark': {
        'base': '#1e1e1e',
        'text': '#ffffff',
        'window': '#323232',
        'windowText': '#ffffff',
        'alternateBase': '#2a2a2a',
        'mid': '#646464',
        'midlight': '#404040',
        'shadow': '#000000',
    },
}

# WCAG luminance threshold — above it, black-on-color is the better
# foreground; below, white.  Matches THRESHOLD_EQUALIBRIUM_WCAG in
# color_math.cpp.
WCAG_LUMINANCE_THRESHOLD = 0.179


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


# =====================================================================
# Color math — Python mirror of color_math.cpp, used by the contrast
# assertions below.  Kept close to the C++ to make divergence obvious.
# =====================================================================


def _hex_to_rgb(hex_str):
    s = hex_str.lstrip('#')
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))


def _rgb_to_hex(r, g, b):
    return f'#{max(0, min(255, round(r))):02x}{max(0, min(255, round(g))):02x}{max(0, min(255, round(b))):02x}'


def _srgb_to_linear(v):
    c = v / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_str):
    r, g, b = _hex_to_rgb(hex_str)
    return (0.2126 * _srgb_to_linear(r)
            + 0.7152 * _srgb_to_linear(g)
            + 0.0722 * _srgb_to_linear(b))


def contrast_ratio(a, b):
    la, lb = luminance(a), luminance(b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def contrasting_text(surface):
    return '#000000' if luminance(surface) > WCAG_LUMINANCE_THRESHOLD else '#ffffff'


def mix(a, b, ratio):
    ra, ga, ba = _hex_to_rgb(a)
    rb, gb, bb = _hex_to_rgb(b)
    return _rgb_to_hex(
        ra + (rb - ra) * ratio,
        ga + (gb - ga) * ratio,
        ba + (bb - ba) * ratio,
    )


def ensure_contrast(color, bg, min_ratio):
    '''Mirror of ColorMath::ensureContrast — binary-search a mix toward
    contrastingText(bg) until ratio is met.'''
    if contrast_ratio(color, bg) >= min_ratio:
        return color
    target = contrasting_text(bg)
    lo, hi = 0.0, 1.0
    for _ in range(24):
        m = (lo + hi) / 2.0
        if contrast_ratio(mix(color, target, m), bg) >= min_ratio:
            hi = m
        else:
            lo = m
    out = mix(color, target, hi)
    return out if contrast_ratio(out, bg) >= min_ratio else target


DISTINCT_SURFACE_RATIO = 1.5  # ColorMath::DistinctSurfaceRatio
READABLE_TEXT_RATIO = 4.5     # ColorMath::ReadableTextRatio


def darken(color, percent):
    '''Mirror of ColorMath::darken (integer channel scaling).'''
    r, g, b = _hex_to_rgb(color)
    return _rgb_to_hex(*(c * (100 - percent) // 100 for c in (r, g, b)))


def selection_hover_fill(base, selection):
    '''Mirror of ColorMath::selectionHoverFill.'''
    return ensure_contrast(mix(base, selection, 0.55), selection,
                           DISTINCT_SURFACE_RATIO)


def readable_text(text, surface):
    '''Mirror of ColorMath::readableText.'''
    return ensure_contrast(text, surface, READABLE_TEXT_RATIO)


def is_readable(text, surface):
    '''Mirror of ColorMath::isReadable.'''
    return contrast_ratio(text, surface) >= READABLE_TEXT_RATIO


def tint_with_alpha(base, accent, alpha255):
    '''Alpha-compositing accent (with alpha) over opaque base — same
    formula ColorMath::mix uses internally.'''
    return mix(base, accent, alpha255 / 255.0)


# =====================================================================
# Theme resolution — Python mirror of the slices of
# theme_token_handler.cpp the contrast assertions below need.
# =====================================================================


def _pick(theme, section, key, mode):
    s = theme.get(section)
    if not s:
        return None
    entry = s.get(key)
    if not entry:
        return None
    return entry.get(mode)


def _resolve_palette(theme, mode):
    out = dict(REFERENCE_PALETTE[mode])
    palette = theme.get('palette') or {}
    for role, pair in palette.items():
        if pair and pair.get(mode):
            out[role] = pair[mode]
    return out


def derived_tokens(theme, mode):
    '''Return the subset of derived tokens the contrast assertions need.

    Mirrors theme_token_handler.cpp's deriveAll() for the new tokens
    (SectionHeader, FieldBorder, Separator, HeaderBackground, Filter*)
    plus the inputs they depend on (HeaderText / HeaderTextMuted).
    '''
    palette = _resolve_palette(theme, mode)
    base = palette['base']
    mid = palette['mid']
    text = palette['text']

    brand_primary = _pick(theme, 'brand', 'primary', mode)
    accent_success = _pick(theme, 'accent', 'success', mode)
    accent_error   = _pick(theme, 'accent', 'error',   mode)

    # Welcome header: the palette's effective selection color darkened,
    # kept apart from the window, then clamped for the title (4.5) and
    # the faded version label (3.0). The selection color resolves as
    # palette.highlight, else packets.selection, else brand.primary;
    # highlightedText is pinned or the
    # contrasting text of that color, lifted to 4.5:1 against it.
    highlight = (_pick(theme, 'palette', 'highlight', mode)
                 or _pick(theme, 'packets', 'selection', mode)
                 or brand_primary)
    highlight_text = readable_text(
        _pick(theme, 'palette', 'highlightedText', mode)
        or contrasting_text(highlight), highlight)
    window = palette['window']
    header_bg = ensure_contrast(darken(highlight, 40), window,
                                DISTINCT_SURFACE_RATIO)
    text_on_dark = (highlight_text
                    if is_readable(highlight_text, header_bg)
                    else contrasting_text(header_bg))
    header_bg = ensure_contrast(header_bg, text_on_dark, READABLE_TEXT_RATIO)
    text_on_dark_muted = ensure_contrast(mix(text_on_dark, header_bg, 0.25),
                                         header_bg, 3.0)

    section_header = ensure_contrast(mid, base, 4.5)
    field_border   = ensure_contrast(mid, base, 3.0)

    explicit_sep = (theme.get('separator') or {}).get(mode)
    separator    = explicit_sep or mix(base, mid, 135 / 255.0)

    explicit_filter_valid   = _pick(theme, 'filter', 'valid',   mode)
    explicit_filter_invalid = _pick(theme, 'filter', 'invalid', mode)
    explicit_filter_busy    = _pick(theme, 'filter', 'busy',    mode)
    explicit_filter_busy_tx = _pick(theme, 'filter', 'busyText',mode)

    filter_valid   = explicit_filter_valid   or tint_with_alpha(base, accent_success, 85)
    filter_invalid = explicit_filter_invalid or tint_with_alpha(base, accent_error,   85)
    explicit_filter_deprecated = _pick(theme, 'filter', 'deprecated', mode)
    accent_warning = _pick(theme, 'accent', 'warning', mode)
    filter_deprecated = (explicit_filter_deprecated
                         or tint_with_alpha(base, accent_warning, 85))

    # Secondary text: Text faded 40% toward Base, lifted to 4.5:1.
    muted_text = ensure_contrast(mix(text, base, 0.40), base, 4.5)

    # Link follows the highlight, lifted to 4.5:1 against Base.
    link = readable_text(highlight, base)

    # Ignored / hidden rows fade WindowText toward Base unless the
    # theme pins them.
    window_text = palette['windowText']
    ignored_text = (_pick(theme, 'packets', 'ignoredText', mode)
                    or mix(base, window_text, 0.50))
    hidden = (_pick(theme, 'packets', 'hidden', mode)
              or mix(base, window_text, 0.40))

    filter_busy      = explicit_filter_busy    or base
    filter_busy_text = explicit_filter_busy_tx or mix(text, base, 0.5)

    return {
        'base':              base,
        'window':            window,
        'highlight':         highlight,
        'highlightText':     highlight_text,
        'text':              text,
        'sectionHeader':     section_header,
        'fieldBorder':       field_border,
        'separator':         separator,
        'headerText':         text_on_dark,
        'headerTextMuted':    text_on_dark_muted,
        'headerBackground':  header_bg,
        'filterValid':       filter_valid,
        'filterInvalid':     filter_invalid,
        'filterDeprecated':  filter_deprecated,
        'warningBackground': filter_deprecated,
        'mutedText':         muted_text,
        'link':              link,
        'ignoredText':       ignored_text,
        'hidden':            hidden,
        'textOnFilterValid':      contrasting_text(filter_valid),
        'textOnFilterInvalid':    contrasting_text(filter_invalid),
        'textOnFilterDeprecated': contrasting_text(filter_deprecated),
        'filterBusy':        filter_busy,
        'filterBusyText':    filter_busy_text,
    }


def _load_theme(theme_path):
    return json.loads(_strip_jsonc(theme_path.read_text()))


# =====================================================================
# ensureContrast math contract
# =====================================================================


class TestEnsureContrast:
    @pytest.mark.parametrize('color,bg,min_ratio', [
        ('#a8a8a8', '#ffffff', 4.5),   # SectionHeader on light base
        ('#646464', '#1e1e1e', 4.5),   # SectionHeader on dark base
        ('#a8a8a8', '#ffffff', 3.0),   # FieldBorder on light base
        ('#646464', '#1e1e1e', 3.0),   # FieldBorder on dark base
        ('#5b9ee6', '#000000', 4.5),   # bright primary vs headerText
        ('#0e9aa7', '#000000', 3.0),   # Stratoshark teal vs headerTextMuted
        ('#204a87', '#000000', 4.5),   # already passes — short-circuit
    ])
    def test_meets_target(self, color, bg, min_ratio):
        out = ensure_contrast(color, bg, min_ratio)
        assert contrast_ratio(out, bg) >= min_ratio - 1e-6

    def test_short_circuits_when_already_meets_target(self):
        '''If the input already meets the target, ensureContrast returns
        it unchanged.  This is what spares "good" themes from drift.'''
        assert ensure_contrast('#000000', '#ffffff', 4.5) == '#000000'


# =====================================================================
# Derived-token contrast — per shipped theme × mode.
# =====================================================================


def _theme_mode_params():
    '''(theme_path, mode) pairs for every bundled theme × {light, dark}.'''
    params = []
    for path in _bundled_themes():
        params.append(pytest.param(path, 'light', id=f'{path.parent.name}-light'))
        params.append(pytest.param(path, 'dark',  id=f'{path.parent.name}-dark'))
    return params


class TestDerivedContrast:
    '''Per design.md §7, for every shipped theme × both modes the
    derived tokens must meet their target contrast ratios against the
    surface they sit on.  Without these assertions, a theme can ship
    that looks fine in one mode but goes invisible (SectionHeader on
    dark base) or unreadable (header bar vs version label) in
    the other — exactly the class of bug the new derivations close.'''

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_section_header_meets_aa_against_base(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['sectionHeader'], t['base']) >= 4.5

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_field_border_meets_non_text_contrast(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['fieldBorder'], t['base']) >= 3.0

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_header_background_holds_title(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['headerText'], t['headerBackground']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_header_background_holds_muted_version(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['headerTextMuted'], t['headerBackground']) >= 3.0

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_header_background_stands_out_from_window(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['headerBackground'], t['window']) >= DISTINCT_SURFACE_RATIO

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_filter_valid_holds_its_auto_foreground(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['textOnFilterValid'], t['filterValid']) >= 4.5

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_filter_invalid_holds_its_auto_foreground(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['textOnFilterInvalid'], t['filterInvalid']) >= 4.5

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_filter_deprecated_holds_its_auto_foreground(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['textOnFilterDeprecated'],
                              t['filterDeprecated']) >= 4.5

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_muted_text_meets_aa_against_base(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['mutedText'], t['base']) >= 4.5

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_link_meets_aa_against_base(self, theme_path, mode):
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['link'], t['base']) >= 4.5

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_filter_busy_text_meets_low_contrast_target(self, theme_path, mode):
        '''Filter-busy fg is intentionally faded (matches QLineEdit's
        placeholder fade); 3.0:1 is the lower target for "transient
        state" text.'''
        t = derived_tokens(_load_theme(theme_path), mode)
        assert contrast_ratio(t['filterBusyText'], t['filterBusy']) >= 3.0


class TestHoverFill:
    '''The hover fill derived from a selection color must stay visibly
    different from the selection and keep its text readable.'''

    @staticmethod
    def _cases(theme, mode):
        t = derived_tokens(theme, mode)
        text = t['text']
        for role in ('selection', 'inactive'):
            sel = _pick(theme, 'packets', role, mode)
            if sel:
                yield role, t['base'], sel, text
        yield 'highlight', t['base'], t['highlight'], text

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_hover_fill_distinct_from_selection(self, theme_path, mode):
        for role, base, sel, _ in self._cases(_load_theme(theme_path), mode):
            fill = selection_hover_fill(base, sel)
            assert contrast_ratio(fill, sel) >= DISTINCT_SURFACE_RATIO, role

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_hover_text_readable(self, theme_path, mode):
        for role, base, sel, text in self._cases(_load_theme(theme_path), mode):
            fill = selection_hover_fill(base, sel)
            assert contrast_ratio(readable_text(text, fill), fill) >= READABLE_TEXT_RATIO, role


class TestInvertedHighlight:
    @pytest.mark.parametrize('mode', ['light', 'dark'])
    def test_highlight_stays_brand_primary(self, mode):
        '''Inverted selects in its brand color on purpose; its
        packets.selection would otherwise take over the highlight.'''
        path = next(p for p in _bundled_themes() if p.parent.name == 'inverted')
        theme = _load_theme(path)
        assert (derived_tokens(theme, mode)['highlight'].lower()
                == _pick(theme, 'brand', 'primary', mode).lower())


class TestSelectionText:
    '''Selection text is checked centrally (palette builder, token
    handler): pinned or derived it is lifted to 4.5:1 on its fill.  The
    shipped themes are designed so that check leaves their pins alone.
    These tests fail when a theme value change makes a pin depend on the
    check, which would turn the designed text color into a grey.'''

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_highlighted_text_pin_reads_on_highlight(self, theme_path, mode):
        theme = _load_theme(theme_path)
        pin = _pick(theme, 'palette', 'highlightedText', mode)
        if pin:
            assert is_readable(pin, derived_tokens(theme, mode)['highlight'])

    @pytest.mark.parametrize('theme_path,mode', _theme_mode_params())
    def test_packet_state_text_pins_read_on_fill(self, theme_path, mode):
        theme = _load_theme(theme_path)
        for state in ('selection', 'inactive', 'marked'):
            fill = _pick(theme, 'packets', state, mode)
            pin = _pick(theme, 'packets', state + 'Text', mode)
            if fill and pin:
                assert is_readable(pin, fill), state


class TestStratosharkMarked:
    @pytest.mark.parametrize('mode', ['light', 'dark'])
    def test_marked_stands_apart_from_selection_states(self, mode):
        '''A marked row must not read as the selected or the unfocused
        selected row; Stratoshark dark once used one near-black teal for
        all three.  Asserted for Stratoshark only: other shipped themes
        do not meet it yet.'''
        path = next(p for p in _bundled_themes() if p.parent.name == 'stratoshark')
        theme = _load_theme(path)
        marked = _pick(theme, 'packets', 'marked', mode)
        for state in ('selection', 'inactive'):
            assert (contrast_ratio(marked, _pick(theme, 'packets', state, mode))
                    >= DISTINCT_SURFACE_RATIO), state


# =====================================================================
# Migration / schema flexibility checks
# =====================================================================


class TestSchemaFlexibility:
    def test_theme_without_filter_or_separator_parses(self):
        '''Per design, filter and separator are both optional.'''
        jsonschema = pytest.importorskip('jsonschema')
        schema = json.loads(SCHEMA_PATH.read_text())
        minimal = {
            'meta':  {'name': 'Test', 'version': 1},
            'brand': {
                'primary': {'light': '#204a87', 'dark': '#5b9ee6'},
            },
            'accent': {
                'success': {'light': '#73d216', 'dark': '#8ae234'},
                'warning': {'light': '#f57900', 'dark': '#fcaf3e'},
                'error':   {'light': '#cc0000', 'dark': '#ef2929'},
                'info':    {'light': '#3465a4', 'dark': '#729fcf'},
            },
        }
        jsonschema.Draft202012Validator(schema).validate(minimal)

    def test_theme_with_explicit_filter_and_separator_parses(self):
        '''The Wireshark theme ships filter; Stratoshark ships both —
        if either schema rule regresses this catches it directly.'''
        jsonschema = pytest.importorskip('jsonschema')
        schema = json.loads(SCHEMA_PATH.read_text())
        full = {
            'meta':  {'name': 'Test', 'version': 1},
            'brand': {
                'primary': {'light': '#204a87', 'dark': '#5b9ee6'},
            },
            'accent': {
                'success': {'light': '#73d216', 'dark': '#8ae234'},
                'warning': {'light': '#f57900', 'dark': '#fcaf3e'},
                'error':   {'light': '#cc0000', 'dark': '#ef2929'},
                'info':    {'light': '#3465a4', 'dark': '#729fcf'},
            },
            'filter': {
                'valid':      {'light': '#296700', 'dark': '#3a7a06'},
                'invalid':    {'light': '#5e0000', 'dark': '#7a1818'},
                'deprecated': {'light': '#cc7700', 'dark': '#cc7700'},
                'busy':       {'light': '#eeeeee', 'dark': '#222222'},
                'busyText':   {'light': '#888888', 'dark': '#aaaaaa'},
                'history':    {'light': '#555753', 'dark': '#d3d7cf'},
            },
            'separator': {'light': '#d6e3e6', 'dark': '#1f3338'},
        }
        jsonschema.Draft202012Validator(schema).validate(full)

    def test_palette_mid_override_still_respected(self):
        '''Migration check: themes that override palette.mid still get
        that override applied (selective-merge semantics unchanged).
        Asserted by resolving the palette and checking the override wins
        — the existing parser path is untouched by the new sections.'''
        theme = {
            'palette': {'mid': {'light': '#5a5a5a', 'dark': '#a0a0a0'}}
        }
        assert _resolve_palette(theme, 'light')['mid'] == '#5a5a5a'
        assert _resolve_palette(theme, 'dark')['mid']  == '#a0a0a0'
