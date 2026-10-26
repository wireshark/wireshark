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
the contract without launching Qt.  Every ratio constant is read from
`ui/qt/utils/themes/color_math.h`, so the tests follow the header.  The
reference QPalette values used
when a theme leaves a role unspecified mirror the SYSTEM_PALETTE
constant in
`analysis/welcome_page_theme_contrast/welcome_theme_contrast.html`, so
the assertions match what the mockup's WCAG readouts report for
variant C.

`jsonschema` is an optional test dependency; tests self-skip when the
package is not installed so existing `pip install pytest pytest-xdist`
setups keep working.

Themes that list `meta.colorVision` are checked for distinguishable semantic colors
and strong graph slots, and every expert severity icon has its own shape.

The derived-token assertions run once per contrast level (Standard and
High, the two ratio sets of color_math.h).  A theme that declares
`"contrast": "high"` runs at High only, because the application never
derives it with the Standard set.  At High the mirror also applies the
high-contrast rules of theme_token_handler.cpp and
theme_palette_builder.cpp, where readability wins over pinned colors.
'''

import itertools
import json
import math
import os
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
COLOR_MATH_H = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes' / 'color_math.h'
SCHEMA_PATH = REPO_ROOT / 'resources' / 'themes' / 'theme.schema.json'
THEME_ROOT = REPO_ROOT / 'resources' / 'themes'
THEME_README = THEME_ROOT / 'README.md'
THEME_PARSER_CPP = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes' / 'theme_parser.cpp'

# Reference QPalette values used when a theme omits the role.  Matches
# SYSTEM_PALETTE in welcome_theme_contrast.html so the test asserts the
# same contract the mockup visualizes.  Real Qt defaults shift per
# platform/style, but the derivation contract is "produce something
# readable against whatever palette.base ends up being" — so the test
# pins a representative palette and asserts the derivation holds.
REFERENCE_PALETTES = {}

REFERENCE_PALETTES['generic'] = {
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

# The second palette reproduces the platform where Mid sits below Base
# (macOS dark mode, Qt 6.11): the plain Base/Mid mix is then
# indistinguishable from the page.  Shadow is copied from the generic
# palette, it was not measured.
REFERENCE_PALETTES['macos-qt611'] = {
    'light': {
        'base': '#ffffff',
        'text': '#000000',
        'window': '#ffffff',
        'windowText': '#000000',
        'alternateBase': '#ffffff',
        'mid': '#b6b6b6',
        'midlight': '#ffffff',
        'shadow': '#5a5a5a',
    },
    'dark': {
        'base': '#171717',
        'text': '#ffffff',
        'window': '#1e1e1e',
        'windowText': '#ffffff',
        'alternateBase': '#8e8e8e',
        'mid': '#151515',
        'midlight': '#1f1f1f',
        'shadow': '#000000',
    },
}

# WCAG luminance threshold — above it, black-on-color is the better
# foreground; below, white.  Matches THRESHOLD_EQUALIBRIUM_WCAG in
# color_math.cpp.
WCAG_LUMINANCE_THRESHOLD = 0.179


def _color_math_constant(name):
    '''Value of `static constexpr qreal NAME` in color_math.h.'''
    m = re.search(r'static\s+constexpr\s+qreal\s+' + re.escape(name)
                  + r'\s*=\s*([0-9.]+)\s*;', COLOR_MATH_H.read_text(encoding='utf-8'))
    if not m:
        raise AssertionError(f'{name} not found in {COLOR_MATH_H}')
    return float(m.group(1))


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

        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        data = json.loads(_strip_jsonc(theme_path.read_text(encoding='utf-8')))
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


# The derivation ratios: module global, color_math.h constant (its High
# value is the constant of the same name with a "High" suffix) and the row
# label of the contrast table in resources/themes/README.md.
RATIOS = (
    ('DISTINCT_SURFACE_RATIO', 'DistinctSurfaceRatio', 'distinct surface'),
    ('READABLE_TEXT_RATIO', 'ReadableTextRatio', 'readable text'),
    ('CARD_SURFACE_RATIO_DARK', 'CardSurfaceRatioDark', 'dark card surface'),
    ('DIVIDER_RATIO', 'DividerRatio', 'divider'),
    ('NON_TEXT_RATIO', 'NonTextRatio', 'non-text'),
    ('LARGE_TEXT_RATIO', 'LargeTextRatio', 'large text'),
    ('ICON_CONTRAST_RATIO', 'IconContrastRatio', 'icon'),
)

# The ratio set of each contrast level, keyed like the theme `contrast`
# field values.
RATIO_SETS = {
    'standard': {name: _color_math_constant(constant) for name, constant, _ in RATIOS},
    'high': {name: _color_math_constant(constant + 'High') for name, constant, _ in RATIOS},
}

# The active level and its ratios.  The autouse fixture
# _contrast_level_ratios switches them per test from the test's
# `contrast` parameter, so the helpers below read the active set.
CONTRAST_LEVEL = 'standard'
DISTINCT_SURFACE_RATIO = RATIO_SETS['standard']['DISTINCT_SURFACE_RATIO']
READABLE_TEXT_RATIO = RATIO_SETS['standard']['READABLE_TEXT_RATIO']
CARD_SURFACE_RATIO_DARK = RATIO_SETS['standard']['CARD_SURFACE_RATIO_DARK']
DIVIDER_RATIO = RATIO_SETS['standard']['DIVIDER_RATIO']
NON_TEXT_RATIO = RATIO_SETS['standard']['NON_TEXT_RATIO']
LARGE_TEXT_RATIO = RATIO_SETS['standard']['LARGE_TEXT_RATIO']
ICON_CONTRAST_RATIO = RATIO_SETS['standard']['ICON_CONTRAST_RATIO']


@pytest.fixture(autouse=True)
def _contrast_level_ratios(request, monkeypatch):
    '''Make the ratio set of the test's `contrast` parameter (Standard
    when the test has none) the module's active set.'''
    callspec = getattr(request.node, 'callspec', None)
    level = callspec.params.get('contrast', 'standard') if callspec else 'standard'
    module = sys.modules[__name__]
    monkeypatch.setattr(module, 'CONTRAST_LEVEL', level)
    for name, value in RATIO_SETS[level].items():
        monkeypatch.setattr(module, name, value)
    return level


def high_contrast():
    '''True when the active level is High, where the high-contrast rules run.'''
    return CONTRAST_LEVEL == 'high'


def darken(color, percent):
    '''Mirror of ColorMath::darken (integer channel scaling).'''
    r, g, b = _hex_to_rgb(color)
    return _rgb_to_hex(*(c * (100 - percent) // 100 for c in (r, g, b)))


def lighten(color, percent):
    '''Mirror of ColorMath::lighten (integer channel scaling toward white).'''
    r, g, b = _hex_to_rgb(color)
    return _rgb_to_hex(*(c + (255 - c) * percent // 100 for c in (r, g, b)))


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


def readable_on_fill(text, fill, min_ratio):
    '''Mirror of ColorMath::readableOnFill: (text, fill), the text lifted
    first, the fill moved away from it only when the text cannot reach
    `min_ratio`.'''
    text = ensure_contrast(text, fill, min_ratio)
    if contrast_ratio(text, fill) < min_ratio:
        fill = ensure_contrast(fill, text, min_ratio)
    return text, fill


def readable_fill(fill):
    '''Mirror of ColorMath::readableFill: the fill moved away from its
    contrasting text until that text reads at READABLE_TEXT_RATIO.'''
    text = contrasting_text(fill)
    if contrast_ratio(text, fill) >= READABLE_TEXT_RATIO:
        return fill
    return ensure_contrast(fill, text, READABLE_TEXT_RATIO)


def selection_hover(base, selection, text):
    '''Mirror of ColorMath::selectionHover: (fill, text) of a hovered row.
    At High the fill moves toward readability of `text` only while it
    stays DISTINCT_SURFACE_RATIO from the selection.'''
    fill = selection_hover_fill(base, selection)
    if high_contrast() and contrast_ratio(text, fill) < READABLE_TEXT_RATIO:
        lifted = ensure_contrast(fill, text, READABLE_TEXT_RATIO)
        if contrast_ratio(lifted, selection) >= DISTINCT_SURFACE_RATIO:
            fill = lifted
    return fill, readable_text(text, fill)


def bar_for_faded_label(bar, title, min_ratio):
    '''Mirror of barForFadedLabel() in theme_token_handler.cpp: the welcome
    header bar moved toward contrasting_text(title) until the title faded
    25 % toward the bar reads at `min_ratio`.'''
    def label_reads(candidate):
        return contrast_ratio(mix(title, candidate, 0.25), candidate) >= min_ratio
    if label_reads(bar):
        return bar
    target = contrasting_text(title)
    lo, hi = 0.0, 1.0
    for _ in range(24):
        m = (lo + hi) / 2.0
        if label_reads(mix(bar, target, m)):
            hi = m
        else:
            lo = m
    return mix(bar, target, hi)


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


def _resolve_palette(theme, mode, reference='generic'):
    out = dict(REFERENCE_PALETTES[reference][mode])
    palette = theme.get('palette') or {}
    for role, pair in palette.items():
        if pair and pair.get(mode):
            out[role] = pair[mode]
    return out


# Expert severity fill keys and the accent each derives from when the
# theme leaves it unpinned (ExpertNone has no theme key).
EXPERT_FILL_ACCENTS = (
    ('none', 'info'),
    ('comment', 'success'),
    ('chat', 'info'),
    ('note', 'info'),
    ('warn', 'warning'),
    ('error', 'error'),
)

# Translucent derived expert fills: alpha of ColorMath::withAlpha(accent, 102).
EXPERT_FILL_ALPHA = 102


def expert_tokens(theme, mode, base):
    '''(foreground, {key: fill as drawn on Base}) of the expert severities.

    Mirrors deriveAll(): an unpinned fill is the accent at alpha 102, its
    foreground the contrasting text of the translucent comment fill over
    the mode's backdrop (ColorMath::contrastingText).  At High a fill on
    which the foreground misses READABLE_TEXT_RATIO becomes its composite
    on Base, moved until the foreground reads.'''
    backdrop = '#000000' if mode == 'dark' else '#ffffff'
    foreground = (_pick(theme, 'expert', 'foreground', mode)
                  or contrasting_text(tint_with_alpha(
                      backdrop, _pick(theme, 'accent', 'success', mode), EXPERT_FILL_ALPHA)))
    fills = {}
    for key, accent in EXPERT_FILL_ACCENTS:
        pin = _pick(theme, 'expert', key, mode)
        fill = pin or tint_with_alpha(base, _pick(theme, 'accent', accent, mode),
                                      EXPERT_FILL_ALPHA)
        if high_contrast():
            fill = ensure_contrast(fill, foreground, READABLE_TEXT_RATIO)
        fills[key] = fill
    return foreground, fills


def conversation_tokens(theme, mode, base):
    '''{(text key, fill key): (text, fill)} of the Follow Stream sides.

    Mirrors deriveAll(): the theme's pins, else accent.error (client) and
    brand.primary (server) tinted on Base, with text darkened (light) or
    lightened (dark).  At High each pair goes through readable_on_fill().'''
    pairs = {}
    for side, accent in (('client', _pick(theme, 'accent', 'error', mode)),
                         ('server', _pick(theme, 'brand', 'primary', mode))):
        fill = (_pick(theme, 'conversation', side, mode)
                or tint_with_alpha(base, accent, 102))
        text = (_pick(theme, 'conversation', side + 'Text', mode)
                or (darken(accent, 30) if mode == 'light' else lighten(accent, 50)))
        if high_contrast():
            text, fill = readable_on_fill(text, fill, READABLE_TEXT_RATIO)
        pairs[(side + 'Text', side)] = (text, fill)
    return pairs


def update_bar_tokens(theme, mode):
    '''The welcome page update bar tokens, all derived from accent.success.

    Mirrors deriveAll().  At High the bar text and links are lifted to
    READABLE_TEXT_RATIO on the bar (the bar giving way when its text still
    misses), the download button states move until TextOnSuccess reads on
    them, and the dot keeps NON_TEXT_RATIO from the bar.'''
    success = _pick(theme, 'accent', 'success', mode)
    t = {
        'background': darken(success, 60),
        'text': lighten(success, 50),
        'textHighlight': lighten(success, 70),
        'link': lighten(success, 30),
        'linkHover': lighten(success, 50),
        'linkPressed': darken(success, 20),
        'buttonBg': success,
        'buttonHover': darken(success, 8),
        'buttonPressed': darken(success, 16),
        'buttonText': contrasting_text(success),
        'dot': success,
    }
    if high_contrast():
        t['text'] = ensure_contrast(t['text'], t['background'], READABLE_TEXT_RATIO)
        t['background'] = ensure_contrast(t['background'], t['text'], READABLE_TEXT_RATIO)
        for key in UPDATE_BAR_TEXT_KEYS[1:]:
            t[key] = ensure_contrast(t[key], t['background'], READABLE_TEXT_RATIO)
        for key in UPDATE_BAR_BUTTON_KEYS:
            t[key] = ensure_contrast(t[key], t['buttonText'], READABLE_TEXT_RATIO)
        t['dot'] = ensure_contrast(success, t['background'], NON_TEXT_RATIO)
    return t


# Update bar tokens drawn as text on the bar, and the button fills that
# carry TextOnSuccess.
UPDATE_BAR_TEXT_KEYS = ('text', 'textHighlight', 'link', 'linkHover', 'linkPressed')
UPDATE_BAR_BUTTON_KEYS = ('buttonBg', 'buttonHover', 'buttonPressed')


def packet_state_fill(theme, mode, state):
    '''The fill of a pinned packet state (selection, inactive, marked) as
    deriveAll() leaves it, None when the theme does not pin it.  Its text
    is the pin or the contrasting text, lifted to READABLE_TEXT_RATIO;
    at High the fill moves when the text cannot get there.'''
    fill = _pick(theme, 'packets', state, mode)
    if not fill:
        return None
    text = readable_text(_pick(theme, 'packets', state + 'Text', mode)
                         or contrasting_text(fill), fill)
    if high_contrast():
        text, fill = readable_on_fill(text, fill, READABLE_TEXT_RATIO)
    return fill


def derived_tokens(theme, mode, reference='generic'):
    '''Return the subset of derived tokens the contrast assertions need.

    Mirrors theme_token_handler.cpp's deriveAll() for the new tokens
    (SectionHeader, FieldBorder, Separator, HeaderBackground, Filter*)
    plus the inputs they depend on (HeaderText / HeaderTextMuted), and the
    expert, conversation and update bar tokens the High rules move.
    '''
    palette = _resolve_palette(theme, mode, reference)
    base = palette['base']
    mid = palette['mid']
    text = palette['text']

    brand_primary = _pick(theme, 'brand', 'primary', mode)
    accent_success = _pick(theme, 'accent', 'success', mode)
    accent_error   = _pick(theme, 'accent', 'error',   mode)

    # Welcome header: the palette's effective selection color darkened,
    # kept apart from the window, then clamped for the title
    # (READABLE_TEXT_RATIO) and the faded version label
    # (LARGE_TEXT_RATIO). The selection color resolves as
    # palette.highlight, else packets.selection, else brand.primary;
    # highlightedText is pinned, else packets.selectionText when the
    # color is packets.selection, else the contrasting text of that
    # color, lifted to READABLE_TEXT_RATIO against it.
    # At High the pair goes through readable_on_fill(): when the text
    # cannot reach READABLE_TEXT_RATIO the highlight itself moves.
    # The header bar then also moves until the faded version label reads
    # at READABLE_TEXT_RATIO (its target at High).
    highlight_pin = _pick(theme, 'palette', 'highlight', mode)
    selection = _pick(theme, 'packets', 'selection', mode)
    highlight = highlight_pin or selection or brand_primary
    highlight_text_source = (
        _pick(theme, 'palette', 'highlightedText', mode)
        or (not highlight_pin and selection
            and _pick(theme, 'packets', 'selectionText', mode))
        or contrasting_text(highlight))
    if high_contrast():
        highlight_text, highlight = readable_on_fill(
            highlight_text_source, highlight, READABLE_TEXT_RATIO)
    else:
        highlight_text = readable_text(highlight_text_source, highlight)
    window = palette['window']
    header_bg = ensure_contrast(darken(highlight, 40), window,
                                DISTINCT_SURFACE_RATIO)
    text_on_dark = (highlight_text
                    if is_readable(highlight_text, header_bg)
                    else contrasting_text(header_bg))
    header_bg = ensure_contrast(header_bg, text_on_dark, READABLE_TEXT_RATIO)
    if high_contrast():
        header_bg = bar_for_faded_label(header_bg, text_on_dark, READABLE_TEXT_RATIO)
    text_on_dark_muted = ensure_contrast(
        mix(text_on_dark, header_bg, 0.25), header_bg,
        READABLE_TEXT_RATIO if high_contrast() else LARGE_TEXT_RATIO)

    section_header = readable_text(mid, base)
    section_header_hover = readable_text(brand_primary, base)
    field_border   = ensure_contrast(mid, base, NON_TEXT_RATIO)

    explicit_sep = (theme.get('separator') or {}).get(mode)
    separator    = explicit_sep or ensure_contrast(
        mix(base, mid, 135 / 255.0), base, DIVIDER_RATIO)

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
    # At High each tint, pinned or derived, moves until its black or
    # white text reads at READABLE_TEXT_RATIO.
    if high_contrast():
        filter_valid = readable_fill(filter_valid)
        filter_invalid = readable_fill(filter_invalid)
        filter_deprecated = readable_fill(filter_deprecated)

    # Secondary text: Text faded 40% toward Base, lifted to
    # READABLE_TEXT_RATIO.
    muted_text = ensure_contrast(mix(text, base, 0.40), base,
                                 READABLE_TEXT_RATIO)

    # Link follows the highlight, lifted to READABLE_TEXT_RATIO against Base.
    link = readable_text(highlight, base)

    # Ignored / hidden rows fade WindowText toward Base unless the
    # theme pins them.
    window_text = palette['windowText']
    ignored_text = (_pick(theme, 'packets', 'ignoredText', mode)
                    or mix(base, window_text, 0.50))
    hidden = (_pick(theme, 'packets', 'hidden', mode)
              or mix(base, window_text, 0.40))
    # At High both are lifted against Base, pins included.
    if high_contrast():
        ignored_text = ensure_contrast(ignored_text, base, READABLE_TEXT_RATIO)
        hidden = ensure_contrast(hidden, base, READABLE_TEXT_RATIO)

    filter_busy      = explicit_filter_busy    or base
    # Pinned or derived, the busy text is lifted to LARGE_TEXT_RATIO
    # against the busy fill at every contrast level.
    filter_busy_text = ensure_contrast(
        explicit_filter_busy_tx or mix(text, base, 0.5),
        filter_busy, LARGE_TEXT_RATIO)

    # Raised card on Base.  The source is the theme's own alternateBase
    # pin only (never the platform palette), else Base.  Dark mode lifts
    # it away from Base; light mode uses it as-is.
    card_source = _pick(theme, 'palette', 'alternateBase', mode) or base
    card = (ensure_contrast(card_source, base, CARD_SURFACE_RATIO_DARK)
            if mode == 'dark' else card_source)
    card_border = ensure_contrast(separator, card, DIVIDER_RATIO)
    card_section_header = readable_text(section_header, card)
    card_section_header_hover = readable_text(section_header_hover, card)
    # Dark: link lifted against the card until it reads on the card's hover
    # fill; the fill gives way only when the link cannot get there.
    # Light: the link keeps the application link color (lifted only if it
    # does not read on the card) and the hover fill moves toward the card
    # until the link reads on it at LARGE_TEXT_RATIO.
    card_link_hover_base = selection_hover_fill(card, highlight)
    if mode == 'dark':
        card_link = ensure_contrast(
            link, card,
            READABLE_TEXT_RATIO * contrast_ratio(card_link_hover_base, card))
        card_link_hover = ensure_contrast(
            card_link_hover_base, card_link, READABLE_TEXT_RATIO)
    else:
        card_link = readable_text(link, card)
        card_link_hover = ensure_contrast(
            card_link_hover_base, card_link, LARGE_TEXT_RATIO)
    card_focus_ring = readable_text(highlight, card)
    overlay_card = card if luminance(card) > luminance(base) else base
    overlay_card_border = ensure_contrast(separator, overlay_card, DIVIDER_RATIO)
    splash_fill = ensure_contrast(brand_primary, overlay_card_border,
                                  NON_TEXT_RATIO)
    syntax_key = readable_text(mid, base)
    expert_foreground, expert_fills = expert_tokens(theme, mode, base)

    return {
        'expertForeground':  expert_foreground,
        'expertFills':       expert_fills,
        'conversation':      conversation_tokens(theme, mode, base),
        'updateBar':         update_bar_tokens(theme, mode),
        'base':              base,
        'window':            window,
        'highlight':         highlight,
        'highlightText':     highlight_text,
        'text':              text,
        'sectionHeader':     section_header,
        'fieldBorder':       field_border,
        'separator':         separator,
        'separatorPinned':   bool(explicit_sep),
        'card':              card,
        'cardBorder':        card_border,
        'cardSectionHeader': card_section_header,
        'cardSectionHeaderHover': card_section_header_hover,
        'cardLink':          card_link,
        'cardLinkHover':     card_link_hover,
        'cardFocusRing':     card_focus_ring,
        'overlayCard':       overlay_card,
        'overlayCardBorder': overlay_card_border,
        'splashFill':        splash_fill,
        'syntaxKey':         syntax_key,
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
    return json.loads(_strip_jsonc(theme_path.read_text(encoding='utf-8')))


# =====================================================================
# Learn card action buttons — Python mirror of
# ThemeStyler::buttonStyleSheet() and LearnCardWidget::resolveButtonColor().
# =====================================================================

LEARN_CARD_JSON = REPO_ROOT / 'resources' / 'json' / 'learn_card.json'
LEARN_CARD_SCHEMA = REPO_ROOT / 'resources' / 'json' / 'learn_card.schema.json'
THEME_MANAGER_H = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'theme_manager.h'


def _theme_token_names():
    '''Enumerator names of `enum ThemeToken` in theme_manager.h, in
    declaration order.  Comments and preprocessor lines (the Qt version
    block inside the enum) are dropped; `= value` initializers are
    accepted.'''
    text = THEME_MANAGER_H.read_text(encoding='utf-8')
    body = re.search(r'enum\s+ThemeToken\s*\{(.*?)\};', text, re.DOTALL).group(1)
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    body = re.sub(r'//[^\n]*', '', body)
    body = re.sub(r'^\s*#.*$', '', body, flags=re.M)
    return [m.group(1) for m in
            re.finditer(r'\b([A-Za-z_]\w*)\s*(?:=[^,]*)?(?:,|$)', body)]


def _learn_card_buttons():
    return json.loads(LEARN_CARD_JSON.read_text(encoding='utf-8'))['buttons']


def _learn_button_seed(theme, color, mode):
    '''Seed color of a button: hex as is, a token name via the theme's
    own top-level sections (the first part of the name is the section,
    the rest the key).  None when it does not resolve.'''
    if color.startswith('#'):
        return color
    lowered = color.lower()
    for section in sorted(theme, key=len, reverse=True):
        if not isinstance(theme[section], dict) or not lowered.startswith(section.lower()):
            continue
        rest = lowered[len(section):]
        for key in theme[section]:
            if key.lower() == rest:
                return _pick(theme, section, key, mode)
    return None


def _learn_button_fill(theme, color, mode):
    seed = _learn_button_seed(theme, color, mode)
    if seed is None:
        return None
    return ensure_contrast(seed, '#ffffff', READABLE_TEXT_RATIO)


class TestLearnCardButtons:
    def test_json_matches_schema(self):
        '''learn_card.json validates against learn_card.schema.json.'''
        jsonschema = pytest.importorskip('jsonschema')
        schema = json.loads(LEARN_CARD_SCHEMA.read_text(encoding='utf-8'))
        data = json.loads(LEARN_CARD_JSON.read_text(encoding='utf-8'))
        validator = jsonschema.validators.validator_for(schema)
        validator(schema).validate(data)

    def test_token_names_exist_in_enum(self):
        '''Every non-hex button color names a ThemeToken enumerator.'''
        names = _theme_token_names()
        assert 'AccentError' in names  # the parser found the enum
        for button in _learn_card_buttons():
            if not button['color'].startswith('#'):
                assert button['color'] in names, button['label']

    @pytest.mark.parametrize('theme_path', _bundled_themes(),
                             ids=lambda p: p.parent.name)
    @pytest.mark.parametrize('mode', ['light', 'dark'])
    def test_white_label_readable_in_every_state(self, theme_path, mode):
        '''White reaches READABLE_TEXT_RATIO on fill, hover and pressed.'''
        theme = _load_theme(theme_path)
        for button in _learn_card_buttons():
            fill = _learn_button_fill(theme, button['color'], mode)
            assert fill is not None, button['label']
            for state, color in (('fill', fill),
                                 ('hover', darken(fill, 12)),
                                 ('pressed', darken(fill, 20))):
                assert (contrast_ratio('#ffffff', color)
                        >= READABLE_TEXT_RATIO - 0.01), (button['label'], state)


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


THEME_MODE_ARGS = 'theme_path,mode,reference,contrast'


def _theme_contrast_levels(theme_path):
    '''The contrast levels a theme is derived with: High only when it
    declares "contrast": "high" (theme_parser.cpp), else both.'''
    if _load_theme(theme_path).get('contrast') == 'high':
        return ('high',)
    return tuple(RATIO_SETS)


def _theme_mode_params(levels=tuple(RATIO_SETS)):
    '''(theme_path, mode, reference, contrast) for every bundled theme ×
    {light, dark} × reference palette × the theme's contrast levels that
    are in `levels`.'''
    params = []
    for path in _bundled_themes():
        for mode in ('light', 'dark'):
            for reference in REFERENCE_PALETTES:
                for contrast in _theme_contrast_levels(path):
                    if contrast not in levels:
                        continue
                    params.append(pytest.param(
                        path, mode, reference, contrast,
                        id=f'{path.parent.name}-{mode}-{reference}-{contrast}'))
    return params


class TestDerivedContrast:
    '''Per design.md §7, for every shipped theme × both modes the
    derived tokens must meet their target contrast ratios against the
    surface they sit on.  Without these assertions, a theme can ship
    that looks fine in one mode but goes invisible (SectionHeader on
    dark base) or unreadable (header bar vs version label) in
    the other — exactly the class of bug the new derivations close.'''

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_section_header_meets_aa_against_base(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['sectionHeader'], t['base']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_field_border_meets_non_text_contrast(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['fieldBorder'], t['base']) >= NON_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_header_background_holds_title(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['headerText'], t['headerBackground']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_header_background_holds_muted_version(self, theme_path, mode, reference, contrast):
        '''The version label reads at LARGE_TEXT_RATIO, at High at
        READABLE_TEXT_RATIO (its target there).'''
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        target = READABLE_TEXT_RATIO if high_contrast() else LARGE_TEXT_RATIO
        assert contrast_ratio(t['headerTextMuted'], t['headerBackground']) >= target

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_header_background_stands_out_from_window(self, theme_path, mode, reference, contrast):
        '''At High the title wins: a bar held DISTINCT_SURFACE_RATIO from a
        near-black window cannot also hold a white title and its faded
        label at READABLE_TEXT_RATIO, so a closer bar passes when that
        window-distinct bar would miss the title or the label.'''
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        if (high_contrast()
                and contrast_ratio(t['headerBackground'], t['window']) < DISTINCT_SURFACE_RATIO):
            distinct_bar = ensure_contrast(darken(t['highlight'], 40), t['window'],
                                           DISTINCT_SURFACE_RATIO)
            title = t['headerText']
            assert (not is_readable(title, distinct_bar)
                    or not is_readable(mix(title, distinct_bar, 0.25), distinct_bar))
            return
        assert contrast_ratio(t['headerBackground'], t['window']) >= DISTINCT_SURFACE_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_filter_valid_holds_its_auto_foreground(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['textOnFilterValid'], t['filterValid']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_filter_invalid_holds_its_auto_foreground(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['textOnFilterInvalid'], t['filterInvalid']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_filter_deprecated_holds_its_auto_foreground(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['textOnFilterDeprecated'],
                              t['filterDeprecated']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_muted_text_meets_aa_against_base(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['mutedText'], t['base']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_link_meets_aa_against_base(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['link'], t['base']) >= READABLE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_filter_busy_text_meets_low_contrast_target(self, theme_path, mode, reference, contrast):
        '''Filter-busy fg is intentionally faded (matches QLineEdit's
        placeholder fade); LARGE_TEXT_RATIO is the lower target for
        "transient state" text.'''
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['filterBusyText'], t['filterBusy']) >= LARGE_TEXT_RATIO

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_dark_card_stands_out_from_base(self, theme_path, mode, reference, contrast):
        if mode != 'dark':
            pytest.skip('light cards are not lifted')
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['card'], t['base']) >= CARD_SURFACE_RATIO_DARK - 1e-6

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_light_card_is_pin_or_base(self, theme_path, mode, reference, contrast):
        '''A light card is the theme's alternateBase pin or Base, never a
        lifted gray: the border alone sets it apart from the page.'''
        if mode != 'light':
            pytest.skip('dark cards are lifted')
        theme = _load_theme(theme_path)
        t = derived_tokens(theme, mode, reference)
        assert t['card'] == (_pick(theme, 'palette', 'alternateBase', 'light') or t['base'])

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_card_border_visible_on_card(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['cardBorder'], t['card']) >= DIVIDER_RATIO - 1e-6

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_derived_separator_visible_on_base(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        if t['separatorPinned']:
            pytest.skip('separator pinned by the theme')
        assert contrast_ratio(t['separator'], t['base']) >= DIVIDER_RATIO - 1e-6

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_card_section_headers_readable_on_card(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        for key in ('cardSectionHeader', 'cardSectionHeaderHover'):
            assert contrast_ratio(t[key], t['card']) >= READABLE_TEXT_RATIO - 1e-6, key

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_card_link_readable_on_card_and_hover(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['cardLink'], t['card']) >= READABLE_TEXT_RATIO - 1e-6
        # Light hover is transient state text, held to the large-text ratio.
        hover_ratio = READABLE_TEXT_RATIO if mode == 'dark' else LARGE_TEXT_RATIO
        assert contrast_ratio(t['cardLink'], t['cardLinkHover']) >= hover_ratio - 1e-6

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_card_link_hover_distinct_from_card(self, theme_path, mode, reference, contrast):
        '''The fill keeps READABLE_TEXT_RATIO / LARGE_TEXT_RATIO from the
        card (DISTINCT_SURFACE_RATIO in Standard); at High in dark mode the
        link target wins and only the link on the fill is asserted.'''
        # The fill keeps its own distance from the card unless the link forces it to move;
        # both are rounded to 8-bit channels, so the bound holds to within that rounding.
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        if high_contrast() and mode == 'dark':
            assert (contrast_ratio(t['cardLink'], t['cardLinkHover'])
                    >= READABLE_TEXT_RATIO - 1e-6)
            return
        assert (contrast_ratio(t['cardLinkHover'], t['card'])
                >= READABLE_TEXT_RATIO / LARGE_TEXT_RATIO - 0.01)

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_card_focus_ring_visible_on_link_hover(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert (contrast_ratio(t['cardFocusRing'], t['cardLinkHover'])
                >= DIVIDER_RATIO - 1e-6)

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_card_focus_ring_readable_on_card(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['cardFocusRing'], t['card']) >= READABLE_TEXT_RATIO - 1e-6

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_overlay_card_border_visible(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert (contrast_ratio(t['overlayCardBorder'], t['overlayCard'])
                >= DIVIDER_RATIO - 1e-6)

    @pytest.mark.parametrize('mode', ['light', 'dark'])
    @pytest.mark.parametrize('reference', list(REFERENCE_PALETTES))
    def test_overlay_card_is_lighter_of_card_and_base(self, mode, reference):
        path = next(p for p in _bundled_themes() if p.parent.name == 'wireshark')
        t = derived_tokens(_load_theme(path), mode, reference)
        assert t['overlayCard'] == (t['card'] if mode == 'dark' else t['base'])

    @pytest.mark.parametrize('reference', list(REFERENCE_PALETTES))
    def test_light_card_link_is_application_link(self, reference):
        '''Light card links keep the application link color.'''
        path = next(p for p in _bundled_themes() if p.parent.name == 'wireshark')
        t = derived_tokens(_load_theme(path), 'light', reference)
        assert t['cardLink'] == t['link']

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_splash_fill_visible_on_overlay_border(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert (contrast_ratio(t['splashFill'], t['overlayCardBorder'])
                >= NON_TEXT_RATIO - 1e-6)

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_syntax_key_readable_on_base(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        assert contrast_ratio(t['syntaxKey'], t['base']) >= READABLE_TEXT_RATIO - 1e-6

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params(levels=('standard',)))
    def test_learn_card_buttons_stand_out_from_card(self, theme_path, mode, reference, contrast):
        '''Each Learn card button fill is kept DISTINCT_SURFACE_RATIO
        apart from the card it sits on, on both reference palettes.
        Standard only: at High a white label at READABLE_TEXT_RATIO needs a
        fill too dark to stand DISTINCT_SURFACE_RATIO off a dark card, and
        the label wins.'''
        theme = _load_theme(theme_path)
        t = derived_tokens(theme, mode, reference)
        for button in _learn_card_buttons():
            fill = _learn_button_fill(theme, button['color'], mode)
            assert fill is not None, button['label']
            assert (contrast_ratio(fill, t['card'])
                    >= DISTINCT_SURFACE_RATIO - 1e-6), button['label']


class TestMacosDarkRegression:
    '''On the macOS palette Mid sits below Base, which flattened the old
    separator and left the Learn card invisible.'''

    @staticmethod
    def _wireshark():
        path = next(p for p in _bundled_themes() if p.parent.name == 'wireshark')
        return _load_theme(path)

    def test_old_separator_formula_stays_flat(self):
        pal = REFERENCE_PALETTES['macos-qt611']['dark']
        old = mix(pal['base'], pal['mid'], 135 / 255.0)
        assert contrast_ratio(old, pal['base']) < 1.05

    def test_card_and_separator_differ_from_base(self):
        t = derived_tokens(self._wireshark(), 'dark', 'macos-qt611')
        assert t['card'] != t['base']
        assert t['separator'] != t['base']
        assert contrast_ratio(t['separator'], t['base']) >= DIVIDER_RATIO - 1e-6


class TestHoverFill:
    '''The hover fill derived from a selection color must stay visibly
    different from the selection and keep its text readable.'''

    @staticmethod
    def _cases(theme, mode, reference):
        t = derived_tokens(theme, mode, reference)
        text = t['text']
        for role in ('selection', 'inactive'):
            sel = packet_state_fill(theme, mode, role)
            if sel:
                yield role, t['base'], sel, text
        yield 'highlight', t['base'], t['highlight'], text

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_hover_fill_distinct_from_selection(self, theme_path, mode, reference, contrast):
        for role, base, sel, text in self._cases(_load_theme(theme_path), mode, reference):
            fill, _ = selection_hover(base, sel, text)
            assert contrast_ratio(fill, sel) >= DISTINCT_SURFACE_RATIO, role

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params())
    def test_hover_text_readable(self, theme_path, mode, reference, contrast):
        '''At High READABLE_TEXT_RATIO can be out of reach on a fill that
        must stay distinct from the selection; the text is then black or
        white (the contrasting text of the fill).'''
        for role, base, sel, text in self._cases(_load_theme(theme_path), mode, reference):
            fill, hover_text = selection_hover(base, sel, text)
            if high_contrast() and contrast_ratio(hover_text, fill) < READABLE_TEXT_RATIO:
                assert hover_text == contrasting_text(fill), role
                continue
            assert contrast_ratio(hover_text, fill) >= READABLE_TEXT_RATIO, role


class TestInvertedHighlight:
    @pytest.mark.parametrize('mode', ['light', 'dark'])
    def test_highlight_pin_wins_over_selection(self, mode):
        '''Inverted pins palette.highlight apart from its pale
        packets.selection; the pin, not the selection, is the highlight.
        Standard only: it checks the designed pin, which High moves.'''
        path = next(p for p in _bundled_themes() if p.parent.name == 'inverted')
        theme = _load_theme(path)
        pin = _pick(theme, 'palette', 'highlight', mode)
        assert pin
        assert pin.lower() != _pick(theme, 'packets', 'selection', mode).lower()
        assert derived_tokens(theme, mode)['highlight'].lower() == pin.lower()


class TestNoRedundantPins:
    '''A pin equal to what the theme system derives for the key anyway
    is a copy that goes stale when its source changes.  A color sets
    both sides, so a pin is redundant only when both sides equal the
    value derived without it.'''

    # (section, key, derived_tokens() key)
    CHECKS = [
        ('palette', 'highlight',       'highlight'),
        ('palette', 'highlightedText', 'highlightText'),
        ('filter',  'busyText',        'filterBusyText'),
    ]

    @pytest.mark.parametrize('check', CHECKS, ids=lambda c: c[1])
    @pytest.mark.parametrize('theme_path', _bundled_themes(),
                             ids=lambda p: p.parent.name)
    def test_pin_is_not_derived(self, theme_path, check):
        section, key, token = check
        theme = _load_theme(theme_path)
        pins = {mode: _pick(theme, section, key, mode)
                for mode in ('light', 'dark')}
        if not all(pins.values()):
            pytest.skip('no %s pin' % key)
        unpinned = dict(theme, **{section: {
            name: value for name, value in theme[section].items()
            if name != key}})
        assert not all(
            derived_tokens(unpinned, mode, reference)[token].lower()
            == pins[mode].lower()
            for mode in pins for reference in REFERENCE_PALETTES)


# Themes whose source has a single light variant share that light side.
# The theme format has no include, so each file carries a copy.
SHARED_LIGHT_FAMILIES = [
    ('catppuccin-frappe', 'catppuccin-macchiato', 'catppuccin-mocha'),
    ('tokyo-night', 'tokyo-night-storm'),
]


def _light_side(theme):
    '''Every light value of a theme by section (and key); meta is skipped.'''
    out = {}
    for section, value in theme.items():
        if section == 'meta':
            continue
        if isinstance(value, list):
            out[section] = [entry['light'] for entry in value]
        elif isinstance(value, dict) and 'light' in value:
            out[section] = value['light']
        elif isinstance(value, dict):
            out[section] = {key: pair['light'] for key, pair in value.items()
                            if isinstance(pair, dict) and 'light' in pair}
    return out


class TestSharedLightSides:
    @pytest.mark.parametrize('family', SHARED_LIGHT_FAMILIES, ids=lambda f: f[0])
    def test_family_light_sides_match(self, family):
        '''The copies of a shared light side stay identical.'''
        sides = [_light_side(_load_theme(THEME_ROOT / stem / 'theme.jsonc'))
                 for stem in family]
        for stem, side in zip(family[1:], sides[1:]):
            assert side == sides[0], stem


class TestReadmeLayout:
    def test_readme_lists_every_bundled_theme(self):
        '''The README directory layout names every bundled theme directory,
        and besides them only the my-custom-theme example.'''
        readme = THEME_README.read_text(encoding='utf-8')
        layout = re.search(r'^## Directory layout\n(.*?)^## ', readme,
                           re.M | re.S).group(1)
        listed = set(re.findall(r'^ {4}([\w-]+)/', layout, re.M))
        bundled = {p.parent.name for p in _bundled_themes()}
        assert listed - bundled == {'my-custom-theme'}
        assert bundled <= listed


class TestSelectionText:
    '''Selection text is checked centrally (palette builder, token
    handler): pinned or derived it is lifted to READABLE_TEXT_RATIO on
    its fill.  The shipped themes are designed so that check leaves
    their pins alone.  These tests fail when a theme value change makes
    a pin depend on the check, which would turn the designed text color
    into a grey.'''

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params(levels=('standard',)))
    def test_highlighted_text_pin_reads_on_highlight(self, theme_path, mode, reference, contrast):
        '''Standard only: it checks the designed pins, which High moves.'''
        theme = _load_theme(theme_path)
        pin = _pick(theme, 'palette', 'highlightedText', mode)
        if pin:
            assert is_readable(pin, derived_tokens(theme, mode, reference)['highlight'])

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params(levels=('standard',)))
    def test_packet_state_text_pins_read_on_fill(self, theme_path, mode, reference, contrast):
        '''Standard only: it checks the designed pins, which High moves.'''
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
        do not meet it yet.  Standard only: it checks the designed pins,
        which High moves.'''
        path = next(p for p in _bundled_themes() if p.parent.name == 'stratoshark')
        theme = _load_theme(path)
        marked = _pick(theme, 'packets', 'marked', mode)
        for state in ('selection', 'inactive'):
            assert (contrast_ratio(marked, _pick(theme, 'packets', state, mode))
                    >= DISTINCT_SURFACE_RATIO), state


# =====================================================================
# Contrast levels — the Standard and High ratio sets, the files that
# repeat them, and the high-contrast rules.
# =====================================================================


class TestContrastLevels:
    def test_high_ratios_not_below_standard(self):
        '''High never asks for less contrast than Standard.'''
        for name, _, _ in RATIOS:
            assert RATIO_SETS['high'][name] >= RATIO_SETS['standard'][name], name

    def test_ratio_table_covers_color_math_constants(self):
        '''RATIOS names every ratio constant of color_math.h and its High sibling.'''
        declared = set(re.findall(r'static\s+constexpr\s+qreal\s+(\w+)\s*=',
                                  COLOR_MATH_H.read_text(encoding='utf-8')))
        listed = {c for _, constant, _ in RATIOS for c in (constant, constant + 'High')}
        assert declared == listed

    def test_readme_contrast_table_matches_ratio_sets(self):
        '''The README contrast table lists the ratios of color_math.h.'''
        rows = re.findall(r'^\|\s*([^|`]+?)\s*\|\s*`([0-9.]+):1`\s*\|\s*`([0-9.]+):1`\s*\|\s*$',
                          THEME_README.read_text(encoding='utf-8'), re.MULTILINE)
        table = {label: (float(standard), float(high)) for label, standard, high in rows}
        expected = {label: (RATIO_SETS['standard'][name], RATIO_SETS['high'][name])
                    for name, _, label in RATIOS}
        assert table == expected

    def test_contrast_values_match_schema_and_parser(self):
        '''The schema `contrast` enum, the values theme_parser.cpp compares
        (ThemeFormat constants in theme_format.h) and the ratio sets name the
        same levels.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        enum = set(schema['properties']['contrast']['enum'])
        values = dict(re.findall(r'inline const QLatin1String (Contrast\w+)\("([^"]*)"\);',
                                 FORMAT_HEADER.read_text(encoding='utf-8')))
        compared = re.findall(r'\bcontrast\s*[!=]=\s*ThemeFormat::(\w+)',
                              THEME_PARSER_CPP.read_text(encoding='utf-8'))
        parsed = {values[name] for name in compared}
        assert enum == parsed == set(RATIO_SETS)

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params(levels=('high',)))
    def test_expert_fills_read_with_foreground(self, theme_path, mode, reference, contrast):
        '''Each expert severity fill, as drawn on Base, holds
        ExpertForeground at READABLE_TEXT_RATIO.'''
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        for key, fill in t['expertFills'].items():
            assert (contrast_ratio(t['expertForeground'], fill)
                    >= READABLE_TEXT_RATIO - 1e-6), key

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params(levels=('high',)))
    def test_conversation_text_reads_on_fill(self, theme_path, mode, reference, contrast):
        t = derived_tokens(_load_theme(theme_path), mode, reference)
        for keys, (text, fill) in t['conversation'].items():
            assert contrast_ratio(text, fill) >= READABLE_TEXT_RATIO - 1e-6, keys

    @pytest.mark.parametrize(THEME_MODE_ARGS, _theme_mode_params(levels=('high',)))
    def test_update_bar_readable(self, theme_path, mode, reference, contrast):
        '''Text and links read on the bar, TextOnSuccess on every button
        state, and the dot keeps NON_TEXT_RATIO from the bar.'''
        u = derived_tokens(_load_theme(theme_path), mode, reference)['updateBar']
        for key in UPDATE_BAR_TEXT_KEYS:
            assert contrast_ratio(u[key], u['background']) >= READABLE_TEXT_RATIO - 1e-6, key
        for key in UPDATE_BAR_BUTTON_KEYS:
            assert contrast_ratio(u['buttonText'], u[key]) >= READABLE_TEXT_RATIO - 1e-6, key
        assert contrast_ratio(u['dot'], u['background']) >= NON_TEXT_RATIO - 1e-6

    @pytest.mark.parametrize('contrast', ['high'])
    def test_dark_hover_falls_back_to_contrasting_text(self, contrast):
        '''Default theme, dark, High on the macOS palette: a fill that holds
        the white text at READABLE_TEXT_RATIO would sit too close to the
        selection, so the fill stays and the text turns black (6.1:1).'''
        theme = _load_theme(THEME_ROOT / 'wireshark' / 'theme.jsonc')
        t = derived_tokens(theme, 'dark', 'macos-qt611')
        selection = packet_state_fill(theme, 'dark', 'selection')
        fill, text = selection_hover(t['base'], selection, t['text'])
        assert fill == '#838b97'
        assert text == contrasting_text(fill) == '#000000'
        assert contrast_ratio(text, fill) < READABLE_TEXT_RATIO

    @pytest.mark.parametrize('contrast', ['high'])
    @pytest.mark.parametrize('mode,header,update_bar', [
        ('light', '#062457', '#002800'),
        ('dark', '#283e52', '#316431'),
    ])
    def test_high_contrast_theme_signed_off_values(self, mode, header, update_bar, contrast):
        '''The welcome header and update bar of the High Contrast theme
        keep the values of the signed-off design.'''
        theme = _load_theme(THEME_ROOT / 'high-contrast' / 'theme.jsonc')
        t = derived_tokens(theme, mode, 'macos-qt611')
        assert t['headerBackground'] == header
        assert contrast_ratio(t['headerText'], t['headerBackground']) >= READABLE_TEXT_RATIO
        u = t['updateBar']
        assert u['background'] == update_bar
        assert contrast_ratio(u['text'], u['background']) >= READABLE_TEXT_RATIO


# =====================================================================
# Migration / schema flexibility checks
# =====================================================================


class TestSchemaFlexibility:
    def test_theme_without_filter_or_separator_parses(self):
        '''Per design, filter and separator are both optional.'''
        jsonschema = pytest.importorskip('jsonschema')
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
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
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
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


# =====================================================================
# Color vision deficiency themes — themes that list deficiencies in
# meta.colorVision must keep every semantic color set distinguishable
# under normal vision and under each listed deficiency.
# =====================================================================

# Full-severity (1.0) dichromacy simulation matrices in linear RGB from
# Machado, Oliveira and Fernandes, "A Physiologically-based Model for
# Simulation of Color Vision Deficiency", IEEE TVCG 15(6), 2009.  The
# keys are the enum values of meta.colorVision in theme.schema.json.
CVD_MATRICES = {
    'protanopia': ((0.152286, 1.052583, -0.204868),
                   (0.114503, 0.786281, 0.099216),
                   (-0.003882, -0.048116, 1.051998)),
    'deuteranopia': ((0.367322, 0.860646, -0.227968),
                     (0.280085, 0.672501, 0.047413),
                     (-0.011820, 0.042940, 0.968881)),
    'tritanopia': ((1.255528, -0.076749, -0.178779),
                   (-0.078411, 0.930809, 0.147602),
                   (0.004733, 0.691367, 0.303900)),
}

# The graph list holds strong colors first and pastel tints of the same
# hues after them (slots 1-7 and 8-14 in resources/themes/README.md).
# The tints repeat the hues on purpose, so only the strong slots must be
# told apart; they are also the only slots the fixed-slot users read
# (TCP stream graph 1-5, SCTP graphs 0/1/3/4/6, DIS analysis 1, I/O Graph
# and Plot defaults 0/1).
STRONG_GRAPH_SLOTS = 7

# Semantic color sets and the minimum CIEDE2000 difference between any
# two members.  None as keys means the strong graph slots; keys starting
# with ALL_EXCEPT mean every key theme.schema.json declares for the
# section except the ones listed after it, so a key added to the schema
# is checked without editing this table.  The floors
# are the values of the bundled color vision themes at the time they
# were designed; raise a floor when the values improve, never lower it
# to make a new value pass.  Accents are weakest for success / info in
# dark protanopia; the expert backgrounds are lowest because the
# Severity column, the tooltip and the status bar icon shape name the
# severity as well, and five tints cannot all reach the strong colors.
# expert.none is the background of items without a severity, so it is
# not one of the severities that must be told apart.
ALL_EXCEPT = '*'

CVD_SETS = (
    ('accent', (ALL_EXCEPT,), 8.0),
    ('filter', ('valid', 'invalid', 'deprecated'), 9.5),
    ('conversation', ('client', 'server'), 10.0),
    ('conversation', ('clientText', 'serverText'), 10.0),
    ('expert', (ALL_EXCEPT, 'foreground', 'none'), 6.5),
    ('graphs', None, 10.0),
)

# Sections the color vision themes copy from the default theme, because
# a theme cannot inherit from another one and an omitted key is derived
# from brand / accent instead (theme_token_handler.cpp), which would
# change the selection, Follow Stream and history colors.  None means
# every key the default theme sets in that section.  The test below
# fails when the copies and the default theme drift apart.
DEFAULT_THEME_COPIES = (
    ('brand', None),
    ('packets', None),
    ('palette', None),
    ('conversation', None),
    ('filter', ('history',)),
)


def _linear_to_srgb(v):
    v = max(0.0, min(1.0, v))
    return 255.0 * (v * 12.92 if v <= 0.0031308 else 1.055 * v ** (1 / 2.4) - 0.055)


def simulate_cvd(hex_str, deficiency):
    '''hex_str as seen with full-severity `deficiency`, as an 8-bit RGB triple.'''
    lin = [_srgb_to_linear(v) for v in _hex_to_rgb(hex_str)]
    return tuple(_linear_to_srgb(sum(m * c for m, c in zip(row, lin)))
                 for row in CVD_MATRICES[deficiency])


def _rgb_to_lab(rgb):
    '''CIELAB (D65) of an 8-bit sRGB triple.'''
    r, g, b = (_srgb_to_linear(v) for v in rgb)
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(t):
        return t ** (1 / 3) if t > 216 / 24389 else (24389 / 27 * t + 16) / 116
    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def ciede2000(lab1, lab2):
    '''CIEDE2000 color difference (Sharma, Wu and Dalal, 2005).'''
    l1, a1, b1 = lab1
    l2, a2, b2 = lab2
    c_bar = (math.hypot(a1, b1) + math.hypot(a2, b2)) / 2
    g = 0.5 * (1 - math.sqrt(c_bar ** 7 / (c_bar ** 7 + 25 ** 7)))
    a1p, a2p = (1 + g) * a1, (1 + g) * a2
    c1p, c2p = math.hypot(a1p, b1), math.hypot(a2p, b2)
    h1p = math.degrees(math.atan2(b1, a1p)) % 360 if c1p else 0.0
    h2p = math.degrees(math.atan2(b2, a2p)) % 360 if c2p else 0.0
    dlp = l2 - l1
    dcp = c2p - c1p
    if c1p * c2p == 0:
        dhp = 0.0
    else:
        dhp = h2p - h1p
        if dhp > 180:
            dhp -= 360
        elif dhp < -180:
            dhp += 360
    dhp_big = 2 * math.sqrt(c1p * c2p) * math.sin(math.radians(dhp / 2))
    l_bar = (l1 + l2) / 2
    cp_bar = (c1p + c2p) / 2
    if c1p * c2p == 0:
        hp_bar = h1p + h2p
    elif abs(h1p - h2p) <= 180:
        hp_bar = (h1p + h2p) / 2
    elif h1p + h2p < 360:
        hp_bar = (h1p + h2p + 360) / 2
    else:
        hp_bar = (h1p + h2p - 360) / 2
    t = (1 - 0.17 * math.cos(math.radians(hp_bar - 30))
         + 0.24 * math.cos(math.radians(2 * hp_bar))
         + 0.32 * math.cos(math.radians(3 * hp_bar + 6))
         - 0.20 * math.cos(math.radians(4 * hp_bar - 63)))
    d_theta = 30 * math.exp(-((hp_bar - 275) / 25) ** 2)
    r_c = 2 * math.sqrt(cp_bar ** 7 / (cp_bar ** 7 + 25 ** 7))
    s_l = 1 + 0.015 * (l_bar - 50) ** 2 / math.sqrt(20 + (l_bar - 50) ** 2)
    s_c = 1 + 0.045 * cp_bar
    s_h = 1 + 0.015 * cp_bar * t
    r_t = -math.sin(math.radians(2 * d_theta)) * r_c
    return math.sqrt((dlp / s_l) ** 2 + (dcp / s_c) ** 2 + (dhp_big / s_h) ** 2
                     + r_t * (dcp / s_c) * (dhp_big / s_h))


def _schema_section_keys(section):
    '''Keys theme.schema.json declares for `section`, in schema order.'''
    props = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))['properties']
    return tuple(props[section]['properties'])


def _cvd_keys(section, keys):
    '''The keys a CVD_SETS row checks, with ALL_EXCEPT resolved.'''
    if keys and keys[0] == ALL_EXCEPT:
        return tuple(k for k in _schema_section_keys(section) if k not in keys[1:])
    return keys


def _color_vision_themes():
    '''(path, deficiencies) of the bundled themes that list meta.colorVision.'''
    themes = []
    for theme_path in _bundled_themes():
        targets = _load_theme(theme_path).get('meta', {}).get('colorVision')
        if targets:
            themes.append((theme_path, tuple(targets)))
    return themes


def _color_vision_params():
    params = []
    for theme_path, targets in _color_vision_themes():
        for mode in ('light', 'dark'):
            for section, keys, minimum in CVD_SETS:
                keys = _cvd_keys(section, keys)
                name = section if keys is None else f'{section}.{keys[0]}'
                params.append(pytest.param(theme_path, mode, section, keys, minimum,
                                           targets,
                                           id=f'{theme_path.parent.name}-{mode}-{name}'))
    return params


class TestColorVisionThemes:
    @pytest.mark.parametrize('theme_path,mode,section,keys,minimum,targets',
                             _color_vision_params())
    def test_semantic_set_stays_distinct(self, theme_path, mode, section, keys,
                                         minimum, targets):
        theme = _load_theme(theme_path)
        if keys is None:
            entries = (theme.get(section) or [])[:STRONG_GRAPH_SLOTS]
            colors = {f'{section}[{i}]': e.get(mode) for i, e in enumerate(entries)}
        else:
            colors = {k: _pick(theme, section, k, mode) for k in keys}
        missing = [k for k, v in colors.items() if not v]
        assert len(colors) >= 2 and not missing, \
            f'{theme_path.parent.name} must pin {section} {missing or "(two or more)"} ({mode})'
        for vision in ('normal',) + targets:
            labs = {k: _rgb_to_lab(_hex_to_rgb(v) if vision == 'normal'
                                   else simulate_cvd(v, vision))
                    for k, v in colors.items()}
            worst = min((ciede2000(labs[a], labs[b]), a, b)
                        for a, b in itertools.combinations(labs, 2))
            assert worst[0] >= minimum, \
                (f'{theme_path.parent.name} {mode} {vision}: {worst[1]} / {worst[2]} '
                 f'differ by CIEDE2000 {worst[0]:.1f} < {minimum}')

    @pytest.mark.parametrize('theme_path', [p for p, _ in _color_vision_themes()],
                             ids=lambda p: p.parent.name)
    def test_default_theme_copies_match(self, theme_path):
        '''The sections copied from the default theme still equal it.'''
        default = _load_theme(THEME_ROOT / 'wireshark' / 'theme.jsonc')
        theme = _load_theme(theme_path)
        for section, keys in DEFAULT_THEME_COPIES:
            for key in keys or sorted(default.get(section) or {}):
                assert (theme.get(section) or {}).get(key) == default[section][key], \
                    f'{theme_path.parent.name} {section}.{key} differs from the default theme'

    def test_sets_name_schema_keys(self):
        '''CVD_SETS keys and exclusions exist in the schema, so a renamed key fails here.'''
        props = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))['properties']
        for section, keys, _ in CVD_SETS:
            assert section in props
            if keys is None:
                continue
            named = keys[1:] if keys[0] == ALL_EXCEPT else keys
            for key in named:
                assert key in props[section]['properties'], f'{section}.{key}'
            assert len(_cvd_keys(section, keys)) >= 2, f'{section} checks fewer than two keys'

    def test_matrices_match_schema_enum(self):
        '''Every deficiency the schema accepts has a simulation matrix.'''
        meta = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))['properties']['meta']
        assert set(meta['properties']['colorVision']['items']['enum']) == set(CVD_MATRICES)

    @pytest.mark.parametrize('lab1,lab2,expected', [
        ((50, 2.6772, -79.7751), (50, 0, -82.7485), 2.0425),
        ((50, 2.5, 0), (73, 25, -18), 27.1492),
        ((2.0776, 0.0795, -1.135), (0.9033, -0.0636, -0.5514), 0.9082),
    ])
    def test_ciede2000_reference_pairs(self, lab1, lab2, expected):
        '''Pairs from Sharma, Wu and Dalal's CIEDE2000 test data.'''
        assert ciede2000(lab1, lab2) == pytest.approx(expected, abs=1e-4)


# GraphDialog gives a new row the palette color of its row number, so the
# two default series of the I/O Graph and Plot dialogs use slots 0 and 1.
DEFAULT_SERIES_SLOTS = (0, 1)
# The default series must be as far apart as any two strong graph slots.
GRAPH_SLOT_FLOOR = next(m for s, k, m in CVD_SETS if s == 'graphs' and k is None)
GRAPH_DIALOG_CPP = REPO_ROOT / 'ui' / 'qt' / 'graph_dialog.cpp'
GRAPH_DIALOG_SUBCLASSES = (
    REPO_ROOT / 'ui' / 'qt' / 'io_graph_dialog.cpp',
    REPO_ROOT / 'ui' / 'qt' / 'plot_dialog.cpp',
    REPO_ROOT / 'ui' / 'stratoshark' / 'stratoshark_io_graph_dialog.cpp',
    REPO_ROOT / 'ui' / 'stratoshark' / 'stratoshark_plot_dialog.cpp',
)


class TestGraphDefaultSeries:
    '''The I/O Graph and Plot dialogs color their rows through GraphDialog,
    which uses the row number as palette slot.'''

    def test_default_slots_are_distinct_strong_slots(self):
        assert len(set(DEFAULT_SERIES_SLOTS)) == len(DEFAULT_SERIES_SLOTS)
        assert all(i < STRONG_GRAPH_SLOTS for i in DEFAULT_SERIES_SLOTS)

    @pytest.mark.parametrize('theme_path', _bundled_themes(),
                             ids=lambda p: p.parent.name)
    @pytest.mark.parametrize('mode', ('light', 'dark'))
    def test_default_series_colors_differ(self, theme_path, mode):
        graphs = _load_theme(theme_path).get('graphs') or []
        assert graphs, f'{theme_path.parent.name} has no graph colors'
        first, second = (graphs[i % len(graphs)].get(mode) for i in DEFAULT_SERIES_SLOTS)
        assert first and second, \
            f'{theme_path.parent.name} must pin both default series slots ({mode})'
        diff = ciede2000(_rgb_to_lab(_hex_to_rgb(first)), _rgb_to_lab(_hex_to_rgb(second)))
        assert diff >= GRAPH_SLOT_FLOOR, \
            (f'{theme_path.parent.name} {mode}: default series {first} / {second} '
             f'differ by CIEDE2000 {diff:.1f} < {GRAPH_SLOT_FLOOR}')

    def test_new_row_color_follows_row_number(self):
        source = GRAPH_DIALOG_CPP.read_text(encoding='utf-8')
        assert re.search(r'graphColor\(\s*uat_model_\s*\?\s*uat_model_->rowCount\(\)', source), \
            'GraphDialog::newGraphColor() must use the new row number as palette slot'

    @pytest.mark.parametrize('dialog', GRAPH_DIALOG_SUBCLASSES, ids=lambda p: p.name)
    def test_dialogs_color_rows_through_graph_dialog(self, dialog):
        source = dialog.read_text(encoding='utf-8')
        for chooser in ('graphColor(', 'GraphColorsList'):
            assert chooser not in source, \
                f'{dialog.name} must not choose palette colors itself ({chooser})'

    @pytest.mark.parametrize('dialog', GRAPH_DIALOG_SUBCLASSES[:2], ids=lambda p: p.name)
    def test_dialogs_use_new_graph_color(self, dialog):
        assert 'newGraphColor()' in dialog.read_text(encoding='utf-8'), \
            f'{dialog.name} must color new rows with GraphDialog::newGraphColor()'

    def test_no_separate_default_graph_color(self):
        offenders = [str(p.relative_to(REPO_ROOT))
                     for p in sorted((REPO_ROOT / 'ui').rglob('*'))
                     if p.suffix in ('.c', '.cpp', '.h') and p.is_file()
                     and 'graphDefaultColor' in p.read_text(encoding='utf-8', errors='replace')]
        assert not offenders, \
            f'graphDefaultColor is back; default series use palette slots: {offenders}'


# =====================================================================
# Expert severity icons — one SVG per Expert* token (except the text
# color ExpertForeground), each bound to its token and drawn with its
# own shape so severity does not depend on color alone.  Outline ring
# and mark use ExpertForeground, the text color on the same fill.
# =====================================================================

SVG_ICON_ROOT = REPO_ROOT / 'resources' / 'svg_icons'


def _expert_icon_tokens():
    '''Expert* severity tokens of the ThemeToken enum, e.g. "ExpertWarn".'''
    return sorted(n for n in _theme_token_names()
                  if n.startswith('Expert') and n != 'ExpertForeground')


def _expert_icon_path(token):
    '''The SVG of an expert severity token, e.g. ExpertWarn -> expert-warn.svg.'''
    return SVG_ICON_ROOT / f'expert-{token[len("Expert"):].lower()}.svg'


class TestExpertIcons:
    def test_each_severity_icon_maps_its_token(self):
        for token in _expert_icon_tokens():
            path = _expert_icon_path(token)
            text = path.read_text(encoding='utf-8')
            for mapped in (token, 'ExpertForeground'):
                assert re.search(r'<ws:map-token\b[^>]*\btoken="' + mapped + '"', text), \
                    f'{path.name} does not map a color to {mapped}'

    def test_severity_icons_have_distinct_shapes(self):
        shapes = {}
        for token in _expert_icon_tokens():
            path = _expert_icon_path(token)
            text = path.read_text(encoding='utf-8')
            geometry = tuple(sorted(' '.join(d.split())
                                    for d in re.findall(r'\sd="([^"]*)"', text)))
            assert geometry, f'{path.name} draws no <path>'
            shapes.setdefault(geometry, []).append(path.name)
        same = [names for names in shapes.values() if len(names) > 1]
        assert not same, f'expert icons share one shape: {same}'


# =====================================================================
# Filter-line glyphs: each inline filter affordance SVG paints its
# Filter* token, contrast-guarded, and the schema and README accept
# exactly the theme.filter keys the parser accepts (the lowercased
# suffix of every Filter* token).
# =====================================================================

# SVG file names do not follow the token names, so this pairing is
# test data; test_glyph_tokens_exist_in_enum keeps it honest.
FILTER_GLYPH_ICONS = {
    'FilterBookmark':        'bookmark-display.svg',
    'FilterBookmarkCapture': 'bookmark-capture.svg',
    'FilterBookmarkMatch':   'bookmark-match.svg',
    'FilterClear':           'filter-clear.svg',
    'FilterApply':           'filter-apply.svg',
    'FilterHistory':         'filter-history.svg',
}


def _svg_map_tokens(svg):
    '''The <ws:map-token> elements of an SVG icon under SVG_ICON_ROOT, as attribute dicts.'''
    text = (SVG_ICON_ROOT / svg).read_text(encoding='utf-8')
    return [dict(re.findall(r'([\w-]+)="([^"]*)"', el))
            for el in re.findall(r'<ws:map-token\b[^>]*>', text)]


def _readme_filter_rows():
    '''The rows of the README `filter` key table, as {key: purpose text}.'''
    readme = THEME_README.read_text(encoding='utf-8')
    section = re.search(r'^#### `filter`.*?(?=^#)', readme, re.MULTILINE | re.DOTALL).group(0)
    return dict(re.findall(r'^\|\s*`(\w+)`\s*\|(.*)\|\s*$', section, re.MULTILINE))


class TestFilterGlyphIcons:
    def test_glyph_tokens_exist_in_enum(self):
        names = _theme_token_names()
        for token in FILTER_GLYPH_ICONS:
            assert token in names, token

    def test_each_glyph_icon_maps_its_token(self):
        for token, svg in FILTER_GLYPH_ICONS.items():
            maps = [m for m in _svg_map_tokens(svg)
                    if token in (m.get('token'), m.get('active'))]
            assert maps, f'{svg} does not map a color to {token}'
            assert all(m.get('adapt') == 'contrast' for m in maps), \
                f'{svg}: the {token} binding is not contrast-guarded'

    def test_schema_filter_keys_match_enum(self):
        '''theme.schema.json lists exactly the theme.filter keys the
        parser derives from the Filter* enumerators.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        keys = {k.lower() for k in schema['properties']['filter']['properties']}
        tokens = {n[len('Filter'):].lower()
                  for n in _theme_token_names() if n.startswith('Filter')}
        assert keys == tokens

    def test_readme_filter_table_matches_schema(self):
        '''The README `filter` key table lists the schema's filter keys.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        assert set(_readme_filter_rows()) == set(schema['properties']['filter']['properties'])

    def test_readme_glyph_defaults_match_handler(self):
        '''Each README glyph row names exactly the accent that
        theme_token_handler.cpp derives that key from when a theme omits it.'''
        src = (REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes'
               / 'theme_token_handler.cpp').read_text(encoding='utf-8')
        pairs = re.findall(r'assign\(\s*ThemeManager::Filter(\w+),\s*'
                           r'tokens\.value\(ThemeManager::Accent(\w+)\),', src)
        assert pairs, 'no Filter* defaults from Accent* found in theme_token_handler.cpp'
        rows = {k.lower(): text for k, text in _readme_filter_rows().items()}
        for suffix, accent in pairs:
            named = re.findall(r'`(accent\.\w+)`', rows[suffix.lower()])
            assert named == [f'accent.{accent.lower()}'], suffix

    def test_default_theme_pins_drawn_match_colour(self):
        '''The wireshark theme pins filter.bookmarkMatch, in both modes, to
        the colour bookmark-match.svg draws: the classic saved-filter yellow.'''
        theme_path = THEME_ROOT / 'wireshark' / 'theme.jsonc'
        theme = json.loads(_strip_jsonc(theme_path.read_text(encoding='utf-8')))
        pin = theme['filter']['bookmarkMatch']
        drawn = [m['color'].lower() for m in _svg_map_tokens('bookmark-match.svg')
                 if m.get('token') == 'FilterBookmarkMatch']
        assert drawn, 'bookmark-match.svg does not map FilterBookmarkMatch'
        assert pin['light'].lower() == drawn[0]
        assert pin['dark'].lower() == drawn[0]


# =====================================================================
# ThemeWriter schema coverage
# =====================================================================

WRITER_SOURCE = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes' / 'theme_writer.cpp'
HANDLER_SOURCE = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes' / 'theme_token_handler.cpp'
BUILDER_SOURCE = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes' / 'theme_palette_builder.cpp'
STYLESHEET_ROOT = REPO_ROOT / 'ui' / 'stylesheets'
# Designer sources that must take every color from the theme system.
DESIGNER_SOURCES = [REPO_ROOT / 'ui' / 'qt' / p for p in (
    'theme_designer_dialog.cpp', 'widgets/theme_color_editor.cpp',
    'widgets/theme_code_view.cpp', 'widgets/theme_welcome_preview.cpp')]
MANAGER_SOURCE = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'theme_manager.cpp'
FORMAT_HEADER = REPO_ROOT / 'ui' / 'qt' / 'utils' / 'themes' / 'theme_format.h'


def _writer_descriptions():
    '''Entries of ThemeWriter's description table as (token, text).'''
    text = WRITER_SOURCE.read_text(encoding='utf-8')
    return re.findall(
        r'\{\s*ThemeManager::(\w+),\s*'
        r'QT_TRANSLATE_NOOP\("ThemeWriter",\s*"((?:[^"\\]|\\.)*)"\)\s*\}', text)


def _settable_keys():
    '''(token, section, key) per settable token, by ThemeManager's rule:
    the section the lower-cased name starts with, the rest with its first
    letter lowered.  The schema tests below check the rule's output.'''
    sections = _manager_sections()
    out = []
    for name in _theme_token_names():
        for section in sections:
            if name.lower().startswith(section):
                rest = name[len(section):]
                out.append((name, section, rest[0].lower() + rest[1:]))
                break
    return out


def _manager_sections():
    '''Color sections of ThemeManager's sections_ table as {name: required}.'''
    text = MANAGER_SOURCE.read_text(encoding='utf-8')
    block = re.search(r'\bsections_\s*=\s*\{(.*?)\n\s*\};', text, re.S).group(1)
    block = re.sub(r'//[^\n]*', '', block)
    return {name: flag == 'true'
            for name, flag in re.findall(r'\{\s*"(\w+)",\s*\{\s*(true|false)\b', block)}


def _format_root_keys():
    '''ThemeFormat::NonSectionRootKeys as file key names.'''
    text = FORMAT_HEADER.read_text(encoding='utf-8')
    consts = dict(re.findall(r'inline const QLatin1String (\w+)\("(\w+)"\);', text))
    block = re.search(r'NonSectionRootKeys\[\]\s*=\s*\{(.*?)\};', text, re.S).group(1)
    return [consts[name] for name in re.findall(r'\b(\w+)\b', block)]


def _derive_all_assignments():
    '''(token, source text or None) per assign() call in deriveAll().'''
    text = HANDLER_SOURCE.read_text(encoding='utf-8')
    body = text[text.index('void ThemeTokenHandler::deriveAll('):]
    out = []
    for token, args in re.findall(r'\bassign\(\s*ThemeManager::(\w+),(.*?)\);', body, re.S):
        m = re.search(r'QT_TRANSLATE_NOOP\(\s*"ThemeTokenHandler",\s*"((?:[^"\\]|\\.)+)"\s*\)\s*$',
                      args.strip(), re.S)
        out.append((token, m.group(1) if m else None))
    return out


def _source_tokens_pattern():
    '''The name regex of ThemeTokenHandler::sourceTokens(), read from the C++ source.'''
    text = HANDLER_SOURCE.read_text(encoding='utf-8')
    body = text[text.index('ThemeTokenHandler::sourceTokens('):]
    m = re.search(r'QRegularExpression\s+\w+\(\s*QStringLiteral\("((?:[^"\\]|\\.)+)"\)', body)
    assert m, 'no QRegularExpression in ThemeTokenHandler::sourceTokens()'
    # The C++ literal doubles each backslash; unicode_escape undoes that.
    return m.group(1).encode().decode('unicode_escape')


class TestThemeWriterCoverage:
    def test_key_table_keys_exist_in_schema(self):
        '''Every key the writer can emit is spelled as in the schema.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        rows = _settable_keys()
        assert rows
        for token, section, key in rows:
            props = schema['properties'][section]['properties']
            assert key in props, f'{token}: {section}.{key} is not in the schema'

    def test_schema_keys_are_settable(self):
        '''Every key of a color section in the schema is a settable token.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        derived = {(section, key) for _, section, key in _settable_keys()}
        for section in _manager_sections():
            for key in schema['properties'][section]['properties']:
                assert (section, key) in derived, f'{section}.{key} has no ThemeToken'

    def test_every_settable_token_has_a_description(self):
        '''The writer's description table mirrors the settable tokens exactly.'''
        described = [token for token, _ in _writer_descriptions()]
        assert 'BrandPrimary' in _theme_token_names()
        assert len(described) == len(set(described)), 'duplicate description entry'
        settable = {token for token, _, _ in _settable_keys()}
        assert set(described) == settable, (
            f'missing: {sorted(settable - set(described))}, '
            f'not settable: {sorted(set(described) - settable)}')

    def test_maximal_document_matches_schema(self):
        '''A document using every writer key validates against the schema.'''
        jsonschema = pytest.importorskip('jsonschema')
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        pair = {'light': '#000000', 'dark': '#000000'}
        doc = {
            'meta': {'name': 'Maximal', 'version': 1, 'author': 'A',
                     'description': 'D'},
            'separator': pair,
            'graphs': [pair, pair],
            'fonts': {
                'regular': {'family': 'Sans', 'size': 12},
                'monospace': {'family': 'Mono', 'size': 12},
            },
        }
        for _, section, key in _settable_keys():
            doc.setdefault(section, {})[key] = pair
        jsonschema.Draft202012Validator(schema).validate(doc)

    def test_extra_theme_dir_matches_schema(self):
        '''Validate written themes when WS_THEME_EXTRA_DIR points at a folder.'''
        jsonschema = pytest.importorskip('jsonschema')
        extra = os.environ.get('WS_THEME_EXTRA_DIR')
        if not extra:
            pytest.skip('WS_THEME_EXTRA_DIR is not set')
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        files = sorted(Path(extra).glob('*.jsonc'))
        assert files, f'no *.jsonc files in {extra}'
        for path in files:
            data = json.loads(_strip_jsonc(path.read_text(encoding='utf-8')))
            jsonschema.Draft202012Validator(schema).validate(data)


class TestThemeSystemIsTheSource:
    def test_key_table_rows_have_descriptions(self):
        '''Every settable key has a description, and the regex saw every row.'''
        rows = _writer_descriptions()
        text = WRITER_SOURCE.read_text(encoding='utf-8')
        assert len(rows) == len(re.findall(r'\{\s*ThemeManager::\w+,', text))
        assert all(description for _, description in rows)

    def test_every_derived_token_is_derived_with_a_source(self):
        '''Each token the parser cannot set is assigned in deriveAll() with a rule text.'''
        assignments = _derive_all_assignments()
        assert assignments
        missing_text = [t for t, s in assignments if not s]
        assert not missing_text, f'assign() without a source text: {missing_text}'
        assigned = {t for t, _ in assignments}
        derived_only = [n for n in _theme_token_names()
                        if not n.lower().startswith(tuple(_manager_sections())) and n != 'NoRole']
        missing = [n for n in derived_only if n not in assigned]
        assert not missing, f'tokens deriveAll() never assigns: {missing}'

    @pytest.mark.parametrize('path', [HANDLER_SOURCE, BUILDER_SOURCE], ids=lambda p: p.name)
    def test_rule_texts_name_known_colors(self, path):
        '''Every color a rule text names resolves to a ThemeToken.

        Reads the regex of ThemeTokenHandler::sourceTokens(), which backs the
        "Go to" entries of the color editor, from its source.
        '''
        texts = re.findall(
            r'QT_TRANSLATE_NOOP\(\s*"ThemeTokenHandler",\s*"((?:[^"\\]|\\.)+)"\s*\)',
            path.read_text(encoding='utf-8'))
        assert texts, f'no rule texts found in {path.name}'
        names = re.compile(_source_tokens_pattern())
        known = {n.lower() for n in _theme_token_names()}
        unknown = []
        for text in texts:
            for name in names.findall(text):
                if name.replace('.', '').lower() not in known:
                    unknown.append(f'{name!r} in {text!r}')
        assert not unknown, unknown

    def test_rule_text_lookup_matches_token_for_name(self):
        '''test_rule_texts_name_known_colors repeats ThemeManager::tokenForName().

        Python cannot call the C++ lookup, so the test drops the dots,
        lower-cases the name and compares it with the lower-cased
        enumerators.  This fails when the C++ lookup stops doing exactly that.
        '''
        text = MANAGER_SOURCE.read_text(encoding='utf-8')
        start = text.index('ThemeManager::tokenForName(')
        body = text[start:text.index('\n}\n', start)]
        assert "key.remove('.')" in body
        assert 'colorRoleCache_.value(key.toLower(), NoRole)' in body
        assert re.search(r'QString\(me\.key\(i\)\)\.toLower\(\);\s*'
                         r'colorRoleCache_\.insert\(key,', text)

    def test_stylesheet_tokens_exist(self):
        '''Every wstheme(Name) in the bundled style sheets names a ThemeToken.'''
        names = set(_theme_token_names())
        unknown = []
        for path in sorted(STYLESHEET_ROOT.rglob('*.qss')):
            for name in re.findall(r'wstheme\(\s*(\w+)\s*\)', path.read_text(encoding='utf-8')):
                if name not in names:
                    unknown.append(f'{path.name}: {name}')
        assert not unknown, unknown

    @pytest.mark.parametrize('path', DESIGNER_SOURCES, ids=lambda p: p.name)
    def test_designer_computes_no_colors(self, path):
        '''The Theme Designer reads colors from the theme system, never computes them.'''
        text = path.read_text(encoding='utf-8')
        for pattern in (r'ColorMath::', r'QColor\(\s*"#',
                        r'#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?\b'):
            assert not re.search(pattern, text), f'{path.name}: {pattern}'

    def test_required_sections_match_schema(self):
        '''Required sections and their keys are the schema's required ones.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        sections = _manager_sections()
        assert 'brand' in sections
        required = {name for name, req in sections.items() if req}
        assert required == set(schema['required']) - {'meta'}
        rows = _settable_keys()
        for name in required:
            keys = {key for _, section, key in rows if section == name}
            assert keys == set(schema['properties'][name].get('required', [])), name

    def test_root_keys_match_schema(self):
        '''Reserved root keys plus color sections are the schema's root properties.'''
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        reserved = _format_root_keys()
        assert 'meta' in reserved
        assert set(reserved) | set(_manager_sections()) == set(schema['properties'])
