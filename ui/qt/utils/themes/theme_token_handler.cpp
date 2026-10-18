/* theme_token_handler.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/theme_token_handler.h"
#include "ui/qt/utils/themes/color_math.h"

#include <QPalette>

using TokenMap = ThemeTokenHandler::TokenMap;
using ThemeToken = ThemeManager::ThemeToken;

namespace {

// Only-if-missing assignment: leaves any theme-provided explicit value
// intact (matches the old ThemeManager::derive(..., overwrite=false)
// behavior).  `overwrite=true` forces the replacement; the state-text
// guard in deriveAll() uses it to rewrite a pinned value that is not
// readable on its fill.
void assign(TokenMap &tokens,
            ThemeToken role,
            const ThemeColorPair &newPair,
            bool overwrite = false)
{
    ThemeColorPair pair = tokens.value(role, ThemeColorPair());
    if (overwrite || !pair.light.isValid())
        pair.light = newPair.light;
    if (overwrite || !pair.dark.isValid())
        pair.dark = newPair.dark;
    tokens[role] = pair;
}

void assign(TokenMap &tokens,
            ThemeToken role,
            const QColor &light,
            const QColor &dark,
            bool overwrite = false)
{
    assign(tokens, role, ThemeColorPair { light, dark }, overwrite);
}

// Picks the effective color for a palette-override role, falling back
// to `palette` when the theme doesn't override that role.  Using the
// pre-built palette (rather than QApplication::palette()) ensures the
// correct values are used even before the palette has been pushed to
// QApplication — see ThemeTokenHandler::deriveAll() parameter docs.
QColor pickPaletteValue(const TokenMap &tokens,
                        ThemeToken role,
                        QPalette::ColorRole qtRole,
                        bool isDarkMode,
                        const QPalette &palette)
{
    if (tokens.contains(role)) {
        const ThemeColorPair &p = tokens.value(role);
        return isDarkMode ? p.dark : p.light;
    }
    return palette.color(qtRole);
}

// readableText() for one side of a pair.  A side the theme leaves
// invalid stays invalid, so assign() can still fill it later.
QColor readableSide(const QColor &text, const QColor &fill)
{
    return text.isValid() && fill.isValid() ? ColorMath::readableText(text, fill) : text;
}

} // namespace

void ThemeTokenHandler::deriveAll(TokenMap &tokens, bool isDarkMode, const QPalette &palette)
{
    const ThemeColorPair successPair  = tokens.value(ThemeManager::AccentSuccess);
    const ThemeColorPair brandPrimary = tokens.value(ThemeManager::BrandPrimary);

    const QColor mid        = palette.color(QPalette::Mid);
    // Flat update bar; the dismiss button tints are computed on it.
    const ThemeColorPair updateBg   = ColorMath::darken(successPair, 60);
    const ThemeColorPair disabledBg = ColorMath::darken(successPair, 40);

    // Expert — alpha-blended accent variants.
    assign(tokens, ThemeManager::ExpertNone,
           ColorMath::withAlpha(tokens.value(ThemeManager::AccentInfo), 102));
    assign(tokens, ThemeManager::ExpertComment,
           ColorMath::withAlpha(tokens.value(ThemeManager::AccentSuccess), 102));
    assign(tokens, ThemeManager::ExpertChat,
           ColorMath::withAlpha(tokens.value(ThemeManager::AccentInfo), 102));
    assign(tokens, ThemeManager::ExpertNote,
           ColorMath::withAlpha(tokens.value(ThemeManager::AccentInfo), 102));
    assign(tokens, ThemeManager::ExpertWarn,
           ColorMath::withAlpha(tokens.value(ThemeManager::AccentWarning), 102));
    assign(tokens, ThemeManager::ExpertError,
           ColorMath::withAlpha(tokens.value(ThemeManager::AccentError), 102));
    assign(tokens, ThemeManager::ExpertForeground,
           ColorMath::contrastingText(tokens.value(ThemeManager::ExpertComment)));

    // Packets / Conversation — need concrete Base / Text / WindowText
    // values.  Read them from the theme's palette overrides if set,
    // otherwise fall back to the current QApplication palette.
    const QColor baseColor   = pickPaletteValue(tokens, ThemeManager::PaletteBase,       QPalette::Base,       isDarkMode, palette);
    const QColor windowColor = pickPaletteValue(tokens, ThemeManager::PaletteWindow,     QPalette::Window,     isDarkMode, palette);
    const QColor textColor   = pickPaletteValue(tokens, ThemeManager::PaletteWindowText, QPalette::WindowText, isDarkMode, palette);

    const QColor paletteTextColor = pickPaletteValue(tokens, ThemeManager::PaletteText, QPalette::Text, isDarkMode, palette);

    assign(tokens, ThemeManager::PacketsSelection,
           ColorMath::mix(ThemeColorPair { baseColor,   baseColor   }, brandPrimary,                                0.30));
    assign(tokens, ThemeManager::PacketsInactive,
           ColorMath::mix(ThemeColorPair { windowColor, windowColor }, brandPrimary,                                0.40));
    assign(tokens, ThemeManager::PacketsMarked,   ColorMath::darken(brandPrimary, 65));
    // PacketsIgnored (bg) intentionally has no derivation — when the
    // theme omits it the consumer leaves the row's normal background
    // alone (matches the historical white-on-row visual).
    // Ignored and hidden rows fade the text toward Base, so they stay
    // readable on any background instead of drifting toward an accent.
    assign(tokens, ThemeManager::PacketsIgnoredText,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, ThemeColorPair { textColor, textColor }, 0.50));
    assign(tokens, ThemeManager::PacketsHidden,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, ThemeColorPair { textColor, textColor }, 0.40));

    // State text: the theme's pin, else black or white by WCAG luminance
    // against the state's fill.  Either way it is lifted to body-text
    // contrast against that fill, per mode, so a pin chosen for another
    // shade (or a fill derived from brand.primary) never turns unreadable.
    // The packet list and every other consumer read these tokens, so this
    // is the one place the state text is checked.
    const struct { ThemeToken text; ThemeToken fill; } stateText[] = {
        { ThemeManager::PacketsSelectionText, ThemeManager::PacketsSelection },
        { ThemeManager::PacketsInactiveText,  ThemeManager::PacketsInactive  },
        { ThemeManager::PacketsMarkedText,    ThemeManager::PacketsMarked    },
    };
    for (const auto &st : stateText) {
        const ThemeColorPair fill = tokens.value(st.fill);
        assign(tokens, st.text, ColorMath::contrastingText(fill));
        const ThemeColorPair text = tokens.value(st.text);
        assign(tokens, st.text,
               ThemeColorPair { readableSide(text.light, fill.light),
                                readableSide(text.dark,  fill.dark) },
               true);
    }

    // Conversation
    const ThemeColorPair accentError = tokens.value(ThemeManager::AccentError);
    assign(tokens, ThemeManager::ConversationClient,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, accentError, 102.0 / 255.0));
    assign(tokens, ThemeManager::ConversationServer,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, brandPrimary, 102.0 / 255.0));
    // Stream-side text fallback: warm for client (saturated accent.error),
    // cool for server (saturated brand.primary).  Direction flips by mode
    // so the fg stays readable on both the light and dark bg tints.
    assign(tokens, ThemeManager::ConversationClientText,
           ThemeColorPair { ColorMath::darken (accentError.light, 30),
                            ColorMath::lighten(accentError.dark,  50) });
    assign(tokens, ThemeManager::ConversationServerText,
           ThemeColorPair { ColorMath::darken (brandPrimary.light, 30),
                            ColorMath::lighten(brandPrimary.dark,  50) });

    // Filter state — tinted accent-on-Base backgrounds.  Default alpha
    // is 85 (~33%) rather than the historical 102 (~40%); the lower
    // value keeps the default Material-leaning accents from
    // overpowering the field background.  Themes that prefer the
    // legacy saturated GTK/Tango look ship explicit hex values in
    // theme.filter and let assign()'s only-if-missing semantics keep
    // them intact.  The foreground on each tint is derived below as
    // TextOnFilter*, so the text stays readable whichever side of the
    // luminance threshold the tint lands on.
    assign(tokens, ThemeManager::FilterValid,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentSuccess), 85.0 / 255.0));
    assign(tokens, ThemeManager::FilterInvalid,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentError), 85.0 / 255.0));
    assign(tokens, ThemeManager::FilterDeprecated,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentWarning), 85.0 / 255.0));

    // Filter Busy — bg and fg used while a capture filter compiles
    // off-thread.  Default bg is palette.base (no tint) and fg is the
    // text colour faded 50% into base, which matches the placeholder-
    // text look QLineEdit shows for empty fields.  Themes can ship a
    // more distinct look via theme.filter.busy / theme.filter.busyText.
    assign(tokens, ThemeManager::FilterBusy,
           ThemeColorPair { baseColor, baseColor });
    assign(tokens, ThemeManager::FilterBusyText,
           ColorMath::mix(ThemeColorPair { paletteTextColor, paletteTextColor },
                          ThemeColorPair { baseColor, baseColor },
                          0.5));

    // Inline filter-affordance glyph colours (bookmark / clear / apply icon
    // fills).  These are full-strength glyph tints, not the alpha bg tints
    // above, so they default to the matching accent verbatim (no mix-with-base).
    // assign()'s only-if-missing semantics let a theme pin explicit values via
    // theme.filter.bookmark / .bookmarkcapture / .bookmarkmatch / .clear /
    // .apply while still guaranteeing every theme has the tokens defined.
    assign(tokens, ThemeManager::FilterBookmark,        tokens.value(ThemeManager::AccentInfo));
    assign(tokens, ThemeManager::FilterBookmarkCapture, tokens.value(ThemeManager::AccentSuccess));
    assign(tokens, ThemeManager::FilterBookmarkMatch,   tokens.value(ThemeManager::AccentWarning));
    assign(tokens, ThemeManager::FilterClear,           tokens.value(ThemeManager::AccentError));
    assign(tokens, ThemeManager::FilterApply,           tokens.value(ThemeManager::AccentInfo));

    // The recent-filters arrow reads as a subtle disclosure caret at rest, so it
    // defaults to palette.mid (a mode-aware gray) rather than a saturated accent.
    // It brightens to a strong colour on hover/press, supplied per-mode by the
    // button's ThemedIcon; this token only sets the resting tint.  The default
    // theme pins the classic combo-arrow Tango grays via theme.filter.history.
    {
        const QColor midGray = pickPaletteValue(tokens, ThemeManager::PaletteMid, QPalette::Mid, isDarkMode, palette);
        assign(tokens, ThemeManager::FilterHistory, ThemeColorPair { midGray, midGray });
    }

    // Syntax highlighting — readable foreground text on PaletteBase.
    // Keys reuse the palette's Mid role (naturally a mode-aware gray).
    // String / number colours shift the accent away from the
    // background: darker in light mode (toward black), lighter in
    // dark mode (toward white) — mirroring how the Tango palette
    // pairs chameleon_5/_3 and sky_blue_5/_3 did pre-theme.
    const QColor midColor = pickPaletteValue(tokens, ThemeManager::PaletteMid, QPalette::Mid, isDarkMode, palette);
    const ThemeColorPair accentSuccess = tokens.value(ThemeManager::AccentSuccess);
    const ThemeColorPair accentInfo    = tokens.value(ThemeManager::AccentInfo);
    assign(tokens, ThemeManager::SyntaxKey,
           ThemeColorPair { midColor, midColor });
    assign(tokens, ThemeManager::SyntaxString,
           ThemeColorPair { ColorMath::darken(accentSuccess.light, 30),
                            ColorMath::lighten(accentSuccess.dark,  30) });
    assign(tokens, ThemeManager::SyntaxNumber,
           ThemeColorPair { ColorMath::darken(accentInfo.light, 30),
                            ColorMath::lighten(accentInfo.dark,  30) });

    // Welcome header bar: a flat, darkened shade of the selection color.
    // Highlight / HighlightedText come from the palette built for this
    // theme (palette.highlight, else packets.selection, else
    // brand.primary, as resolved by ThemePaletteBuilder), so the choice
    // is made in one place.  The bar is first kept apart from the
    // window so it never melts into it (a dark selection darkened by
    // 40 % lands almost on a dark window), then shifted only as far as
    // the title needs to read.  The version label is the title color
    // faded 25 % toward the bar, lifted back to 3.0:1 if that overshoots.
    const QColor highlight     = palette.color(QPalette::Active, QPalette::Highlight);
    const QColor highlightText = palette.color(QPalette::Active, QPalette::HighlightedText);
    QColor headerBg = ColorMath::ensureContrast(ColorMath::darken(highlight, 40),
                                                windowColor, ColorMath::DistinctSurfaceRatio);
    // The title keeps HighlightedText when that reads on the bar, else
    // it switches to black or white outright.  readableText() would stop
    // at a grey just at the threshold (inverted, midnight-blue light),
    // too weak for a title.
    const QColor headerText = ColorMath::isReadable(highlightText, headerBg)
            ? highlightText : ColorMath::contrastingText(headerBg);
    headerBg = ColorMath::ensureContrast(headerBg, headerText,
            ColorMath::ReadableTextRatio);
    const QColor headerMuted = ColorMath::ensureContrast(
            ColorMath::mix(headerText, headerBg, 0.25), headerBg, 3.0);
    // The palette describes only the current mode; deriveAll() runs again
    // on every mode switch, so both halves carry the current value.
    assign(tokens, ThemeManager::HeaderBackground, ThemeColorPair { headerBg,    headerBg });
    assign(tokens, ThemeManager::HeaderText,        ThemeColorPair { headerText,  headerText });
    assign(tokens, ThemeManager::HeaderTextMuted,   ThemeColorPair { headerMuted, headerMuted });

    // Section headers — ensureContrast against palette.base at 4.5:1 so
    // welcome-page labels ("Open", "Capture", "Learn") stay readable on
    // every shipped theme regardless of whether the theme overrides
    // palette.mid.  Replaces the legacy `mid, mid` assignment that left
    // the labels invisible on dark Wireshark.
    const QColor sectionHeader      = ColorMath::ensureContrast(mid,                  baseColor, 4.5);
    const QColor sectionHeaderHover = ColorMath::ensureContrast(brandPrimary.dark,    baseColor, 4.5);
    // Light-mode hover uses the light brand value; the off-mode slot is
    // unused at runtime but is filled symmetrically.
    const QColor sectionHeaderHoverLight = ColorMath::ensureContrast(brandPrimary.light, baseColor, 4.5);
    assign(tokens, ThemeManager::SectionHeader,
           ThemeColorPair { sectionHeader, sectionHeader });
    assign(tokens, ThemeManager::SectionHeaderHover,
           ThemeColorPair { sectionHeaderHoverLight, sectionHeaderHover });

    // Structural form chrome — FieldBorder frames interactive controls
    // (3.0:1 against base, the WCAG non-text contrast minimum).
    // Separator is a softer divider; defaults to a 53% mix of base
    // toward mid for hairlines between cards.  Themes can pin Separator
    // via the JSONC "separator" top-level key (Stratoshark does, since
    // its palette.mid intentionally doubles as muted text and would
    // produce too-pronounced dividers otherwise).
    const QColor fieldBorder = ColorMath::ensureContrast(mid, baseColor, 3.0);
    const QColor separator   = ColorMath::mix(baseColor, mid, 135.0 / 255.0);
    assign(tokens, ThemeManager::FieldBorder,
           ThemeColorPair { fieldBorder, fieldBorder });
    assign(tokens, ThemeManager::Separator,
           ThemeColorPair { separator, separator });

    // Secondary text: Text faded 40 % toward Base, then lifted to the
    // 4.5:1 WCAG text contrast minimum against Base.
    const QColor mutedText = ColorMath::ensureContrast(
        ColorMath::mix(paletteTextColor, baseColor, 0.40), baseColor, 4.5);
    assign(tokens, ThemeManager::MutedText, ThemeColorPair { mutedText, mutedText });

    // Foregrounds for solid accent surfaces — auto-pick black or white
    // per contrastingText().  These give QSS rules a single token to
    // paint text on accent backgrounds without each theme having to
    // hand-tune the contrast (or rely on one fixed text color
    // that may not fit a bright accent — see #headerBuildLabel and
    // #updateDownload in welcome-header.qss).
    assign(tokens, ThemeManager::TextOnSuccess,
           ColorMath::contrastingText(successPair));
    assign(tokens, ThemeManager::TextOnWarning,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentWarning)));
    assign(tokens, ThemeManager::TextOnError,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentError)));
    assign(tokens, ThemeManager::TextOnInfo,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentInfo)));

    // Foreground for the filter validity tints.
    assign(tokens, ThemeManager::TextOnFilterValid,
           ColorMath::contrastingText(tokens.value(ThemeManager::FilterValid)));
    assign(tokens, ThemeManager::TextOnFilterInvalid,
           ColorMath::contrastingText(tokens.value(ThemeManager::FilterInvalid)));
    assign(tokens, ThemeManager::TextOnFilterDeprecated,
           ColorMath::contrastingText(tokens.value(ThemeManager::FilterDeprecated)));

    // Update bar — all from accent.success
    assign(tokens, ThemeManager::UpdateBackground,       updateBg);
    assign(tokens, ThemeManager::UpdateBorder,           ColorMath::withAlpha(successPair, 51));
    assign(tokens, ThemeManager::UpdateText,             ColorMath::lighten(successPair, 50));
    assign(tokens, ThemeManager::UpdateTextHighlight,    ColorMath::lighten(successPair, 70));
    assign(tokens, ThemeManager::UpdateLink,             ColorMath::lighten(successPair, 30));
    assign(tokens, ThemeManager::UpdateLinkHover,        ColorMath::lighten(successPair, 50));
    assign(tokens, ThemeManager::UpdateLinkPressed,      ColorMath::darken(successPair, 20));
    assign(tokens, ThemeManager::UpdateButtonBg,         successPair);
    assign(tokens, ThemeManager::UpdateButtonHover,      ColorMath::darken(successPair, 8));
    assign(tokens, ThemeManager::UpdateButtonPressed,    ColorMath::darken(successPair, 16));
    assign(tokens, ThemeManager::UpdateButtonDisabledBg, disabledBg);
    // Disabled button text: contrasting text faded toward the disabled button bg
    assign(tokens, ThemeManager::UpdateButtonDisabledText,
           ColorMath::disabled(ColorMath::contrastingText(disabledBg.light), disabledBg.light),
           ColorMath::disabled(ColorMath::contrastingText(disabledBg.dark),  disabledBg.dark));
    // Dismiss hover: subtle tint of contrasting color onto the bar
    assign(tokens, ThemeManager::UpdateDismissHoverBg,
           ColorMath::hoverBg(ColorMath::contrastingText(updateBg.light), updateBg.light),
           ColorMath::hoverBg(ColorMath::contrastingText(updateBg.dark), updateBg.dark));
    // Dismiss pressed: same pattern but use disabled() for a stronger blend
    assign(tokens, ThemeManager::UpdateDismissPressedBg,
           ColorMath::disabled(ColorMath::hoverBg(ColorMath::contrastingText(updateBg.light), updateBg.light), updateBg.light),
           ColorMath::disabled(ColorMath::hoverBg(ColorMath::contrastingText(updateBg.dark), updateBg.dark), updateBg.dark));

    // Accent aliases (derived)
    assign(tokens, ThemeManager::HighlightColorOrange, tokens.value(ThemeManager::AccentWarning));
    assign(tokens, ThemeManager::HighlightColorGreen,  successPair);
}
