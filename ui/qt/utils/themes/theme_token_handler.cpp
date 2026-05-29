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
// behavior).  `overwrite=true` forces the replacement — not used today
// but kept on the signature to match the old API in case a derivation
// ever needs it.
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

} // namespace

void ThemeTokenHandler::deriveAll(TokenMap &tokens, bool isDarkMode, const QPalette &palette)
{
    const ThemeColorPair successPair  = tokens.value(ThemeManager::AccentSuccess);
    const ThemeColorPair brandPrimary = tokens.value(ThemeManager::BrandPrimary);
    const ThemeColorPair brandDeep    = tokens.value(ThemeManager::BrandDeep);

    const QColor mid        = palette.color(QPalette::Mid);
    const QColor lBarEnd    = ColorMath::darken(successPair.light, 60);
    const QColor dBarEnd    = ColorMath::darken(successPair.dark, 60);
    const ThemeColorPair disabledBg = ColorMath::darken(successPair, 40);

    // Expert — alpha-blended accent variants.
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
    const QColor windowColor = pickPaletteValue(tokens, ThemeManager::PaletteText,       QPalette::Window,     isDarkMode, palette);
    const QColor textColor   = pickPaletteValue(tokens, ThemeManager::PaletteWindowText, QPalette::WindowText, isDarkMode, palette);

    assign(tokens, ThemeManager::PacketsSelection,
           ColorMath::mix(ThemeColorPair { baseColor,   baseColor   }, brandPrimary,                                30));
    assign(tokens, ThemeManager::PacketsInactive,
           ColorMath::mix(ThemeColorPair { windowColor, windowColor }, brandPrimary,                                40));
    assign(tokens, ThemeManager::PacketsMarked,   ColorMath::darken(brandPrimary, 65));
    // PacketsIgnored (bg) intentionally has no derivation — when the
    // theme omits it the consumer leaves the row's normal background
    // alone (matches the historical white-on-row visual).
    assign(tokens, ThemeManager::PacketsIgnoredText,
           ColorMath::mix(ThemeColorPair { textColor, textColor }, successPair, 50));
    assign(tokens, ThemeManager::PacketsHidden,
           ColorMath::mix(ThemeColorPair { textColor, textColor }, successPair, 40));

    // Foreground fallbacks — only kicks in when a custom theme provides
    // a bg tint but omits its <bg>Text sibling.  contrastingText picks
    // white/black per WCAG luminance against each side of the pair.
    assign(tokens, ThemeManager::PacketsSelectionText,
           ColorMath::contrastingText(tokens.value(ThemeManager::PacketsSelection)));
    assign(tokens, ThemeManager::PacketsInactiveText,
           ColorMath::contrastingText(tokens.value(ThemeManager::PacketsInactive)));
    assign(tokens, ThemeManager::PacketsMarkedText,
           ColorMath::contrastingText(tokens.value(ThemeManager::PacketsMarked)));

    // Conversation
    const ThemeColorPair accentError = tokens.value(ThemeManager::AccentError);
    assign(tokens, ThemeManager::ConversationClient,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, accentError, 102));
    assign(tokens, ThemeManager::ConversationServer,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, brandPrimary, 102));
    // Stream-side text fallback: warm for client (saturated accent.error),
    // cool for server (saturated brand.primary).  Direction flips by mode
    // so the fg stays readable on both the light and dark bg tints.
    assign(tokens, ThemeManager::ConversationClientText,
           ThemeColorPair { ColorMath::darken (accentError.light, 30),
                            ColorMath::lighten(accentError.dark,  50) });
    assign(tokens, ThemeManager::ConversationServerText,
           ThemeColorPair { ColorMath::darken (brandPrimary.light, 30),
                            ColorMath::lighten(brandPrimary.dark,  50) });

    // Filter state — tinted accent-on-Base backgrounds (same pattern
    // as Conversation).  Foreground is the caller's problem: pair with
    // QPalette::Text, which contrasts against Base.
    assign(tokens, ThemeManager::FilterValid,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentSuccess), 102));
    assign(tokens, ThemeManager::FilterInvalid,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentError), 102));
    assign(tokens, ThemeManager::FilterDeprecated,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentWarning), 102));

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

    // Header (derived from brand)
    assign(tokens, ThemeManager::HeaderGradientStart, brandDeep);
    assign(tokens, ThemeManager::HeaderGradientEnd,   brandPrimary);

    // Section headers (derived from QPalette::Mid at runtime)
    assign(tokens, ThemeManager::SectionHeader,      ThemeColorPair { mid, mid });
    assign(tokens, ThemeManager::SectionHeaderHover, brandPrimary);

    // Text on dark surfaces (derived from brand)
    assign(tokens, ThemeManager::TextOnDark, ColorMath::contrastingText(brandDeep));
    assign(tokens, ThemeManager::TextOnDarkMuted,
           ColorMath::disabled(ColorMath::contrastingText(brandDeep.light), brandDeep.light),
           ColorMath::disabled(ColorMath::contrastingText(brandDeep.dark),  brandDeep.dark));

    // Update bar — all from accent.success
    assign(tokens, ThemeManager::UpdateGradientStart,    ColorMath::darken(successPair, 65));
    assign(tokens, ThemeManager::UpdateGradientEnd,      ColorMath::darken(successPair, 60));
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
           ColorMath::hoverBg(ColorMath::contrastingText(lBarEnd), lBarEnd),
           ColorMath::hoverBg(ColorMath::contrastingText(dBarEnd), dBarEnd));
    // Dismiss pressed: same pattern but use disabled() for a stronger blend
    assign(tokens, ThemeManager::UpdateDismissPressedBg,
           ColorMath::disabled(ColorMath::hoverBg(ColorMath::contrastingText(lBarEnd), lBarEnd), lBarEnd),
           ColorMath::disabled(ColorMath::hoverBg(ColorMath::contrastingText(dBarEnd), dBarEnd), dBarEnd));

    // Accent aliases (derived)
    assign(tokens, ThemeManager::HighlightColorOrange, successPair);
    assign(tokens, ThemeManager::HighlightColorGreen,  successPair);
}
