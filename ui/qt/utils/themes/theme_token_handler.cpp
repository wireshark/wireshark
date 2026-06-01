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

    // Filter state — tinted accent-on-Base backgrounds.  Default alpha
    // is 85 (~33%) rather than the historical 102 (~40%); the lower
    // value keeps the default Material-leaning accents from
    // overpowering the field background.  Themes that prefer the
    // legacy saturated GTK/Tango look ship explicit hex values in
    // theme.filter and let assign()'s only-if-missing semantics keep
    // them intact.  Foreground for valid/invalid/deprecated is the
    // caller's problem: pair with QPalette::Text, which contrasts
    // against Base.
    assign(tokens, ThemeManager::FilterValid,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentSuccess), 85));
    assign(tokens, ThemeManager::FilterInvalid,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentError), 85));
    assign(tokens, ThemeManager::FilterDeprecated,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ThemeManager::AccentWarning), 85));

    // Filter Busy — bg and fg used while a capture filter compiles
    // off-thread.  Default bg is palette.base (no tint) and fg is the
    // text colour faded 50% into base, which matches the placeholder-
    // text look QLineEdit shows for empty fields.  Themes can ship a
    // more distinct look via theme.filter.busy / theme.filter.busyText.
    const QColor paletteTextColor = pickPaletteValue(tokens, ThemeManager::PaletteText, QPalette::Text, isDarkMode, palette);
    assign(tokens, ThemeManager::FilterBusy,
           ThemeColorPair { baseColor, baseColor });
    assign(tokens, ThemeManager::FilterBusyText,
           ColorMath::mix(ThemeColorPair { paletteTextColor, paletteTextColor },
                          ThemeColorPair { baseColor, baseColor },
                          0.5));

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

    // Text on dark surfaces (derived from brand) — computed first so the
    // HeaderGradientEnd derivation below can clamp against them.
    //
    // TextOnDarkMuted is the foreground for "secondary" labels sitting on
    // the brand gradient (e.g. the version string under the title).  It
    // is intentionally less prominent than TextOnDark, but it must stay
    // readable across the whole gradient — including over portions that
    // get close to brand.primary.  ColorMath::disabled() blends 40% of
    // the bg into white, which collapses contrast for themes whose
    // brand.deep approaches pure black (mid-gray text on bright primary
    // ⇒ ~1.5:1).  Using a 0.25 mix instead keeps the muted text closer
    // to white (~75% mix) so it survives the brighter half of the
    // gradient without becoming as bold as the title.
    const QColor textOnDarkLight       = ColorMath::contrastingText(brandDeep.light);
    const QColor textOnDarkDark        = ColorMath::contrastingText(brandDeep.dark);
    const QColor textOnDarkMutedLight  = ColorMath::mix(textOnDarkLight, brandDeep.light, 0.25);
    const QColor textOnDarkMutedDark   = ColorMath::mix(textOnDarkDark,  brandDeep.dark,  0.25);
    assign(tokens, ThemeManager::TextOnDark,
           ThemeColorPair { textOnDarkLight, textOnDarkDark });
    assign(tokens, ThemeManager::TextOnDarkMuted,
           ThemeColorPair { textOnDarkMutedLight, textOnDarkMutedDark });

    // Header gradient — START is brand.deep (intentionally near-black).
    // END auto-adjusts via two ensureContrast passes so BOTH the title
    // (TextOnDark, 4.5:1) and the version label (TextOnDarkMuted, 3.0:1)
    // stay readable against it.  Without this clamp, themes whose
    // brand.primary is bright fail by one to two stops (e.g. the old
    // Wireshark dark #5b9ee6 → title 2.8, version 1.6).  Themes whose
    // primary is already dark enough are unaffected — ensureContrast
    // short-circuits when the ratio is already met.
    QColor gradientEndLight = ColorMath::ensureContrast(brandPrimary.light, textOnDarkLight,      4.5);
    gradientEndLight        = ColorMath::ensureContrast(gradientEndLight,   textOnDarkMutedLight, 3.0);
    QColor gradientEndDark  = ColorMath::ensureContrast(brandPrimary.dark,  textOnDarkDark,       4.5);
    gradientEndDark         = ColorMath::ensureContrast(gradientEndDark,    textOnDarkMutedDark,  3.0);
    assign(tokens, ThemeManager::HeaderGradientStart, brandDeep);
    assign(tokens, ThemeManager::HeaderGradientEnd,
           ThemeColorPair { gradientEndLight, gradientEndDark });

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

    // Foregrounds for solid accent surfaces — auto-pick black or white
    // per contrastingText().  These give QSS rules a single token to
    // paint text on accent backgrounds without each theme having to
    // hand-tune the contrast (or rely on a fixed `wstheme(TextOnDark)`
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
