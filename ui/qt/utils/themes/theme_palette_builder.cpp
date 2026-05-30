/* theme_palette_builder.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/theme_palette_builder.h"
#include "ui/qt/utils/themes/color_math.h"

#include <QApplication>
#include <QStyle>
#include <QStyleHints>

using TokenMap = ThemePaletteBuilder::TokenMap;

namespace {

// Pick the effective (light/dark) side of a pair stored in the token
// map.  Returns an invalid QColor when the token is absent or its pair
// contains no valid color for the requested side.
QColor sideOf(const TokenMap &tokens, ThemeManager::ThemeToken role, bool isDarkMode)
{
    if (role == ThemeManager::NoRole)
        return QColor();
    const ThemeColorPair p = tokens.value(role, ThemeColorPair());
    return isDarkMode ? p.dark : p.light;
}

// Baseline palette to start from, before applying theme overrides.
//
//   - macOS (any Qt) and
//     Windows (Qt ≥ 6.8): caller-supplied snapshot.  ThemeManager
//                         takes this from the platform style at
//                         construction time (pristine, before any
//                         setPalette() pollution) and refreshes it on
//                         scheme flips.  Reading
//                         QApplication::palette() here would be wrong:
//                         once we've pushed any palette, that call
//                         returns the customized palette — so
//                         successive theme switches would build on
//                         each other instead of restarting from the
//                         OS baseline.
//   - Linux (any Qt) and
//     Windows (Qt < 6.8): our own built-in light/dark palette, chosen
//                         by isDarkMode.  Needed because the Linux
//                         platform themes (and pre-6.8 Fusion) refuse
//                         to honor app-level setColorScheme().
QPalette baselinePalette(bool isDarkMode, const QPalette &osBaseline)
{
#if defined(Q_OS_MACOS) || (defined(Q_OS_WIN) && QT_VERSION >= QT_VERSION_CHECK(6, 8, 0))
    Q_UNUSED(isDarkMode);
    return osBaseline;
#else
    // Linux (any Qt) + Windows on Qt < 6.8:
    //
    // Qt's Linux platform integration *owns* QStyleHints::colorScheme
    // and keeps both the hint and QStyle::standardPalette() pinned to
    // the OS value — app-level setColorScheme() calls are silently
    // dropped.  Qt < 6.8 Fusion on Windows has similar issues.  So
    // even when Wireshark's mode disagrees with the OS (user picked
    // "Light" on a dark OS, or vice versa), trusting Qt would give us
    // the wrong baseline.
    //
    // Solution: don't trust Qt here at all.  Supply our own dark AND
    // light palettes, keyed purely on the mode we intend to render.
    // Loses some system-palette integration (Ubuntu oranges, etc.),
    // gains deterministic correctness across every mode/OS
    // combination.
    Q_UNUSED(osBaseline);
    return isDarkMode
        ? ThemePaletteBuilder::builtInDarkPalette()
        : ThemePaletteBuilder::builtInLightPalette();
#endif
}

} // namespace

QPalette ThemePaletteBuilder::builtInLightPalette()
{
    // Mirrors Qt Fusion's default light palette so a Wireshark "Light"
    // mode looks like a stock Fusion-light application — familiar to
    // users who were already running Wireshark that way.  Highlight /
    // Link / Accent are placeholders; apply() overlays brand.primary
    // over them.

    QPalette p;

    p.setColor(QPalette::Window,          QColor("#efefef"));
    p.setColor(QPalette::WindowText,      Qt::black);
    p.setColor(QPalette::Base,            Qt::white);
    p.setColor(QPalette::AlternateBase,   QColor("#f7f7f7"));
    p.setColor(QPalette::ToolTipBase,     QColor("#ffffdc"));
    p.setColor(QPalette::ToolTipText,     Qt::black);
    p.setColor(QPalette::Text,            Qt::black);
    p.setColor(QPalette::Button,          QColor("#efefef"));
    p.setColor(QPalette::ButtonText,      Qt::black);
    p.setColor(QPalette::BrightText,      Qt::red);
    p.setColor(QPalette::Link,            QColor("#007acc"));
    p.setColor(QPalette::Highlight,       QColor("#308cc6"));
    p.setColor(QPalette::HighlightedText, Qt::white);

    // 3D bevel/separator ladder + placeholder, derived from the flat
    // roles above (same derivation as the dark palette; here the base
    // is light so the same percent steps stay near-white at the top of
    // the ladder and grade down through the mid/dark/shadow grays).
    const QColor lightButton     = p.color(QPalette::Button);
    const QColor lightWindowText = p.color(QPalette::WindowText);
    p.setColor(QPalette::Light,           ColorMath::lighten(lightButton, 12));
    p.setColor(QPalette::Midlight,        ColorMath::lighten(lightButton, 6));
    p.setColor(QPalette::Mid,             ColorMath::darken(lightButton, 15));
    p.setColor(QPalette::Dark,            ColorMath::darken(lightButton, 30));
    p.setColor(QPalette::Shadow,          ColorMath::darken(lightButton, 55));
    p.setColor(QPalette::PlaceholderText, ColorMath::withAlphaF(lightWindowText, 0.5));

    // Disabled
    const QColor disabledText("#808080");
    p.setColor(QPalette::Disabled, QPalette::WindowText,      disabledText);
    p.setColor(QPalette::Disabled, QPalette::Text,            disabledText);
    p.setColor(QPalette::Disabled, QPalette::ButtonText,      disabledText);
    p.setColor(QPalette::Disabled, QPalette::HighlightedText, Qt::white);
    p.setColor(QPalette::Disabled, QPalette::Highlight,       QColor("#c8c8c8"));

    return p;
}

QPalette ThemePaletteBuilder::builtInDarkPalette()
{
    // Values based on QuantumCD's widely-reused "dark Fusion palette"
    // (https://gist.github.com/QuantumCD/6245215), with Disabled-group
    // coverage added so our own disabled() math works out.  Highlight /
    // Link / Accent are placeholders — apply() overlays the theme's
    // brand.primary over these before pushing the palette.

    QPalette p;

    // Active & Inactive (Qt applies the same color to both unless
    // overridden per-group).
    p.setColor(QPalette::Window,          QColor("#353535"));
    p.setColor(QPalette::WindowText,      Qt::white);
    p.setColor(QPalette::Base,            QColor("#191919"));
    p.setColor(QPalette::AlternateBase,   QColor("#353535"));
    p.setColor(QPalette::ToolTipBase,     QColor("#2a2a2a"));
    p.setColor(QPalette::ToolTipText,     Qt::white);
    p.setColor(QPalette::Text,            Qt::white);
    p.setColor(QPalette::Button,          QColor("#353535"));
    p.setColor(QPalette::ButtonText,      Qt::white);
    p.setColor(QPalette::BrightText,      Qt::red);
    p.setColor(QPalette::Link,            QColor("#2a82da"));
    p.setColor(QPalette::Highlight,       QColor("#2a82da"));
    p.setColor(QPalette::HighlightedText, Qt::black);

    // 3D bevel/separator ladder + placeholder, derived from the flat
    // roles above.  Native styles paint header gradients, button bevels
    // and separators from these; left unset they keep QPalette()'s
    // light-ish defaults and render light-on-dark.
    const QColor darkButton     = p.color(QPalette::Button);
    const QColor darkWindowText = p.color(QPalette::WindowText);
    p.setColor(QPalette::Light,           ColorMath::lighten(darkButton, 12));
    p.setColor(QPalette::Midlight,        ColorMath::lighten(darkButton, 6));
    p.setColor(QPalette::Mid,             ColorMath::darken(darkButton, 15));
    p.setColor(QPalette::Dark,            ColorMath::darken(darkButton, 30));
    p.setColor(QPalette::Shadow,          ColorMath::darken(darkButton, 55));
    p.setColor(QPalette::PlaceholderText, ColorMath::withAlphaF(darkWindowText, 0.5));

    // Disabled
    const QColor disabledText("#808080");
    p.setColor(QPalette::Disabled, QPalette::WindowText,      disabledText);
    p.setColor(QPalette::Disabled, QPalette::Text,            disabledText);
    p.setColor(QPalette::Disabled, QPalette::ButtonText,      disabledText);
    p.setColor(QPalette::Disabled, QPalette::HighlightedText, disabledText);
    p.setColor(QPalette::Disabled, QPalette::Highlight,       QColor("#505050"));

    return p;
}

QPalette ThemePaletteBuilder::build(const TokenMap                                     &tokens,
                                    bool                                                isDarkMode,
                                    const QHash<QString, ThemeManager::ThemeToken>     &tokenNameCache,
                                    const QHash<QString, QPalette::ColorRole>          &paletteRoleCache,
                                    const QPalette                                     &osBaseline)
{
    QPalette pal = baselinePalette(isDarkMode, osBaseline);

    // Apply theme-provided palette overrides.  Iterate over the full
    // QPalette role map so we only touch roles that Qt actually
    // defines; the token-name cache may not have a corresponding
    // ThemeToken for every QPalette::ColorRole (and that's fine —
    // unsupported roles simply retain whatever the baseline gave us).
    for (auto it = paletteRoleCache.constBegin(); it != paletteRoleCache.constEnd(); ++it) {
        const QString             &roleName = it.key();
        const QPalette::ColorRole  qpRole   = it.value();
        const ThemeManager::ThemeToken token = tokenNameCache.value(roleName, ThemeManager::NoRole);
        const QColor c = sideOf(tokens, token, isDarkMode);
        if (!c.isValid())
            continue;
        pal.setColor(QPalette::Active,   qpRole, c);
        pal.setColor(QPalette::Inactive, qpRole, c);
    }

    // Now do a second pass to derive Disabled-group colors from the
    // just-applied Active colors, using QPalette::Base as the blend
    // target.
    const QColor baseColor = pal.color(QPalette::Base);
    for (auto it = paletteRoleCache.constBegin(); it != paletteRoleCache.constEnd(); ++it) {
        const QString             &roleName = it.key();
        const QPalette::ColorRole  qpRole   = it.value();
        const ThemeManager::ThemeToken token = tokenNameCache.value(roleName, ThemeManager::NoRole);
        const QColor c = sideOf(tokens, token, isDarkMode);
        if (!c.isValid())
            continue;
        pal.setColor(QPalette::Disabled, qpRole, ColorMath::disabled(c, baseColor));
    }

    // Brand-driven overlay: Highlight, HighlightedText, Link (and
    // Accent on Qt 6.6+).  Themes get these for free from brand.primary;
    // no need to declare them in the palette section.
    //
    // HighlightedText is the one role here a theme can pre-empt: when
    // `palette.highlightedText` is declared, the loops above already
    // applied it, and the contrastingText() auto-derivation below
    // would otherwise overwrite that choice.  Some saturated
    // mid-tone brand colours sit on the WCAG luminance threshold where
    // contrastingText flips to black even though white reads better
    // (#0e9aa7 teal is one such case); themes can pin white here.
    const QColor brandPrimary = sideOf(tokens, ThemeManager::BrandPrimary, isDarkMode);
    if (brandPrimary.isValid()) {
        const QColor explicitHighlightedText =
                sideOf(tokens, ThemeManager::PaletteHighlightedText, isDarkMode);
        const QColor effectiveHighlightedText = explicitHighlightedText.isValid()
                ? explicitHighlightedText
                : ColorMath::contrastingText(brandPrimary);
        if (!explicitHighlightedText.isValid())
            pal.setColor(QPalette::HighlightedText, effectiveHighlightedText);
        pal.setColor(QPalette::Disabled, QPalette::HighlightedText,
                     ColorMath::disabled(effectiveHighlightedText, baseColor));

        QList<QPalette::ColorRole> brandRoles = { QPalette::Highlight, QPalette::Link };
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        brandRoles << QPalette::Accent;
#endif
        for (QPalette::ColorRole role : brandRoles) {
            pal.setColor(QPalette::Active,   role, brandPrimary);
            pal.setColor(QPalette::Inactive, role, brandPrimary);
            pal.setColor(QPalette::Disabled, role, ColorMath::disabled(brandPrimary, baseColor));
        }
    }

    return pal;
}

void ThemePaletteBuilder::apply(const TokenMap                                     &tokens,
                                bool                                                isDarkMode,
                                const QHash<QString, ThemeManager::ThemeToken>     &tokenNameCache,
                                const QHash<QString, QPalette::ColorRole>          &paletteRoleCache,
                                const QPalette                                     &osBaseline)
{
    QApplication::setPalette(build(tokens, isDarkMode, tokenNameCache, paletteRoleCache, osBaseline));
}
