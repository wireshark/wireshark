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
#include "ui/qt/utils/themes/theme_token_handler.h"

#include <QStyle>
#include <QStyleHints>

using TokenMap = ThemePaletteBuilder::TokenMap;

namespace {

// Baseline palette to start from, before applying theme overrides.
//
//   - macOS (any Qt) and
//     Windows (Qt ≥ 6.8): caller-supplied snapshot.  ThemeManager
//                         captures the platform palette at
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
    // Link / Accent are placeholders; build() overlays the theme's
    // selection color (Highlight, Link) and brand.primary (Accent) over
    // them.

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
    // Link / Accent are placeholders; build() overlays the theme's
    // selection color (Highlight, Link) and brand.primary (Accent) over
    // them.

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
                                    const QPalette                                     &osBaseline,
                                    const ColorMath::ContrastRatios                    &ratios,
                                    QHash<ThemeManager::ThemeToken, const char *>      *sources)
{
    QPalette pal = baselinePalette(isDarkMode, osBaseline);

    // The OS baseline's Inactive group (e.g. macOS, when the window is in
    // the background) can carry text colors that don't match the mode,
    // leaving header and button text dark on a dark background.  Keep
    // text legible by making Inactive text follow Active.
    for (QPalette::ColorRole role : { QPalette::WindowText, QPalette::ButtonText,
                                      QPalette::Text, QPalette::PlaceholderText }) {
        pal.setColor(QPalette::Inactive, role, pal.color(QPalette::Active, role));
    }

    // Apply theme-provided palette overrides.  Iterate over the full
    // QPalette role map so we only touch roles that Qt actually
    // defines; the token-name cache may not have a corresponding
    // ThemeToken for every QPalette::ColorRole (and that's fine —
    // unsupported roles simply retain whatever the baseline gave us).
    for (auto it = paletteRoleCache.constBegin(); it != paletteRoleCache.constEnd(); ++it) {
        const QString             &roleName = it.key();
        const QPalette::ColorRole  qpRole   = it.value();
        const ThemeManager::ThemeToken token = tokenNameCache.value(roleName, ThemeManager::NoRole);
        const QColor c = ThemeTokenHandler::sideOf(tokens, token, isDarkMode);
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
        const QColor c = ThemeTokenHandler::sideOf(tokens, token, isDarkMode);
        if (!c.isValid())
            continue;
        pal.setColor(QPalette::Disabled, qpRole, ColorMath::disabled(c, baseColor));
    }

    // Sets a role in the Active and Inactive groups, and its Disabled
    // variant blended toward Base.
    const auto setAllGroups = [&pal, &baseColor](QPalette::ColorRole role, const QColor &c) {
        pal.setColor(QPalette::Active,   role, c);
        pal.setColor(QPalette::Inactive, role, c);
        pal.setColor(QPalette::Disabled, role, ColorMath::disabled(c, baseColor));
    };

    // Brand-driven overlay: Highlight, HighlightedText, Link (and
    // Accent on Qt 6.6+).
    //
    // Highlight is the selection color of every view except the packet
    // list (lists, the details tree, the bytes pane) and the base of the
    // welcome header.  It resolves to `palette.highlight` when the theme
    // declares it, else to the theme's own `packets.selection`, so a
    // selection looks the same in every pane without the theme repeating
    // the value, else to brand.primary.  Only declared values count:
    // callers pass the parsed token map, before
    // ThemeTokenHandler::deriveAll() fills PacketsSelection from
    // brand.primary.
    //
    // HighlightedText is the theme's `palette.highlightedText` when it
    // pins one (a saturated selection color can sit where
    // contrastingText() picks black although the theme wants white),
    // else the theme's `packets.selectionText` when the highlight is the
    // theme's `packets.selection`, so a theme states its selection text
    // once, else contrastingText() of the resolved highlight.  Either way it is
    // lifted to body-text contrast against that highlight: the highlight
    // may come from packets.selection or brand.primary, so a pin chosen
    // for one color must not turn unreadable on another.  Every Qt-drawn
    // selection and every delegate that paints selected text reads this
    // role, so this is the one place the selection text is checked.
    const QColor brandPrimary = ThemeTokenHandler::sideOf(tokens, ThemeManager::BrandPrimary, isDarkMode);
    if (brandPrimary.isValid()) {
        const QColor pinnedHighlight =
                ThemeTokenHandler::sideOf(tokens, ThemeManager::PaletteHighlight, isDarkMode);
        const QColor selectionFill =
                ThemeTokenHandler::sideOf(tokens, ThemeManager::PacketsSelection, isDarkMode);
        QColor highlight = pinnedHighlight.isValid() ? pinnedHighlight
                         : selectionFill.isValid()   ? selectionFill
                                                     : brandPrimary;
        if (sources)
            sources->insert(ThemeManager::PaletteHighlight,
                QT_TRANSLATE_NOOP("ThemeTokenHandler", "packets.selection when set, else brand.primary"));

        QColor highlightedTextSource =
                ThemeTokenHandler::sideOf(tokens, ThemeManager::PaletteHighlightedText, isDarkMode);
        if (!highlightedTextSource.isValid() && !pinnedHighlight.isValid() && selectionFill.isValid())
            highlightedTextSource =
                    ThemeTokenHandler::sideOf(tokens, ThemeManager::PacketsSelectionText, isDarkMode);
        if (!highlightedTextSource.isValid())
            highlightedTextSource = ColorMath::contrastingText(highlight);
        QColor highlightedText;
        if (ratios.level == ThemeContrast::High) {
            // High contrast: readability wins over the theme's pinned
            // selection.  The text is lifted first; when it cannot reach
            // body-text contrast the highlight gives way, and the link
            // below follows the moved highlight.
            const ColorMath::TextOnFill selection = ColorMath::readableOnFill(
                    highlightedTextSource, highlight, ratios.readableText);
            highlightedText = selection.text;
            highlight = selection.fill;
        } else {
            highlightedText = ColorMath::readableText(highlightedTextSource, highlight, ratios);
        }
        setAllGroups(QPalette::HighlightedText, highlightedText);
        if (sources)
            sources->insert(ThemeManager::PaletteHighlightedText,
                QT_TRANSLATE_NOOP("ThemeTokenHandler", "packets.selectionText when palette.highlight is packets.selection, else black or white on palette.highlight, kept readable on it"));
        setAllGroups(QPalette::Highlight, highlight);
        // Links follow the selection color.  Link text is drawn on Base,
        // so a dark selection color must be lifted until it stays
        // readable there in either scheme.
        setAllGroups(QPalette::Link, ColorMath::readableText(
                pal.color(QPalette::Active, kLinkSourceRole), baseColor, ratios));
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        setAllGroups(QPalette::Accent, brandPrimary);
#endif
    }

    // High contrast: the roles a theme cannot pin are derived from the
    // theme's own colors, so a platform baseline (such as a Windows
    // high-contrast scheme) does not mix its colors into the theme.
    // Buttons and tooltips take the window surface with readable window
    // text, placeholder text is Text faded halfway into Base and lifted
    // to the large-text ratio, and the bevel roles keep the non-text
    // ratio from the window.
    if (ratios.level == ThemeContrast::High) {
        const QColor window     = pal.color(QPalette::Active, QPalette::Window);
        const QColor windowText = pal.color(QPalette::Active, QPalette::WindowText);
        const QColor windowTextReadable = ColorMath::readableText(windowText, window, ratios);
        setAllGroups(QPalette::Button,      window);
        setAllGroups(QPalette::ButtonText,  windowTextReadable);
        setAllGroups(QPalette::ToolTipBase, window);
        setAllGroups(QPalette::ToolTipText, windowTextReadable);
        setAllGroups(QPalette::PlaceholderText, ColorMath::ensureContrast(
                ColorMath::mix(baseColor, pal.color(QPalette::Active, QPalette::Text), 0.5),
                baseColor, ratios.largeText));
        for (QPalette::ColorRole role : { QPalette::Dark, QPalette::Shadow }) {
            setAllGroups(role, ColorMath::ensureContrast(pal.color(QPalette::Active, role),
                                                         window, ratios.nonText));
        }
    }

    return pal;
}
