/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_PALETTE_BUILDER_H
#define THEME_PALETTE_BUILDER_H

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QHash>
#include <QPalette>
#include <QString>

/**
 * Builds the application palette from the current theme's token map and
 * mode; ThemeManager pushes it via `QApplication::setPalette()`.
 *
 * The baseline palette comes from:
 *
 *   - macOS (any supported Qt) and Windows on Qt ≥ 6.8: a caller-
 *     supplied `osBaseline` snapshot.  ThemeManager captures the
 *     platform palette at construction time (when the palette is
 *     pristine) and refreshes it whenever the effective scheme flips.
 *     Reading `QApplication::palette()` here would be wrong: once the
 *     builder has pushed any palette via `setPalette()`, subsequent
 *     reads return that customized palette — so consecutive theme
 *     switches would accumulate overrides instead of restarting from a
 *     clean OS baseline.
 *   - Linux (any Qt) and Windows on Qt < 6.8: our own **built-in
 *     light or dark palette** (see `builtInLightPalette()` /
 *     `builtInDarkPalette()`).  The Linux platform themes
 *     (gnome/gtk3/qt6ct) silently ignore `QStyleHints::setColorScheme()`
 *     and pin both the hint and `standardPalette()` to the OS value,
 *     which makes "Dark mode on a Light OS" (or vice versa)
 *     impossible to honor without supplying our own palette.  Old
 *     Fusion has the same problem.  `osBaseline` is ignored on these
 *     platforms.
 *
 * Theme-provided palette overrides (the `palette:` section of
 * `theme.jsonc`) are applied on top of the baseline.  The selection
 * roles (`Highlight`, `HighlightedText`, `Link`) and `Accent` are
 * overlaid last, so themes don't need to set them: Highlight resolves to
 * `palette.highlight`, else `packets.selection`, else `brand.primary`;
 * HighlightedText is derived from it unless pinned; Link follows it;
 * Accent is `brand.primary`.
 */
class ThemePaletteBuilder
{
public:
    using TokenMap = QHash<ThemeManager::ThemeToken, ThemeColorPair>;

    /**
     * The palette role the Link role is derived from in build().  Code that
     * traces a link color back to a theme token starts from this role.
     */
    static constexpr QPalette::ColorRole kLinkSourceRole = QPalette::Highlight;

    /**
     * Build and return the full QPalette from the token map without
     * pushing it to QApplication.  Callers that need the palette value
     * before it is applied (e.g. to derive tokens first) should call
     * this and then push the result themselves via
     * `QApplication::setPalette()`.
     *
     * @param tokens            Populated theme token map (brand,
     *                          accent, optional palette overrides).
     * @param isDarkMode        Which side of color pairs to use.
     * @param tokenNameCache    Map "palettewindow" → ThemeToken::PaletteWindow
     *                          (etc.), shared with the parser/QSS loader.
     * @param paletteRoleCache  Map "palettewindow" → QPalette::Window
     *                          (etc.) — Qt's 21 palette-role keys by
     *                          lowercased enumerator name.
     * @param osBaseline        Pristine OS palette snapshot supplied by
     *                          ThemeManager; used as the baseline on
     *                          macOS and Windows Qt ≥ 6.8.  Ignored on
     *                          Linux and Windows Qt < 6.8.
     * @param ratios            The contrast ratio set derived roles
     *                          (HighlightedText, Link) are lifted to.
     * @param sources           When not null, receives the rule text (untranslated,
     *                          QT_TRANSLATE_NOOP in the "ThemeTokenHandler" context)
     *                          of the roles build() resolves itself, Highlight and
     *                          HighlightedText, while brand.primary is declared.
     *                          Same type as ThemeTokenHandler::SourceMap.
     */
    static QPalette build(const TokenMap                                     &tokens,
                          bool                                                isDarkMode,
                          const QHash<QString, ThemeManager::ThemeToken>     &tokenNameCache,
                          const QHash<QString, QPalette::ColorRole>          &paletteRoleCache,
                          const QPalette                                     &osBaseline,
                          const ColorMath::ContrastRatios                    &ratios,
                          QHash<ThemeManager::ThemeToken, const char *>      *sources = nullptr);

    /**
     * Built-in dark QPalette used as the baseline on non-macOS
     * platforms when the current mode is dark.  Based on
     * https://gist.github.com/QuantumCD/6245215 with Disabled-group
     * coverage added.
     */
    static QPalette builtInDarkPalette();

    /**
     * Built-in light QPalette used as the baseline on non-macOS
     * platforms when the current mode is light.  Mirrors Qt Fusion's
     * default light palette so the visual identity stays familiar
     * when our override replaces the system's.
     */
    static QPalette builtInLightPalette();
};

#endif /* THEME_PALETTE_BUILDER_H */
