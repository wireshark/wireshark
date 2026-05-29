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

#include <QHash>
#include <QPalette>
#include <QString>

/**
 * Builds the `QApplication::palette()` from the current theme's token
 * map and mode, and pushes it via `QApplication::setPalette()`.
 *
 * The baseline palette comes from:
 *
 *   - macOS (any supported Qt) and Windows on Qt ≥ 6.8: a caller-
 *     supplied `osBaseline` snapshot.  ThemeManager captures this from
 *     the platform style at construction time (when the palette is
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
 * `theme.jsonc`) are applied on top of the baseline.  Brand-driven
 * roles (`Highlight`, `Link`, `Accent`, `HighlightedText`) are always
 * overlaid last, so themes don't need to set them.
 */
class ThemePaletteBuilder
{
public:
    using TokenMap = QHash<ThemeManager::ThemeToken, ThemeColorPair>;

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
     */
    static QPalette build(const TokenMap                                     &tokens,
                          bool                                                isDarkMode,
                          const QHash<QString, ThemeManager::ThemeToken>     &tokenNameCache,
                          const QHash<QString, QPalette::ColorRole>          &paletteRoleCache,
                          const QPalette                                     &osBaseline);

    /**
     * Convenience wrapper: calls build() and pushes the result via
     * `QApplication::setPalette()`.
     */
    static void apply(const TokenMap                                     &tokens,
                      bool                                                isDarkMode,
                      const QHash<QString, ThemeManager::ThemeToken>     &tokenNameCache,
                      const QHash<QString, QPalette::ColorRole>          &paletteRoleCache,
                      const QPalette                                     &osBaseline);

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
