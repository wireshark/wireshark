/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_STYLESHEET_LOADER_H
#define THEME_STYLESHEET_LOADER_H

#include <ui/qt/utils/theme_manager.h>

#include <QHash>
#include <QPalette>
#include <QString>

/**
 * Loads a QSS stylesheet from the built-in `:/stylesheets/` resource
 * tree and resolves every `wstheme(RoleName)` token by looking up
 * RoleName in the current theme's color map.
 *
 * Split out of ThemeManager so the loader logic — stylesheet path
 * sanitization, QSS read, token regex, role-enum lookup — lives
 * alongside the other theme helpers under `ui/qt/utils/themes/`.
 *
 * Stateless: every call reads fresh resource contents and resolves
 * tokens against the token map the caller provides.  ThemeManager is
 * the usual caller and passes its own `themeColors_` / `isDarkMode()`.
 */
class ThemeStyleSheetLoader
{
public:
    using TokenMap = QHash<ThemeManager::ThemeToken, ThemeColorPair>;

    /**
     * Load `:/stylesheets/<name>.qss` and return its contents with
     * every `wstheme(RoleName)` token replaced by the resolved
     * `#rrggbb` hex of the corresponding ThemeToken, picked from
     * `tokens` using `isDarkMode` to choose the light/dark side.
     *
     * Returns an empty QString on any of:
     *   - `name` is empty or contains illegal characters / path
     *     traversal attempts (`..`, leading `/`, leading `.`,
     *     backslash, etc.)
     *   - The resource file cannot be opened.
     *
     * Tokens that don't resolve (unknown role name or missing color
     * in the map) are **stripped** from the output and a `qWarning`
     * is emitted — Qt's QSS parser is all-or-nothing per object, so
     * leaving a literal `wstheme(Foo)` in place would silently drop
     * the entire rule on the first typo; stripping keeps the rest
     * of the rules valid and the warning surfaces the typo.
     *
     * @param name       Logical name under :/stylesheets/, without
     *                   extension (e.g. "widgets/learn-card").
     * @param tokens     Current theme's color map.
     * @param isDarkMode Which side of color pairs to select.
     */
    static QString load(const QString  &name,
                        const TokenMap &tokens,
                        bool            isDarkMode);

    /**
     * Replaces every `palette(<role>)` in @p sheet with @p palette's Active color
     * for that role.  Qt resolves palette() in style sheets against the
     * application palette, not the widget's, so a sheet previewing another
     * palette resolves the references itself.  Role names are the ones Qt's
     * style sheet grammar accepts, derived from QPalette::ColorRole.  A name
     * that matches no role is left as written (Qt ignores it on the live page
     * too) and logged with qWarning once per name.
     *
     * @param sheet   Style sheet text.
     * @param palette Palette whose Active colors are substituted.
     * @return The sheet with the palette() references resolved.
     */
    static QString resolvePaletteRoles(const QString &sheet, const QPalette &palette);
};

#endif /* THEME_STYLESHEET_LOADER_H */
