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
     * Load `:/stylesheets/<name>.qss` and return its contents with:
     *
     *   - every `wstheme(RoleName)` token replaced by the resolved
     *     `#rrggbb` hex of the corresponding ThemeToken, picked from
     *     `tokens` using `isDarkMode` to choose the light/dark side;
     *   - every literal `%wsmode%` occurrence replaced by the string
     *     `"dark"` or `"light"` — intended for picking mode-specific
     *     asset filenames inside `image: url(...)` rules, e.g.
     *       image: url(:/stock_icons/14x14/x-filter-dropdown.%wsmode%.png);
     *     The `%wsmode%` placeholder takes no arguments and is a plain
     *     text substitution; it runs before the `wstheme(...)`
     *     regex pass.
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
};

#endif /* THEME_STYLESHEET_LOADER_H */
