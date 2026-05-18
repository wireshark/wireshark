/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STOCK_ICON_H
#define STOCK_ICON_H

#include <QIcon>

/** @file
 *  Goal: Beautiful icons appropriate for each of our supported platforms.
 */

// Supported standard names:
// document-open

// Supported custom names (see images/toolbar):
// x-capture-file-close
// x-capture-file-save
// x-lua-debug-continue
// x-lua-debug-step-in
// x-lua-debug-step-out
// x-lua-debug-step-over
// x-lua-debug-run-to-line

/**
 * @brief QIcon subclass that loads a named application icon from theme
 *        resources, with fallback handling across platforms, plus factory
 *        methods for generating solid-colour shape icons at runtime.
 */
class StockIcon : public QIcon
{
public:
    /**
     * @brief Constructs a StockIcon by resolving @p icon_name against the
     *        application's icon theme and resource paths.
     * @param icon_name Canonical icon name (e.g. "x-capture-file-close").
     */
    explicit StockIcon(const QString icon_name);

    /**
     * @brief Creates a square icon filled with @p bg_color, optionally
     *        overlaying @p glyph in @p fg_color.
     * @param bg_color Background fill colour (ARGB).
     * @param fg_color Foreground/glyph colour (ARGB).
     * @param glyph    Optional single-character string to render centred on the icon.
     * @return Generated QIcon.
     */
    static QIcon colorIcon(const QRgb bg_color, const QRgb fg_color, const QString glyph = QString());

    /**
     * @brief Creates a square icon containing a filled triangle in @p fg_color
     *        on a @p bg_color background.
     * @param bg_color Background fill colour (ARGB).
     * @param fg_color Triangle fill colour (ARGB).
     * @return Generated QIcon.
     */
    static QIcon colorIconTriangle(const QRgb bg_color, const QRgb fg_color);

    /**
     * @brief Creates a square icon containing a filled cross (×) in @p fg_color
     *        on a @p bg_color background.
     * @param bg_color Background fill colour (ARGB).
     * @param fg_color Cross fill colour (ARGB).
     * @return Generated QIcon.
     */
    static QIcon colorIconCross(const QRgb bg_color, const QRgb fg_color);

    /**
     * @brief Creates a square icon containing a filled circle in @p fg_color
     *        on a @p bg_color background.
     * @param bg_color Background fill colour (ARGB).
     * @param fg_color Circle fill colour (ARGB).
     * @return Generated QIcon.
     */
    static QIcon colorIconCircle(const QRgb bg_color, const QRgb fg_color);

private:
    /**
     * @brief Populates the internal icon-name-to-resource-path map used when
     *        resolving icon names that are not available from the system theme.
     */
    void fillIconNameMap();
};

#endif // STOCK_ICON_H
