/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEMED_ICON_H
#define THEMED_ICON_H

#include <ui/qt/utils/theme_manager.h>

#include <QIcon>
#include <QSize>
#include <QString>

/**
 * @brief A QIcon that renders an SVG silhouette recoloured to a ThemeManager
 *        token, tracking light/dark and theme changes automatically.
 *
 * Companion to StockIcon.  StockIcon selects a pre-made, per-mode raster
 * resource; ThemedIcon renders one SVG and tints it to a live theme colour, so
 * a single asset follows the active theme without per-mode variants.  The tint
 * uses CompositionMode_SourceIn, which flattens the rendered shape to the
 * resolved colour — the source SVG's own colours (even gradients) don't matter,
 * only its alpha silhouette.
 *
 * It is part of the theme system and deliberately speaks ThemeManager tokens
 * only: there are no QColor or QPalette overloads.  Use a palette token
 * (e.g. ThemeManager::PaletteText) for monochrome glyphs that should follow the
 * text colour, or an accent token (e.g. ThemeManager::AccentSuccess) for a
 * functional colour.
 *
 * Theme tracking needs no caller code: the backing engine resolves the token
 * colour at paint time and keys its pixmap cache on that colour, so a theme or
 * light/dark flip is a natural cache miss and re-renders on the next repaint.
 */
class ThemedIcon : public QIcon
{
public:
    /**
     * @param svg_resource_path Qt resource path of the SVG, e.g.
     *        ":/svg_icons/x-filter-clear.svg".
     * @param token Theme colour token the glyph is tinted to.
     * @param size  Nominal render size used when a caller requests a null size.
     */
    explicit ThemedIcon(const QString &svg_resource_path,
                        ThemeManager::ThemeToken token,
                        QSize size = QSize(14, 14));
};

#endif // THEMED_ICON_H
