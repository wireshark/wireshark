/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <ui/qt/utils/theme_manager.h>

#include <QColor>
#include <QIcon>
#include <QPalette>
#include <QString>

/**
 * @brief A QIcon that paints a filled shape (square, circle, triangle or cross)
 *        on demand, at whatever size and device-pixel ratio Qt asks for.
 *
 * Meant for colour legends and colour pickers: the fill carries the data
 * colour (a graph series, a colouring rule), the outline separates it from the
 * surface it sits on.  The fill is either a fixed colour or an entry of the
 * theme's graph palette; the outline is either a fixed colour or a
 * ThemeManager token.  Palette entries and tokens are resolved on every paint,
 * so the icon follows theme and light/dark changes the way ThemedIcon does,
 * and a legend icon keeps matching a plot series drawn with the same palette
 * index.
 *
 * The given outline colour is a starting point.  Where it is too close to the
 * fill (a black outline on a dark series colour, a white one on a pale series
 * colour) it is moved until it reaches ColorMath::NonTextRatio against
 * the fill; a glyph is lifted to ColorMath::ReadableTextRatio.  Colours that
 * already contrast enough are drawn as given.
 *
 * Nothing is rasterised ahead of time.  paint() draws vectors with the caller's
 * painter; pixmap requests render into a transparent pixmap of the requested
 * size times the device-pixel ratio.  QIcon::Disabled draws the shape in grey
 * and dims it to the same opacity as the other theme icons.
 */
class ThemedShapeIcon : public QIcon
{
public:
    enum Shape {
        Square,     /**< Filled square; the shape normally given a glyph. */
        Circle,     /**< Filled circle. */
        Triangle,   /**< Filled, pointing up. */
        Cross       /**< Diagonal cross, drawn as a filled band. */
    };

    /**
     * @brief Entry @p index of the theme's graph palette, see
     *        ThemeManager::graphColor().  Resolved on every paint.
     *
     * A type of its own rather than a plain int: ThemeManager::ThemeToken is
     * an unscoped enum and would convert to an index without any warning.
     */
    struct PaletteColor {
        int index;  /**< Palette index, non-negative; wraps around the palette. */
    };

    /**
     * @param shape   Shape to draw.
     * @param fill    Fill colour; its alpha is respected.
     * @param outline Base outline and glyph colour, adapted to the fill where
     *                it lacks contrast; its alpha is respected otherwise.
     * @param glyph   Optional short text (e.g. a number), centred.
     */
    ThemedShapeIcon(Shape shape, const QColor &fill, const QColor &outline,
                    const QString &glyph = QString());

    /**
     * @brief Theme-tracking variant: @p outline_token is resolved on every
     *        paint, e.g. ThemeManager::PaletteText.
     */
    ThemedShapeIcon(Shape shape, const QColor &fill,
                    ThemeManager::ThemeToken outline_token,
                    const QString &glyph = QString());

    /**
     * @brief Legend variant: fill and outline are both resolved on every
     *        paint, so the icon tracks a plot series that uses
     *        ThemeManager::graphColor(@p fill.index).
     */
    ThemedShapeIcon(Shape shape, PaletteColor fill,
                    ThemeManager::ThemeToken outline_token);

    /**
     * A palette role is not a colour.  Without this, an unscoped
     * QPalette::ColorRole would convert to QRgb and then to a nearly
     * transparent QColor without any warning.
     */
    ThemedShapeIcon(Shape, const QColor &, QPalette::ColorRole,
                    const QString & = QString()) = delete;
};
