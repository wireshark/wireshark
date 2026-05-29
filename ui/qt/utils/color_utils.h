/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLOR_UTILS_H
#define COLOR_UTILS_H

#include <config.h>

#include <epan/color_filters.h>

#include <QBrush>
#include <QColor>
#include <QObject>

/**
 * @brief Utility class providing color conversion, blending, and theme-aware UI color definitions.
 */
class ColorUtils : public QObject
{
public:
    /**
     * @brief Constructs a new ColorUtils object.
     * @param parent The parent QObject, defaults to 0.
     */
    explicit ColorUtils(QObject *parent = 0);

    /**
     * @brief Converts a core color_t pointer to a QColor.
     * @param color Pointer to the core color_t structure.
     * @return The corresponding QColor.
     */
    static QColor fromColorT(const color_t *color);

    /**
     * @brief Converts a core color_t value to a QColor.
     * @param color The core color_t structure.
     * @return The corresponding QColor.
     */
    static QColor fromColorT(color_t color);

    /**
     * @brief Converts a QColor to a core color_t.
     * @param color The QColor to convert.
     * @return The corresponding core color_t structure.
     */
    static const color_t toColorT(const QColor color);

    /**
     * @brief Blends two colors together using the specified alpha factor.
     * @param color1 The first color.
     * @param color2 The second color.
     * @param alpha The alpha blending factor.
     * @return The blended color as a QRgb value.
     */
    static QRgb alphaBlend(const QColor &color1, const QColor &color2, qreal alpha);

    /**
     * @brief Blends the colors of two brushes together using the specified alpha factor.
     * @param brush1 The first brush.
     * @param brush2 The second brush.
     * @param alpha The alpha blending factor.
     * @return The blended color as a QRgb value.
     */
    static QRgb alphaBlend(const QBrush &brush1, const QBrush &brush2, qreal alpha);


    /**
     * @brief Returns an appropriate link color for the current mode.
     * @return A brush suitable for setting a text color.
     */
    static QBrush themeLinkBrush();

    /**
     * @brief Returns an appropriate HTML+CSS link style for the current mode.
     * @return A "<style>a:link { color: ... ; }</style>" string
     */
    static QString themeLinkStyle();


    /**
     * @brief Returns an appropriate background color for hovered abstract items.
     * @return The background color.
     */
    static const QColor hoverBackground();

    /**
     * @brief Returns an appropriate warning background color for the current mode.
     * @return The background color.
     */
    static const QColor warningBackground();

    /**
     * @brief Returns an appropriate foreground color for disabled text.
     * @return The foreground color.
     */
    static const QColor disabledForeground();

private:
    /** Internal list of cached graph colors. */
    static QList<QRgb> graph_colors_;

    /** Internal list of cached sequence diagram colors. */
    static QList<QRgb> sequence_colors_;
};

/**
 * @brief Adds a color filter callback to the specified color filter.
 *
 * @param colorf Pointer to the color filter structure.
 * @param user_data User data to be passed to the callback function.
 */
void color_filter_qt_add_cb(color_filter_t *colorf, void *user_data);

#endif // COLOR_UTILS_H
