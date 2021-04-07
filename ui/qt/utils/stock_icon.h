/* stock_icon.h
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

class StockIcon : public QIcon
{
public:
    explicit StockIcon(const QString icon_name);

    static QIcon colorIcon(const QRgb bg_color, const QRgb fg_color, const QString glyph = QString());
    static QIcon colorIconTriangle(const QRgb bg_color, const QRgb fg_color);
    static QIcon colorIconCross(const QRgb bg_color, const QRgb fg_color);
    static QIcon colorIconCircle(const QRgb bg_color, const QRgb fg_color);

private:
    void fillIconNameMap();
};

#endif // STOCK_ICON_H
