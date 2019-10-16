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

private:
    void fillIconNameMap();
};

#endif // STOCK_ICON_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
