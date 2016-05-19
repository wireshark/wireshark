/* color_utils.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef COLOR_UTILS_H
#define COLOR_UTILS_H

#include <config.h>

#include <glib.h>

#include <epan/color_filters.h>

#include <QBrush>
#include <QColor>
#include <QObject>

class ColorUtils : public QObject
{
    Q_OBJECT
public:
    explicit ColorUtils(QObject *parent = 0);

    static QColor fromColorT(const color_t *color);
    static QColor fromColorT(color_t color);
    static const color_t toColorT(const QColor color);
    static QRgb alphaBlend(const QColor &color1, const QColor &color2, qreal alpha);
    static QRgb alphaBlend(const QBrush &brush1, const QBrush &brush2, qreal alpha);

    // ...because they don't really fit anywhere else?
    static const QColor expert_color_comment;    /* green */
    static const QColor expert_color_chat;       /* light blue */
    static const QColor expert_color_note;       /* bright turquoise */
    static const QColor expert_color_warn;       /* yellow */
    static const QColor expert_color_error;      /* pale red */
    static const QColor expert_color_foreground; /* black */
    static const QColor hidden_proto_item;       /* gray */

    static const QList<QRgb> graphColors();
    static QRgb graphColor(int item);
    static QRgb sequenceColor(int item);

signals:

public slots:

private:
    static QList<QRgb> graph_colors_;
    static QList<QRgb> sequence_colors_;
};

void color_filter_qt_add_cb(color_filter_t *colorf, gpointer user_data);

#endif // COLOR_UTILS_H

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
