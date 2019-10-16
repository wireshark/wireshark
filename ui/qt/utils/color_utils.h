/* color_utils.h
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

    /** Checks if our application is in "dark mode".
     * Dark mode is determined by comparing the application palette's window
     * text color with the window color.
     *
     * @return true if we're running in dark mode, false otherwise.
     */
    static bool themeIsDark();
    static QBrush themeLinkBrush();
    static QString themeLinkStyle();

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
