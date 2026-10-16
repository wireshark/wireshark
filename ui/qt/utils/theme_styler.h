/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_STYLER_H
#define THEME_STYLER_H

#include <QProxyStyle>

class ThemeStyler : public QProxyStyle {
    Q_OBJECT
public:
    ThemeStyler(QStyle *style = nullptr);
    ThemeStyler(const QString &key);

    int styleHint(StyleHint hint, const QStyleOption *option = nullptr,
        const QWidget *widget = nullptr, QStyleHintReturn *returnData = nullptr) const override;

    void drawPrimitive(PrimitiveElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override;

    // The object name of the underlying (native) style, e.g. "windows11",
    // "windowsvista", "fusion", or "macos". QApplication::style() returns
    // either this proxy or a QStyleSheetStyle wrapping it, neither of which
    // has a useful objectName().
    static QString baseStyleName();

    static QString buttonStyleSheet(const QString &objectname, const QColor &baseColor);
};


#endif /* THEME_STYLER_H */
