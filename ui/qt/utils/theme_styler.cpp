/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/utils/theme_styler.h"

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QColor>
#include <QDebug>

ThemeStyler::ThemeStyler(QStyle *style) : QProxyStyle(style)
{
}

ThemeStyler::ThemeStyler(const QString &key) : QProxyStyle(key)
{
}

int ThemeStyler::styleHint(StyleHint hint, const QStyleOption *option,
    const QWidget *widget, QStyleHintReturn *returnData) const
{
    if (hint == QStyle::SH_MessageBox_TextInteractionFlags)
            return QProxyStyle::styleHint(hint, option, widget, returnData) | Qt::TextSelectableByMouse;
    return QProxyStyle::styleHint(hint, option, widget, returnData);
}

QString ThemeStyler::buttonStyleSheet(const QString &objectname, const QColor &baseColor)
{
    QString buttonStyle = QStringLiteral(
        "QPushButton#%1%2 { "
        "    background-color: %3; "
        "    color: %4; "
        "}");

    QColor hovorColor = ColorMath::darken(baseColor, 12);
    QColor pressedColor = ColorMath::darken(baseColor, 20);

    QString resultStyle = buttonStyle.arg(objectname, "", baseColor.name(), ColorMath::contrastingText(baseColor).name());
    resultStyle += buttonStyle.arg(objectname, ":hover", hovorColor.name(), ColorMath::contrastingText(hovorColor).name());
    resultStyle += buttonStyle.arg(objectname, ":pressed", pressedColor.name(), ColorMath::contrastingText(baseColor).name());

    return resultStyle;
}
