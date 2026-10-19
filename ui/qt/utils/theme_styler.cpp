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
#include <QOperatingSystemVersion>
#include <QPainter>
#include <QStyleOptionViewItem>

static QString base_style_name_;

ThemeStyler::ThemeStyler(QStyle *style) : QProxyStyle(style)
{
    base_style_name_ = baseStyle()->objectName();
}

ThemeStyler::ThemeStyler(const QString &key) : QProxyStyle(key)
{
    base_style_name_ = baseStyle()->objectName();
}

QString ThemeStyler::baseStyleName()
{
    return base_style_name_;
}

int ThemeStyler::styleHint(StyleHint hint, const QStyleOption *option,
    const QWidget *widget, QStyleHintReturn *returnData) const
{
    if (hint == QStyle::SH_MessageBox_TextInteractionFlags)
            return QProxyStyle::styleHint(hint, option, widget, returnData) | Qt::TextSelectableByMouse;
    return QProxyStyle::styleHint(hint, option, widget, returnData);
}

void ThemeStyler::drawPrimitive(PrimitiveElement element, const QStyleOption *option,
    QPainter *painter, const QWidget *widget) const
{
#ifdef Q_OS_MACOS
    // With the Liquid Glass appearance (macOS 26+ SDK and runtime), the
    // macOS style ignores the position of the indicator rect and draws the
    // check box at the painter origin, so item view check boxes end up
    // outside the item and are invisible. Draw at the origin of a translated
    // painter instead.
    static const bool liquid_glass_os = QOperatingSystemVersion::current().majorVersion() >= 26;
    if (liquid_glass_os && element == PE_IndicatorItemViewItemCheck && option && painter
            && !option->rect.topLeft().isNull()) {
        QStyleOptionViewItem opt;
        if (const QStyleOptionViewItem *vopt = qstyleoption_cast<const QStyleOptionViewItem *>(option))
            opt = *vopt;
        else
            static_cast<QStyleOption &>(opt) = *option;
        opt.rect.moveTopLeft(QPoint(0, 0));

        painter->save();
        painter->translate(option->rect.topLeft());
        QProxyStyle::drawPrimitive(element, &opt, painter, widget);
        painter->restore();
        return;
    }
#endif
    QProxyStyle::drawPrimitive(element, option, painter, widget);
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
    resultStyle += buttonStyle.arg(objectname, ":pressed", pressedColor.name(), ColorMath::contrastingText(pressedColor).name());

    return resultStyle;
}
