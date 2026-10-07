/* stock_icon_tool_button.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/stock_icon_tool_button.h>

#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/themed_icon.h>

#include <QApplication>
#include <QEvent>
#include <QMenu>
#include <QMouseEvent>

// We want nice icons that render correctly, and that are responsive
// when the user hovers and clicks them.
// Using setIcon renders correctly on normal and retina displays. It is
// not completely responsive, particularly on macOS.
// Calling setStyleSheet is responsive, but does not render correctly on
// retina displays: https://bugreports.qt.io/browse/QTBUG-36825
// Subclass QToolButton, which lets us catch events and set icons as needed.

StockIconToolButton::StockIconToolButton(QWidget * parent, QString icon_name) :
    QToolButton(parent)
{
    setCursor(Qt::ArrowCursor);
    setIconByName(icon_name);
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, [this]() { setIconByName(); });
}

void StockIconToolButton::setIconByName(QString icon_name)
{
    if (!icon_name.isEmpty()) {
        icon_name_ = icon_name;
    }
    if (icon_name_.isEmpty()) {
        return;
    }
    base_icon_ = ThemedIcon(icon_name_);
    setIcon(base_icon_);
}

bool StockIconToolButton::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        setIconByName();
        break;
    default:
        break;
    }

    return QToolButton::event(event);
}
