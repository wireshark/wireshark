/* native_title_bar_common.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Platform-neutral part of NativeTitleBar: which windows get a title bar
 * style, which style, and when it is applied.  The native call is in the
 * per-platform backend.
 */

#include "ui/qt/utils/themes/native_title_bar.h"

#include "ui/qt/utils/theme_manager.h"
#include "ui/qt/utils/themes/color_math.h"

#include <QApplication>
#include <QEvent>
#include <QPalette>
#include <QTimer>
#include <QWidget>

namespace {

// Set on a window while its title bar carries a theme color, so that a
// reset only touches windows whose title bar was changed here.
const char *const tintedProperty = "_ws_title_bar_tinted";

} // namespace

NativeTitleBar::NativeTitleBar(QObject *parent)
    : QObject(parent)
{
    qApp->installEventFilter(this);
}

void NativeTitleBar::applyToAll()
{
    const Style style = currentStyle();
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        // Windows without a native window yet get their style on Show;
        // asking for a winId() here would create one.
        if (widget->testAttribute(Qt::WA_WState_Created) && hasTitleBar(widget))
            applyTo(widget, style);
    }
}

bool NativeTitleBar::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::Show && watched->isWidgetType()) {
        QWidget *widget = static_cast<QWidget *>(watched);
        if (widget->isWindow() && widget->testAttribute(Qt::WA_WState_Created)
                && hasTitleBar(widget))
            applyTo(widget, currentStyle());
    }
    return QObject::eventFilter(watched, event);
}

NativeTitleBar::Style NativeTitleBar::styleFor(bool tinted, const QColor &window,
                                               const QColor &windowText)
{
    Style style;
    if (!tinted || !window.isValid())
        return style;

    style.background = window;
    style.text = ColorMath::readableText(windowText, window);
    style.darkBackground = ColorMath::isDark(window);
    return style;
}

NativeTitleBar::Style NativeTitleBar::currentStyle()
{
    // Only a theme that declares its own window color paints the title bar,
    // and only where the platform lets us color it.  The applied palette is
    // what the window body and its toolbars paint, so the title bar uses the
    // same color and reads as one surface.
    const QPalette palette = QApplication::palette();
    const bool tinted = ThemeManager::instance()->colorIsAvailable(ThemeManager::PaletteWindow)
            && isSupported();
    Style style = styleFor(tinted,
                           palette.color(QPalette::Active, QPalette::Window),
                           palette.color(QPalette::Active, QPalette::WindowText));
    style.appDark = ThemeManager::isDark();
    return style;
}

NativeTitleBar::Style NativeTitleBar::previewStyle(bool declaresWindow, const QColor &window,
                                                   const QColor &windowText)
{
    // No isSupported() here: the preview shows the theme, and the real
    // title bar on Linux or Windows 10 is the platform's business.
    return styleFor(declaresWindow, window, windowText);
}

bool NativeTitleBar::hasTitleBar(const QWidget *widget)
{
    if (widget->windowFlags().testFlag(Qt::FramelessWindowHint))
        return false;
    // Translucency does not rule a window out: Qt makes a macOS main window
    // with unifiedTitleAndToolBarOnMac translucent, and it still has a title
    // bar.  For a framed translucent window Qt keeps the native window
    // background, which is what the backend colors.
    // Popups, tool tips, splash screens, sheets and drawers have no title bar.
    switch (widget->windowType()) {
    case Qt::Window:
    case Qt::Dialog:
    case Qt::Tool:
        return true;
    default:
        return false;
    }
}

void NativeTitleBar::applyTo(QWidget *window, const Style &style)
{
    // Native title bar wanted and never changed: leave the window alone.
    if (!style.background.isValid() && !window->property(tintedProperty).toBool())
        return;

    if (applyAndMark(window, style))
        return;

    // The platform window can lag behind the widget's Show; try once more
    // after the event loop has finished showing it.  A theme change in the
    // meantime re-applies through applyToAll().
    QTimer::singleShot(0, window, [window, style]() {
        applyAndMark(window, style);
    });
}

bool NativeTitleBar::applyAndMark(QWidget *window, const Style &style)
{
    if (!applyNative(window, style))
        return false;
    window->setProperty(tintedProperty, style.background.isValid());
    return true;
}
