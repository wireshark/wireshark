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
#include <QEvent>
#include <QList>
#include <QMainWindow>
#include <QOperatingSystemVersion>
#include <QPainter>
#include <QPen>
#include <QRectF>
#include <QStyleOptionToolBar>
#include <QStyleOptionViewItem>
#include <QToolBar>

static QString base_style_name_;

#ifdef Q_OS_MACOS
// The toolbars that make up the unified title and toolbar area of a
// main window: visible, docked, in the top area. The native style
// tests this with a private QMainWindowLayout call.
static QList<QToolBar *> dockedTopToolBars(const QMainWindow *mainWindow)
{
    QList<QToolBar *> result;
    const QList<QToolBar *> toolBars = mainWindow->findChildren<QToolBar *>(Qt::FindDirectChildrenOnly);
    for (QToolBar *toolBar : toolBars) {
        if (toolBar->isVisible() && !toolBar->isFloating()
                && mainWindow->toolBarArea(toolBar) == Qt::TopToolBarArea)
            result.append(toolBar);
    }
    return result;
}

// True if no other unified area toolbar sits below this one, i.e. the
// unified area ends at its bottom. The toolbars' line position is no
// help, since lines that hold only hidden toolbars still count.
static bool isLastTopToolBarRow(const QMainWindow *mainWindow, const QWidget *toolBar)
{
    const int bottom = toolBar->geometry().bottom();
    for (const QToolBar *other : dockedTopToolBars(mainWindow)) {
        if (other != toolBar && other->geometry().top() > bottom)
            return false;
    }
    return true;
}
#endif

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

    // Fusion outlines buttons, combo boxes and line edits with
    // Window.darker(140), about 2:1 on a light window, which misses the
    // non-text contrast a High control boundary needs.  Paint the frame
    // again in FieldBorder on Fusion's own geometry.  Fusion also draws
    // raised or pressed tool buttons through PE_PanelButtonCommand, so a
    // hovered tool button gets the same frame.
    if ((element == PE_PanelButtonCommand || element == PE_FrameLineEdit)
            && option && painter
            && ColorMath::activeRatios().level == ThemeContrast::High
            && baseStyleName() == QLatin1String("fusion")) {
        // QFusionStyle's button and line edit frame geometry (private in
        // qfusionstyle.cpp, no API exposes it): the rect inset by half a
        // pixel with a 2 px corner radius.
        constexpr qreal fusionFrameInset = 0.5;
        constexpr qreal fusionFrameRadius = 2.0;
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(QPen(ThemeManager::instance()->color(ThemeManager::FieldBorder), 1));
        painter->setBrush(Qt::NoBrush);
        painter->drawRoundedRect(
                QRectF(option->rect).adjusted(fusionFrameInset, fusionFrameInset,
                                              -fusionFrameInset, -fusionFrameInset),
                fusionFrameRadius, fusionFrameRadius);
        painter->restore();
    }
}

void ThemeStyler::drawControl(ControlElement element, const QStyleOption *option,
    QPainter *painter, const QWidget *widget) const
{
#ifdef Q_OS_MACOS
    // In the unified title and toolbar area the macOS style fills top
    // toolbars with transparent pixels so the window's native content
    // border shows through, which ignores the application palette. A
    // theme that sets palette.window expects its toolbars in that
    // color, as on the other platforms and in non-unified mode, where
    // the macOS style fills palette.window itself. The check runs at
    // paint time: every theme, mode or contrast switch sets the
    // application style sheet again, which repaints the toolbars, so
    // switching to a theme without palette.window restores the native
    // look.
    if (element == CE_ToolBar && option && painter && widget) {
        const QStyleOptionToolBar *toolBarOption = qstyleoption_cast<const QStyleOptionToolBar *>(option);
        const QMainWindow *mainWindow = qobject_cast<const QMainWindow *>(widget->window());
        ThemeManager *themeManager = ThemeManager::instance();
        if (toolBarOption && toolBarOption->toolBarArea == Qt::TopToolBarArea
                && mainWindow && mainWindow->unifiedTitleAndToolBarOnMac()
                && themeManager->colorIsAvailable(ThemeManager::PaletteWindow)) {
            painter->fillRect(option->rect, option->palette.window());
            if (isLastTopToolBarRow(mainWindow, widget)) {
                // The native separator is one pixel high.
                constexpr int separatorHeight = 1;
                painter->fillRect(QRect(option->rect.left(), option->rect.bottom(),
                                        option->rect.width(), separatorHeight),
                                  themeManager->color(ThemeManager::Separator));
            }
            return;
        }
    }
#endif
    QProxyStyle::drawControl(element, option, painter, widget);
}

void ThemeStyler::polish(QWidget *widget)
{
    QProxyStyle::polish(widget);
#ifdef Q_OS_MACOS
    // Which toolbar row is the last one changes when any toolbar is
    // shown, hidden or moved, but the other toolbars keep their
    // geometry, so Qt does not repaint them. Watch the toolbars to
    // repaint their separator line. Installing the filter again on a
    // repolish does not add a second entry.
    if (qobject_cast<QToolBar *>(widget))
        widget->installEventFilter(this);
#endif
}

void ThemeStyler::unpolish(QWidget *widget)
{
#ifdef Q_OS_MACOS
    if (qobject_cast<QToolBar *>(widget))
        widget->removeEventFilter(this);
#endif
    QProxyStyle::unpolish(widget);
}

bool ThemeStyler::eventFilter(QObject *watched, QEvent *event)
{
#ifdef Q_OS_MACOS
    switch (event->type()) {
    case QEvent::Show:
    case QEvent::Hide:
    case QEvent::Move:
    case QEvent::Resize:
        if (const QToolBar *toolBar = qobject_cast<const QToolBar *>(watched)) {
            // A toolbar shown before the layout has placed it gets a
            // Move or Resize afterwards, which repaints again with the
            // final geometry.
            const QMainWindow *mainWindow = qobject_cast<const QMainWindow *>(toolBar->parentWidget());
            if (mainWindow && mainWindow->unifiedTitleAndToolBarOnMac()) {
                for (QToolBar *other : dockedTopToolBars(mainWindow)) {
                    if (other != toolBar)
                        other->update();
                }
            }
        }
        break;
    default:
        break;
    }
#endif
    return QProxyStyle::eventFilter(watched, event);
}

QString ThemeStyler::buttonStyleSheet(const QString &objectname, const QColor &baseColor)
{
    QString buttonStyle = QStringLiteral(
        "QPushButton#%1%2 { "
        "    background-color: %3; "
        "    color: %4; "
        "}");

    // The label is white in every state.  The fill is darkened until
    // white reads on it, so a pastel dark-mode accent still carries the
    // label; hover and pressed darken further, which only raises the
    // contrast.  contrastingText() is not used: on a fill just at the
    // readable ratio it would pick black, and the label would flip
    // between states.
    const QColor labelColor(Qt::white);
    const QColor fillColor = ColorMath::ensureContrast(baseColor, labelColor,
                                                       ColorMath::activeRatios().readableText);
    const QColor hoverColor = ColorMath::darken(fillColor, 12);
    const QColor pressedColor = ColorMath::darken(fillColor, 20);

    QString resultStyle = buttonStyle.arg(objectname, "", fillColor.name(), labelColor.name());
    resultStyle += buttonStyle.arg(objectname, ":hover", hoverColor.name(), labelColor.name());
    resultStyle += buttonStyle.arg(objectname, ":pressed", pressedColor.name(), labelColor.name());

    return resultStyle;
}
