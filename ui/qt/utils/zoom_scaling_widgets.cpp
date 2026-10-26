/* zoom_scaling_widgets.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <ui/qt/utils/zoom_scaling.h>
#include <ui/qt/utils/font_manager.h>

#include <QLayout>
#include <QMargins>
#include <QSize>
#include <QVariant>
#include <QWidget>

#ifdef Q_OS_MACOS
#include <QComboBox>
#include <QFont>
#endif

// Zoom level 0 side in pixels of the display filter toolbar and status bar
// icons.  The main window .ui files carry the same value as their Designer
// default, which the code overwrites at startup.
static const int bar_icon_base_size = 14;

// Dynamic properties holding a widget's zoom level 0 size limits, set by
// ZoomScaling::scaleSizeLimits(), and the same for the icon size, the layout
// margins and the layout spacing.
static const char design_min_size_property[] = "_ws_design_min_size";
static const char design_max_size_property[] = "_ws_design_max_size";
static const char design_icon_size_property[] = "_ws_design_icon_size";
static const char design_margins_property[] = "_ws_design_margins";
static const char design_spacing_property[] = "_ws_design_spacing";

// Applies the stored design size limits of @p widget at the current zoom
// level.  The maximum is set first: setMaximumSize() shrinks the widget to
// the new maximum, then setMinimumSize() grows it to the new minimum, and the
// scaled minimum never exceeds the scaled maximum.
static void applyScaledSizeLimits(QWidget *widget)
{
    const QSize design_min = widget->property(design_min_size_property).toSize();
    const QSize design_max = widget->property(design_max_size_property).toSize();

    widget->setMaximumSize(ZoomScaling::scaledSizeLimit(design_max.width()),
                           ZoomScaling::scaledSizeLimit(design_max.height()));
    widget->setMinimumSize(ZoomScaling::scaledSizeLimit(design_min.width()),
                           ZoomScaling::scaledSizeLimit(design_min.height()));
}

// Applies the stored design icon size of @p widget at the current zoom level.
static void applyScaledIconSize(QWidget *widget)
{
    const QSize design = widget->property(design_icon_size_property).toSize();
    widget->setProperty("iconSize", QSize(ZoomScaling::scaledPixels(design.width()),
                                          ZoomScaling::scaledPixels(design.height())));
}

// Applies the stored design margins and spacing of @p layout at the current
// zoom level.  A negative spacing (the style default) stays negative.
static void applyScaledLayoutMetrics(QLayout *layout)
{
    const QMargins design = layout->property(design_margins_property).value<QMargins>();
    layout->setContentsMargins(ZoomScaling::scaledPixels(design.left()),
                               ZoomScaling::scaledPixels(design.top()),
                               ZoomScaling::scaledPixels(design.right()),
                               ZoomScaling::scaledPixels(design.bottom()));
    const int spacing = layout->property(design_spacing_property).toInt();
    if (spacing >= 0)
        layout->setSpacing(ZoomScaling::scaledPixels(spacing));
}

#ifdef Q_OS_MACOS
// Marks a widget whose macOS control size follows the zoom level, set by
// ZoomScaling::scaleMacControlSize().
static const char mac_control_size_property[] = "_ws_mac_control_size";

// Applies the macOS control size of the current zoom level to @p widget.
static void applyMacControlSize(QWidget *widget)
{
    // The small control size suits the small font up to zoom level 0.
    // Above it the regular size keeps the native controls, whose heights
    // do not depend on the font, in step with the zoomed text.  The
    // regular size is set explicitly: with no size attribute, QMacStyle
    // guesses the size from the widget geometry.  Setting a size attribute
    // also re-resolves the font of a widget without an explicit font, so
    // it picks up the matching small or regular application font.
    const Qt::WidgetAttribute size = FontManager::zoomFactor() > 1.0 ? Qt::WA_MacNormalSize
                                                                     : Qt::WA_MacSmallSize;
    if (!widget->testAttribute(size)) {
        widget->setAttribute(size, true);
    }

    // QComboBox answers every control size change with an explicit font
    // at the platform size of that control size.  An explicit font does
    // not follow the zoomed application fonts, so drop it and let the
    // combo use the zoomed class font like the widgets next to it.
    if (qobject_cast<QComboBox *>(widget)) {
        widget->setFont(QFont());
    }
}
#endif // Q_OS_MACOS

int ZoomScaling::scaledPixels(int px)
{
    return scaledPixels(px, FontManager::zoomFactor());
}

int ZoomScaling::scaledSizeLimit(int design)
{
    return scaledSizeLimit(design, FontManager::zoomFactor());
}

void ZoomScaling::scaleSizeLimits(QWidget *widget)
{
    if (!widget)
        return;

    // Store the design values on the first call only, so a repeated call
    // does not capture zoomed values.
    if (!widget->property(design_min_size_property).isValid()) {
        widget->setProperty(design_min_size_property, widget->minimumSize());
        widget->setProperty(design_max_size_property, widget->maximumSize());
        QObject::connect(FontManager::instance(), &FontManager::zoomChanged, widget, [widget]() { applyScaledSizeLimits(widget); });
    }
    applyScaledSizeLimits(widget);
}

void ZoomScaling::scaleIconSize(QWidget *widget)
{
    if (!widget || !widget->property("iconSize").isValid())
        return;

    if (!widget->property(design_icon_size_property).isValid()) {
        widget->setProperty(design_icon_size_property, widget->property("iconSize"));
        QObject::connect(FontManager::instance(), &FontManager::zoomChanged, widget, [widget]() { applyScaledIconSize(widget); });
    }
    applyScaledIconSize(widget);
}

void ZoomScaling::scaleLayoutMetrics(QLayout *layout)
{
    if (!layout)
        return;

    if (!layout->property(design_margins_property).isValid()) {
        layout->setProperty(design_margins_property, QVariant::fromValue(layout->contentsMargins()));
        layout->setProperty(design_spacing_property, layout->spacing());
        QObject::connect(FontManager::instance(), &FontManager::zoomChanged, layout, [layout]() { applyScaledLayoutMetrics(layout); });
    }
    applyScaledLayoutMetrics(layout);
}

int ZoomScaling::barIconSize()
{
    return scaledPixels(bar_icon_base_size);
}

#ifdef Q_OS_MACOS
void ZoomScaling::scaleMacControlSize(QWidget *widget)
{
    if (!widget)
        return;

    if (!widget->property(mac_control_size_property).isValid()) {
        widget->setProperty(mac_control_size_property, true);
        QObject::connect(FontManager::instance(), &FontManager::zoomChanged, widget, [widget]() { applyMacControlSize(widget); });
    }
    applyMacControlSize(widget);
}

void ZoomScaling::scaleMacControlSizes(QWidget *parent)
{
    if (!parent)
        return;

    const QList<QWidget *> children = parent->findChildren<QWidget *>();
    for (QWidget *child : children) {
        scaleMacControlSize(child);
    }
}
#endif // Q_OS_MACOS
