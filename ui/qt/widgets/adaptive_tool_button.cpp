/* adaptive_tool_button.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/adaptive_tool_button.h>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/zoom_scaling.h>

#include <QStyle>

AdaptiveToolButton::AdaptiveToolButton(QWidget *parent) :
    QToolButton(parent)
{
    // Icon-only, non-focusable inline affordance (not a standalone toolbar
    // button). The flat look — no frame or fill — is applied globally via the
    // AdaptiveToolButton rule in application.qss, not here.
    setAutoRaise(true);
    setToolButtonStyle(Qt::ToolButtonIconOnly);
    setFocusPolicy(Qt::NoFocus);
    setCursor(Qt::PointingHandCursor);

    // Match the compact macOS control-size class used by the app's other inline
    // tool buttons. Must precede the metric queries below and in applyZoom():
    // the macOS style folds the control-size class into the values it reports
    // for this widget, so querying first would capture the larger regular-size
    // value.
#ifdef Q_OS_MACOS
    setAttribute(Qt::WA_MacSmallSize, true);
#endif

    // Default padding is the style's frame width (a crisp hairline that stays
    // stable across platforms); callers may override via setIconPadding().
    icon_padding_ = style()->pixelMetric(QStyle::PM_DefaultFrameWidth, nullptr, this);

    // Track the application zoom so the glyph grows/shrinks with the text.
    connect(FontManager::instance(), &FontManager::zoomChanged,
            this, &AdaptiveToolButton::applyZoom);

    applyZoom();
}

void AdaptiveToolButton::setBaseIconSize(const QSize &size)
{
    if (base_icon_size_ == size)
        return;
    base_icon_size_ = size;
    applyZoom();
}

void AdaptiveToolButton::setIconPadding(int padding)
{
    if (icon_padding_ == padding)
        return;
    icon_padding_ = padding;
    updateGeometry();
}

QSize AdaptiveToolButton::sizeHint() const
{
    // Tight: the effective (zoom-scaled) icon plus symmetric padding, ignoring
    // the style's own button margins so the box hugs the glyph.
    const QSize icon = iconSize();
    return QSize(icon.width()  + 2 * icon_padding_,
                 icon.height() + 2 * icon_padding_);
}

QSize AdaptiveToolButton::minimumSizeHint() const
{
    return sizeHint();
}

void AdaptiveToolButton::applyZoom()
{
    QSize eff;
    if (base_icon_size_.isValid()) {
        eff = QSize(ZoomScaling::scaledPixels(base_icon_size_.width()),
                    ZoomScaling::scaledPixels(base_icon_size_.height()));
    } else {
        // Default: the platform icon contract. The style scales this metric
        // with the zoom itself, so it must not be scaled again here.
        const int icon_size = style()->pixelMetric(QStyle::PM_SmallIconSize, nullptr, this);
        eff = QSize(icon_size, icon_size);
    }
    setIconSize(eff);
    updateGeometry();
}
