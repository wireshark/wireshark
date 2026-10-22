/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QPixmap>
#include <QSize>
#include <QtGlobal>

/**
 * @brief Opacity of an icon drawn in QIcon::Disabled mode.  Shared by the
 *        theme icon engines so every disabled icon dims alike.
 */
inline constexpr qreal kIconDisabledOpacity = 0.4;

/**
 * @brief A fully transparent pixmap of @p logical size at device-pixel ratio
 *        @p scale, to be painted in logical coordinates.
 *
 * A new QPixmap is uninitialised, and filling it through a painter with
 * Qt::transparent is a no-op under SourceOver, so it is cleared directly.
 */
inline QPixmap transparentIconPixmap(const QSize &logical, qreal scale)
{
    QPixmap pm(logical * scale);
    pm.setDevicePixelRatio(scale);
    pm.fill(Qt::transparent);
    return pm;
}
