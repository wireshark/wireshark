/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/adaptive_header_view.h>

#include <QEvent>
#include <QFontMetrics>
#include <QSize>
#include <QStyle>

AdaptiveHeaderView::AdaptiveHeaderView(Qt::Orientation orientation, QWidget *parent) :
    QHeaderView(orientation, parent)
{
}

QSize AdaptiveHeaderView::sizeHint() const
{
    QSize size = QHeaderView::sizeHint();
    int margin = style()->pixelMetric(QStyle::PM_HeaderMargin, nullptr, this);
    // fontMetrics is a shortcut for QFontMetrics(font())
    size.setHeight(fontMetrics().height() + 2 * margin);
    return size;
}

void AdaptiveHeaderView::changeEvent(QEvent *event)
{
    QHeaderView::changeEvent(event);

    if (event->type() == QEvent::FontChange) {
        // Update the size hint when the font changes, to ensure the header height is updated.
        updateGeometry();
    }
}
