/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/adaptive_header_view.h>

#include <ui/qt/utils/font_manager.h>

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
    // The platform style pins the header height to the base font — on macOS it
    // is a hard constant that ignores the current font, so it never tracks the
    // application zoom. Take the native height as the baseline and add only the
    // extra room the zoomed font needs: native look at default zoom, growing
    // when the user zooms in.
    QStyleOptionHeader opt;
    opt.initFrom(this);
    QFont baseFont = FontManager::font();          // unzoomed baseline
    opt.fontMetrics = QFontMetrics(baseFont);
    int nativeHeight = style()->sizeFromContents(QStyle::CT_HeaderSection, &opt, QSize(), this).height();
    int zoomDelta = qMax(0, fontMetrics().height() - QFontMetrics(baseFont).height());

    size.setHeight(nativeHeight + zoomDelta);
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
