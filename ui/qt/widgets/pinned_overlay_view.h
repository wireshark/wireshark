/** @file
 *
 * Header file defining shared setup for the pinned overlay views
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PINNED_OVERLAY_VIEW_H
#define PINNED_OVERLAY_VIEW_H

#include <QTreeView>
#include <QHeaderView>
#include <QWidget>
#include <QPalette>

/**
 * @brief Setup shared by PinnedColumnView and PinnedRowView, the two
 * QTreeView-based overlay panes used to keep frozen columns/pinned rows
 * visible alongside the primary packet list. Factored out so a fix to one
 * overlay's base configuration (or its boundary-divider widget) can't be
 * applied to only one of the two views by mistake.
 */
namespace PinnedOverlayView {

/**
 * @brief Applies the QTreeView configuration common to every pinned
 * overlay pane: no expand arrows, uniform row heights, no keyboard focus
 * (see either view's constructor comment for why), continuous mouse
 * tracking (so hover can be reported to the primary view), and no
 * scrollbars of its own (scrolling is always mirrored from the primary
 * view instead).
 * @param view The overlay view to configure.
 */
inline void applyCommonTreeViewSetup(QTreeView *view)
{
    view->setItemsExpandable(false);
    view->setRootIsDecorated(false);
    view->setUniformRowHeights(true);
    view->setFocusPolicy(Qt::NoFocus);
    view->setMouseTracking(true);
    view->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    view->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    view->setFrameShape(QFrame::NoFrame);
    view->setVisible(false);
}

/**
 * @brief Constructs the thin child widget marking the boundary between
 * frozen and non-frozen columns, styled to match the palette's "mid"
 * color the same way in both overlay panes. A plain QPainter(view) can't
 * be used directly on a QAbstractScrollArea-derived widget like QTreeView
 * (Qt redirects painting to the viewport, not the widget itself), so this
 * is a real (if trivial) child widget instead of a custom paintEvent().
 * @param view The overlay view the divider belongs to (used as its parent
 * and as the source of the palette to match).
 * @return The newly-constructed divider widget, parented to view.
 */
inline QWidget *createBoundaryDivider(QTreeView *view)
{
    QWidget *divider = new QWidget(view);
    divider->setAutoFillBackground(true);
    QPalette divider_palette = divider->palette();
    divider_palette.setColor(QPalette::Window, view->palette().color(QPalette::Mid));
    divider->setPalette(divider_palette);
    return divider;
}

/**
 * @brief Repositions a boundary divider widget (see createBoundaryDivider())
 * to hug the view's right edge, spanning its full height. Called from both
 * overlay panes' resizeEvent() overrides to keep the divider in sync as
 * the view is resized.
 * @param divider The divider widget to reposition.
 * @param view The overlay view it belongs to.
 */
inline void repositionBoundaryDivider(QWidget *divider, QTreeView *view)
{
    const int divider_width = 2;
    divider->setGeometry(view->width() - divider_width, 0, divider_width, view->height());
    divider->raise();
}

/**
 * @brief Mirrors a single section's width from the primary view's header
 * onto this overlay view's own header, ignoring an out-of-range column
 * (e.g. one not currently shown by this particular overlay).
 * @param view The overlay view whose header should be resized.
 * @param column The column (logical section index) to resize.
 * @param width The new width, from the primary view's header.
 */
inline void mirrorSectionWidth(QTreeView *view, int column, int width)
{
    if (column < 0 || !view->header() || column >= view->header()->count()) {
        return;
    }
    view->header()->resizeSection(column, width);
}

} // namespace PinnedOverlayView

#endif // PINNED_OVERLAY_VIEW_H
