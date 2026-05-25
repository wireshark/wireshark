/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TIMELINE_DELEGATE_H
#define TIMELINE_DELEGATE_H

/*
 * @file Timeline delegate.
 *
 * QStyledItemDelegate subclass that will draw a timeline indicator for
 * the specified value.
 *
 * This is intended to be used in QTreeWidgets to show timelines, e.g. for
 * conversations.
 * To use it, first call setItemDelegate:
 *
 *   myTreeWidget()->setItemDelegateForColumn(col_time_start_, new TimelineDelegate());
 *
 * Then, for each QTreeWidgetItem, set or return a timeline_span for the start and end
 * of the timeline in pixels relative to the column width.
 *
 *   setData(col_start_, Qt::UserRole, start_span);
 *   setData(col_end_, Qt::UserRole, end_span);
 *
 */

#include <QStyledItemDelegate>

/**
 * @brief Describes a single time-span bar to be rendered inside a timeline cell,
 *        with pixel geometry and normalised time coordinates for positioning.
 *
 * All pixel fields are relative to the item's bounding rectangle and will be
 * clipped to it during painting.
 */
struct timeline_span {
    int start; /**< Left edge of the span bar in pixels, relative to the item rect. */
    int width; /**< Width of the span bar in pixels. */

    double startTime;   /**< Absolute start time of the span in seconds. */
    double stopTime;    /**< Absolute stop time of the span in seconds. */
    double minRelTime;  /**< Minimum relative time across all spans in the cell, used for normalisation. */
    double maxRelTime;  /**< Maximum relative time across all spans in the cell, used for normalisation. */

    int colStart;    /**< Start colour index or gradient stop for the span bar. */
    int colDuration; /**< Duration used to select the span bar colour or gradient width. */
};

Q_DECLARE_METATYPE(timeline_span)


/**
 * @brief Item delegate that paints a horizontal timeline bar inside a table or
 *        tree cell, using timeline_span data retrieved from a configurable model role.
 */
class TimelineDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Constructs the TimelineDelegate.
     * @param parent Optional parent widget passed to QStyledItemDelegate.
     */
    TimelineDelegate(QWidget *parent = 0);

    /**
     * @brief Sets the model role from which timeline_span data is retrieved during painting.
     * @param role Qt item data role that returns a QVariant containing a timeline_span.
     */
    void setDataRole(int role);

protected:
    /**
     * @brief Paints the timeline bar for the cell at @p index using the span geometry
     *        stored in the configured data role.
     * @param painter Painter to draw with; clipped to the item rectangle.
     * @param option  Style options including the item rectangle and state flags.
     * @param index   Model index of the cell being painted.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

private:
    int _dataRole; /**< Model role used to retrieve timeline_span data for each cell. */
};

#endif // TIMELINE_DELEGATE_H
