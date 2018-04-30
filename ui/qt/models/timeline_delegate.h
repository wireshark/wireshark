/* timeline_delegate.h
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

// Pixels are relative to item rect and will be clipped.
struct timeline_span {
    int start;
    int width;
};

Q_DECLARE_METATYPE(timeline_span)

class TimelineDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    TimelineDelegate(QWidget *parent = 0);

    // Make sure QStyledItemDelegate::paint doesn't draw any text.
    virtual QString displayText(const QVariant &, const QLocale &) const { return QString(); }

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const;
private:
};

#endif // TIMELINE_DELEGATE_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
