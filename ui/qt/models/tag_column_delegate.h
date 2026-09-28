/* tag_column_delegate.h
 *
 * Delegate for COL_TAG packet list column
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TAG_COLUMN_DELEGATE_H
#define TAG_COLUMN_DELEGATE_H

#include <config.h>

#include <QStyledItemDelegate>

class QPainter;

class TagColumnDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit TagColumnDelegate(QWidget *parent = nullptr);

    /**
     * @brief Paint only the tag content (emoji/text), no background fill.
     *
     * Used by PacketList::drawRow() and PinnedRowView::drawRow() when
     * painting the hover highlight, so the hover background isn't clobbered
     * by this delegate's own background fill (which paint() does via
     * initStyleOption(), re-fetching Qt::BackgroundRole from the model).
     */
    void paintContent(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    bool editorEvent(QEvent *event, QAbstractItemModel *model, const QStyleOptionViewItem &option, const QModelIndex &index) override;
};

#endif // TAG_COLUMN_DELEGATE_H
