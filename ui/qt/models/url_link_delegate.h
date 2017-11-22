/* url_link_delegate.h
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef URL_LINK_DELEGATE_H
#define URL_LINK_DELEGATE_H

#include <config.h>

#include <QWidget>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QModelIndex>
#include <QAbstractItemModel>

class UrlLinkDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit UrlLinkDelegate(QObject *parent = Q_NULLPTR);

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const;


};
#endif // URL_LINK_DELEGATE_H
