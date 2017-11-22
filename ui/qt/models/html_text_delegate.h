/* html_text_delegate.h
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef HTML_TEXT_DELEGATE_H
#define HTML_TEXT_DELEGATE_H

#include <config.h>

#include <QWidget>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QModelIndex>
#include <QAbstractItemModel>

class HTMLTextDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit HTMLTextDelegate(QObject *parent = Q_NULLPTR);

protected:
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const;


};
#endif // HTML_TEXT_DELEGATE_H

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
