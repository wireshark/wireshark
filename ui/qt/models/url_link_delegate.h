/* url_link_delegate.h
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef URL_LINK_DELEGATE_H
#define URL_LINK_DELEGATE_H

#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QModelIndex>

class QRegExp;

class UrlLinkDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    explicit UrlLinkDelegate(QObject *parent = Q_NULLPTR);
    ~UrlLinkDelegate();
    // If pattern matches the string in column, render as a URL.
    // Otherwise render as plain text.
    void setColCheck(int column, QString &pattern);

protected:
    virtual void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;

private:
    int re_col_;
    QRegExp *url_re_;
};
#endif // URL_LINK_DELEGATE_H

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
 */
