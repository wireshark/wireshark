/* profile_tree_view.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_TREEVIEW_H
#define PROFILE_TREEVIEW_H

#include <ui/qt/models/url_link_delegate.h>

#include <QTreeView>
#include <QItemDelegate>

class ProfileUrlLinkDelegate : public UrlLinkDelegate
{
    Q_OBJECT

public:
    explicit ProfileUrlLinkDelegate(QObject *parent = Q_NULLPTR);

    virtual void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const;
};

class ProfileTreeEditDelegate : public QItemDelegate
{
    Q_OBJECT
public:
    ProfileTreeEditDelegate(QWidget *parent = Q_NULLPTR);

    virtual void setEditorData(QWidget *editor, const QModelIndex &index) const;
};

class ProfileTreeView : public QTreeView
{
    Q_OBJECT
public:
    ProfileTreeView(QWidget *parent = nullptr);

    void selectRow(int row);

Q_SIGNALS:
    void currentItemChanged();
    void itemUpdated();

    // QAbstractItemView interface
protected slots:
    virtual void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    virtual void currentChanged(const QModelIndex &current, const QModelIndex &previous);

    virtual void clicked(const QModelIndex &index);

private:
    ProfileTreeEditDelegate *delegate_;
};

#endif
