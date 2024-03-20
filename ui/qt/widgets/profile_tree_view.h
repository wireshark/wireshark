/** @file
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

    // QAbstractItemDelegate interface
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    virtual void setEditorData(QWidget *editor, const QModelIndex &index) const;

private:
    QWidget * editor_;
    QModelIndex index_;
};

class ProfileTreeView : public QTreeView
{
    Q_OBJECT
public:
    ProfileTreeView(QWidget *parent = nullptr);
    ~ProfileTreeView();

    void selectRow(int row);
    bool activeEdit();

signals:
    void itemUpdated();

    // QWidget interface
protected:
    virtual void showEvent(QShowEvent *);
    virtual void mouseDoubleClickEvent(QMouseEvent *event);

    // QAbstractItemView interface
protected slots:
    virtual void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    virtual void itemClicked(const QModelIndex &index);

private:
    ProfileTreeEditDelegate *delegate_;

};

#endif
