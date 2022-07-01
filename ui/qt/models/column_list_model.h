/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLUMN_LIST_MODELS_H
#define COLUMN_LIST_MODELS_H

#include <QAbstractListModel>
#include <QSortFilterProxyModel>
#include <QStyledItemDelegate>
#include <QSortFilterProxyModel>
#include <QMimeData>

class ColumnProxyModel : public QSortFilterProxyModel
{
public:
    ColumnProxyModel(QObject *parent = Q_NULLPTR);

    void setShowDisplayedOnly(bool set);

protected:
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

private:
    bool showDisplayedOnly_;
};

class ColumnTypeDelegate : public QStyledItemDelegate
{
public:
    ColumnTypeDelegate(QObject * parent = Q_NULLPTR);

    QWidget * createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

    void setEditorData(QWidget *editor, const QModelIndex &index) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const override;
};

class ColumnListModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    ColumnListModel(QObject * parent = Q_NULLPTR);

    enum {
        COL_DISPLAYED,
        COL_TITLE,
        COL_TYPE,
        COL_FIELDS,
        COL_OCCURRENCE,
        COL_RESOLVED
    };

    enum {
        OriginalType = Qt::UserRole,
        DisplayedState
    };

    void saveColumns();

    void addEntry();
    void deleteEntry(int row);
    void reset();

    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const;

    virtual QStringList mimeTypes() const;
    virtual QMimeData *mimeData(const QModelIndexList &indexes) const;
    virtual Qt::DropActions supportedDropActions() const;
    virtual bool canDropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) const;
    virtual bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent);

    virtual bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

private:
    QString headerTitle(int section) const;

    void populate();
};

#endif // COLUMN_LIST_MODELS_H
