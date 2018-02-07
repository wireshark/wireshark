/* dissector_tables_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISSECTOR_TABLES_MODEL_H
#define DISSECTOR_TABLES_MODEL_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <QSortFilterProxyModel>

class DissectorTablesItem : public ModelHelperTreeItem<DissectorTablesItem>
{
public:
    DissectorTablesItem(QString tableName, QString shortName, DissectorTablesItem* parent);
    virtual ~DissectorTablesItem();

    QString tableName() const {return tableName_;}
    QString shortName() const {return shortName_;}

    virtual bool lessThan(DissectorTablesItem &right) const;

protected:
    QString tableName_;
    QString shortName_;
};

class DissectorTablesModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit DissectorTablesModel(QObject * parent = Q_NULLPTR);
    virtual ~DissectorTablesModel();

    enum DissectorTablesColumn {
        colTableName = 0,
        colShortName,
        colLast
    };

    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
    QVariant data(const QModelIndex &index, int role) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    void populate();

private:
    DissectorTablesItem* root_;
};

class DissectorTablesProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:

    explicit DissectorTablesProxyModel(QObject * parent = Q_NULLPTR);

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    void adjustHeader(const QModelIndex &currentIndex);
    void setFilter(const QString& filter);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    bool filterAcceptItem(DissectorTablesItem& item) const;

private:

    QString tableName_;
    QString shortName_;
    QString filter_;
};

#endif // DISSECTOR_TABLES_MODEL_H

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
