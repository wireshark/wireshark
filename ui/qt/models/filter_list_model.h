/* filter_list_model.h
 * Model for all filter types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_LIST_MODEL_h
#define FILTER_LIST_MODEL_h

#include <config.h>

#include <QAbstractListModel>
#include <QList>
#include <QStringList>

class FilterListModel : public QAbstractListModel
{

public:
    enum FilterListType {
        Display,
        Capture
    };

    explicit FilterListModel(FilterListType type = FilterListModel::Display, QObject * parent = Q_NULLPTR);
    explicit FilterListModel(QObject * parent = Q_NULLPTR);

    enum {
        ColumnName,
        ColumnExpression
    };

    void setFilterType(FilterListModel::FilterListType type);
    FilterListModel::FilterListType filterType() const;

    QModelIndex findByName(QString name);
    QModelIndex findByExpression(QString expression);

    QModelIndex addFilter(QString name, QString expression);
    void removeFilter(QModelIndex idx);

    void saveList();

    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role) override;
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    virtual Qt::DropActions supportedDropActions() const override;
    virtual QStringList mimeTypes() const override;
    virtual QMimeData *mimeData(const QModelIndexList &indexes) const override;
    virtual bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) override;

private:

    FilterListModel::FilterListType type_;

    QStringList storage;

    void reload();
};

#endif // FILTER_LIST_MODEL_h

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
