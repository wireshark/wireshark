/* supported_protocols_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SUPPORTED_PROTOCOLS_MODEL_H
#define SUPPORTED_PROTOCOLS_MODEL_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <epan/proto.h>

#include <QSortFilterProxyModel>

class SupportedProtocolsItem : public ModelHelperTreeItem<SupportedProtocolsItem>
{
public:
    SupportedProtocolsItem(protocol_t* proto, const char *name, const char* filter, ftenum_t ftype, const char* descr, SupportedProtocolsItem* parent);
    virtual ~SupportedProtocolsItem();

    protocol_t* protocol() const {return proto_; }
    QString name() const { return name_; }
    ftenum_t type() const {return ftype_; }
    QString filter() const { return filter_; }
    QString description() const { return descr_; }

private:
    protocol_t* proto_;
    QString name_;
    QString filter_;
    ftenum_t ftype_;
    QString descr_;
};


class SupportedProtocolsModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit SupportedProtocolsModel(QObject * parent = Q_NULLPTR);
    virtual ~SupportedProtocolsModel();

    enum SupportedProtocolsColumn {
        colName = 0,
        colFilter,
        colType,
        colDescription,
        colLast
    };

    int fieldCount() {return field_count_;}

    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
    QVariant data(const QModelIndex &index, int role) const;

    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    void populate();

private:
    SupportedProtocolsItem* root_;
    int field_count_;
};

class SupportedProtocolsProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:

    explicit SupportedProtocolsProxyModel(QObject * parent = Q_NULLPTR);

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    void setFilter(const QString& filter);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    bool filterAcceptItem(SupportedProtocolsItem& item) const;

private:

    QString filter_;
};

#endif // SUPPORTED_PROTOCOLS_MODEL_H

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
