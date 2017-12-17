/* enabled_protocols_model.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef ENABLED_PROTOCOLS_MODEL_H
#define ENABLED_PROTOCOLS_MODEL_H

#include <config.h>

#include <epan/proto.h>

#include <QAbstractItemModel>
#include <QSortFilterProxyModel>

class EnabledProtocolItem;

class EnabledProtocolsModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    explicit EnabledProtocolsModel(QObject * parent = Q_NULLPTR);
    virtual ~EnabledProtocolsModel();

    enum EnabledProtocolsColumn {
        colProtocol = 0,
        colDescription,
        colLast
    };

    QModelIndex index(int row, int column,
                      const QModelIndex & = QModelIndex()) const;
    QModelIndex parent(const QModelIndex &) const;
    Qt::ItemFlags flags(const QModelIndex &index) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    void populate();
    void invertEnabled();
    void enableAll();
    void disableAll();

    void applyChanges(bool writeChanges = true);
    static void disableProtocol(struct _protocol *protocol);

protected:
    static void saveChanges(bool writeChanges = true);

private:
    EnabledProtocolItem* root_;
};

class EnabledProtocolsProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:

    explicit EnabledProtocolsProxyModel(QObject * parent = Q_NULLPTR);

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    void setFilter(const QString& filter);

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    bool filterAcceptItem(EnabledProtocolItem& item) const;

private:

    QString filter_;
};

#endif // ENABLED_PROTOCOLS_MODEL_H

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
