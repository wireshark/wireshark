/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ENABLED_PROTOCOLS_MODEL_H
#define ENABLED_PROTOCOLS_MODEL_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <epan/proto.h>

#include <QAbstractItemModel>
#include <QSortFilterProxyModel>

class EnabledProtocolItem : public ModelHelperTreeItem<EnabledProtocolItem>
{
    Q_GADGET
public:
    enum EnableProtocolType{
        Any,
        Standard,
        Heuristic
    };
    Q_ENUM(EnableProtocolType)

    EnabledProtocolItem(QString name, QString description, bool enabled, EnabledProtocolItem* parent);
    virtual ~EnabledProtocolItem();

    QString name() const {return name_;}
    QString description() const {return description_;}
    bool enabled() const {return enabled_;}
    void setEnabled(bool enable) {enabled_ = enable;}

    EnableProtocolType type() const;

    bool applyValue();

protected:
    virtual void applyValuePrivate(bool value) = 0;

    QString name_;
    QString description_;
    bool enabled_;
    bool enabledInit_;      //value that model starts with to determine change
    EnableProtocolType type_;
};

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

    enum EnableProtocolData {
        DATA_ENABLE = Qt::UserRole,
        DATA_PROTOCOL_TYPE
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
    enum SearchType
    {
        EveryWhere,
        OnlyProtocol,
        OnlyDescription,
        EnabledItems,
        DisabledItems
    };
    Q_ENUM(SearchType)

    enum EnableType
    {
        Enable,
        Disable,
        Invert
    };

    explicit EnabledProtocolsProxyModel(QObject * parent = Q_NULLPTR);

    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    void setFilter(const QString& filter, EnabledProtocolsProxyModel::SearchType type,
        EnabledProtocolItem::EnableProtocolType protocolType);

    void setItemsEnable(EnabledProtocolsProxyModel::EnableType enable, QModelIndex parent = QModelIndex());

protected:
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;

private:
    EnabledProtocolsProxyModel::SearchType type_;
    EnabledProtocolItem::EnableProtocolType protocolType_;
    QString filter_;

    bool filterAcceptsSelf(int sourceRow, const QModelIndex &sourceParent) const;
    bool filterAcceptsChild(int sourceRow, const QModelIndex &sourceParent) const;
};

#endif // ENABLED_PROTOCOLS_MODEL_H
