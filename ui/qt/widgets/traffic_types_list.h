/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TRAFFIC_TYPES_LIST_H
#define TRAFFIC_TYPES_LIST_H

#include "config.h"

#include <glib.h>

#include <QTreeView>
#include <QAbstractListModel>
#include <QMap>
#include <QList>
#include <QString>
#include <QSortFilterProxyModel>

class TrafficTypesRowData
{

public:
    TrafficTypesRowData(int protocol, QString name);

    int protocol() const;
    QString name() const;
    bool checked() const;
    void setChecked(bool checked);

private:
    int _protocol;
    QString _name;
    bool _checked;
};


class TrafficTypesModel : public QAbstractListModel
{
    Q_OBJECT
public:

    enum {
        TRAFFIC_PROTOCOL = Qt::UserRole,
        TRAFFIC_IS_CHECKED,
    } eTrafficUserData;

    enum {
        COL_CHECKED,
        COL_NAME,
        COL_NUM,
        COL_PROTOCOL,
    } eTrafficColumnNames;

    TrafficTypesModel(GList ** recentList, QObject *parent = nullptr);

    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    virtual QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const override;
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    virtual bool setData(const QModelIndex &idx, const QVariant &value, int role) override;
    virtual Qt::ItemFlags flags (const QModelIndex & idx) const override;

    QList<int> protocols() const;

public slots:
    void selectProtocols(QList<int> protocols);

signals:
    void protocolsChanged(QList<int> protocols);

private:
    QList<TrafficTypesRowData> _allTaps;
    GList ** _recentList;

};


class TrafficListSortModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    TrafficListSortModel(QObject * parent = nullptr);

    void setFilter(QString filter = QString());

protected:
    virtual bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override;

private:
    QString _filter;
};


class TrafficTypesList : public QTreeView
{
    Q_OBJECT
public:

    TrafficTypesList(QWidget *parent = nullptr);

    void setProtocolInfo(QString name, GList ** recentList);
    QList<int> protocols(bool onlySelected = false) const;

public slots:
    void selectProtocols(QList<int> protocols);
    void filterList(QString);

signals:
    void protocolsChanged(QList<int> protocols);
    void clearFilterList();

private:
    QString _name;
    TrafficTypesModel * _model;
    TrafficListSortModel * _sortModel;
};

#endif // TRAFFIC_TYPES_LIST_H