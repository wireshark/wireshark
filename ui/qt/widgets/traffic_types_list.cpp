/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/conversation_table.h>

#include <ui/qt/widgets/traffic_types_list.h>

#include <QStringList>

TrafficTypesRowData::TrafficTypesRowData(int protocol, QString name) :
    _protocol(protocol),
    _name(name),
    _checked(false)
{}

int TrafficTypesRowData::protocol() const
{
    return _protocol;
}

QString TrafficTypesRowData::name() const
{
    return _name;
}

bool TrafficTypesRowData::checked() const
{
    return _checked;
}

void TrafficTypesRowData::setChecked(bool checked)
{
    _checked = checked;
}

static gboolean iterateProtocols(const void *key, void *value, void *userdata)
{
    QList<TrafficTypesRowData> * protocols = (QList<TrafficTypesRowData> *)userdata;

    register_ct_t* ct = (register_ct_t*)value;
    const QString title = (const gchar*)key;
    int proto_id = get_conversation_proto_id(ct);
    TrafficTypesRowData entry(proto_id, title);
    protocols->append(entry);

    return FALSE;
}

TrafficTypesModel::TrafficTypesModel(GList ** recentList, QObject *parent) :
    QAbstractListModel(parent),
    _recentList(recentList)
{
    conversation_table_iterate_tables(iterateProtocols, &_allTaps);

    std::sort(_allTaps.begin(), _allTaps.end(), [](TrafficTypesRowData a, TrafficTypesRowData b) {
        return a.name().compare(b.name(), Qt::CaseInsensitive) < 0;
    });

    QList<int> _protocols;

    for (GList * endTab = *_recentList; endTab; endTab = endTab->next) {
        int protoId = proto_get_id_by_short_name((const char *)endTab->data);
        if (protoId > -1 && ! _protocols.contains(protoId))
            _protocols.append(protoId);
    }

    if (_protocols.isEmpty()) {
        QStringList protoNames = QStringList() << "eth" << "ip" << "ipv6" << "tcp" << "udp";
        foreach(QString name, protoNames)
            _protocols << proto_get_id_by_filter_name(name.toStdString().c_str());
    }

    for(int cnt = 0; cnt < _allTaps.count(); cnt++)
    {
        _allTaps[cnt].setChecked(false);
        if (_protocols.contains(_allTaps[cnt].protocol()))
            _allTaps[cnt].setChecked(true);
    }

}

int TrafficTypesModel::rowCount(const QModelIndex &) const
{
    return (int) _allTaps.count();
}

int TrafficTypesModel::columnCount(const QModelIndex &) const
{
    return TrafficTypesModel::COL_NUM;
}

QVariant TrafficTypesModel::data(const QModelIndex &idx, int role) const
{
    if (!idx.isValid())
        return QVariant();

    TrafficTypesRowData data = _allTaps[idx.row()];
    if (role == Qt::DisplayRole)
    {
        switch(idx.column())
        {
            case(TrafficTypesModel::COL_NAME):
                return data.name();
            case(TrafficTypesModel::COL_PROTOCOL):
                return data.protocol();
        }
    } else if (role == Qt::CheckStateRole && idx.column() == TrafficTypesModel::COL_CHECKED) {
        return data.checked() ? Qt::Checked : Qt::Unchecked;
    } else if (role == TrafficTypesModel::TRAFFIC_PROTOCOL) {
        return data.protocol();
    } else if (role == TrafficTypesModel::TRAFFIC_IS_CHECKED) {
        return (bool)data.checked();
    }

    return QVariant();
}

QVariant TrafficTypesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (section < 0 || role != Qt::DisplayRole || orientation != Qt::Horizontal)
        return QVariant();

    if (section == TrafficTypesModel::COL_NAME)
        return tr("Protocol");
    return QVariant();
}

Qt::ItemFlags TrafficTypesModel::flags (const QModelIndex & idx) const
{
    Qt::ItemFlags defaultFlags = QAbstractListModel::flags(idx);
    if (idx.isValid())
        return defaultFlags | Qt::ItemIsUserCheckable;

    return defaultFlags;
}

bool TrafficTypesModel::setData(const QModelIndex &idx, const QVariant &value, int role)
{
    if(!idx.isValid() || role != Qt::CheckStateRole)
        return false;

    if (_allTaps.count() <= idx.row())
        return false;

    _allTaps[idx.row()].setChecked(value == Qt::Checked);

    QList<int> selected;
    prefs_clear_string_list(*_recentList);
    *_recentList = NULL;

    for (int cnt = 0; cnt < _allTaps.count(); cnt++) {
        if (_allTaps[cnt].checked()) {
            int protoId = _allTaps[cnt].protocol();
            selected.append(protoId);
            char *title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(protoId)));
            *_recentList = g_list_append(*_recentList, title);
        }
    }

    emit protocolsChanged(selected);

    emit dataChanged(idx, idx);
    return true;
}

void TrafficTypesModel::selectProtocols(QList<int> protocols)
{
    beginResetModel();
    for (int cnt = 0; cnt < _allTaps.count(); cnt++) {
        _allTaps[cnt].setChecked(false);
        if (protocols.contains(_allTaps[cnt].protocol()))
            _allTaps[cnt].setChecked(true);
    }
    endResetModel();
}


TrafficListSortModel::TrafficListSortModel(QObject * parent) :
    QSortFilterProxyModel(parent)
{}

bool TrafficListSortModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    if (source_left.isValid() && source_left.column() == TrafficTypesModel::COL_NAME) {
        QString valA = source_left.data().toString();
        QString valB = source_right.data().toString();
        return valA.compare(valB, Qt::CaseInsensitive) <= 0;
    }
    return QSortFilterProxyModel::lessThan(source_left, source_right);
}


TrafficTypesList::TrafficTypesList(QWidget *parent) :
    QTreeView(parent)
{
    _name = QString();
    _model = nullptr;

    setAlternatingRowColors(true);
    setRootIsDecorated(false);
}

void TrafficTypesList::setProtocolInfo(QString name, GList ** recentList)
{
    _name = name;

    TrafficListSortModel * sortModel = new TrafficListSortModel();

    _model = new TrafficTypesModel(recentList);
    sortModel->setSourceModel(_model);
    setModel(sortModel);

    setSortingEnabled(true);
    sortByColumn(TrafficTypesModel::COL_NAME, Qt::AscendingOrder);

    connect(_model, &TrafficTypesModel::protocolsChanged, this, &TrafficTypesList::protocolsChanged);

    resizeColumnToContents(0);
    resizeColumnToContents(1);
}

void TrafficTypesList::selectProtocols(QList<int> protocols)
{
    if (_model)
        _model->selectProtocols(protocols);
}

QList<int> TrafficTypesList::protocols() const
{
    QList<int> entries;
    for (int cnt = 0; cnt < _model->rowCount(); cnt++) {
        QModelIndex idx = _model->index(cnt, TrafficTypesModel::COL_CHECKED);
        int protoId = _model->data(idx, TrafficTypesModel::TRAFFIC_PROTOCOL).toInt();
        if (protoId > 0 && ! entries.contains(protoId))
            entries.append(protoId);
    }

    return entries;
}

QList<int> TrafficTypesList::selectedProtocols() const
{
    QList<int> entries;
    for (int cnt = 0; cnt < _model->rowCount(); cnt++) {
        QModelIndex idx = _model->index(cnt, TrafficTypesModel::COL_CHECKED);
        int protoId = _model->data(idx, TrafficTypesModel::TRAFFIC_PROTOCOL).toInt();
        if (protoId > 0 && ! entries.contains(protoId) && _model->data(idx, TrafficTypesModel::TRAFFIC_IS_CHECKED).toBool())
            entries.append(protoId);
    }

    return entries;
}
