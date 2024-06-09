/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/conversation_table.h>
#include <epan/prefs.h>

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

static bool iterateProtocols(const void *key, void *value, void *userdata)
{
    QList<TrafficTypesRowData> * protocols = (QList<TrafficTypesRowData> *)userdata;

    register_ct_t* ct = (register_ct_t*)value;
    const QString title = (const char*)key;
    int proto_id = get_conversation_proto_id(ct);
    TrafficTypesRowData entry(proto_id, title);
    protocols->append(entry);

    return false;
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

    // When updating the tabs, save the current selection, it will be restored below
    GList *selected_tab = g_list_first(*_recentList);
    int rct_protoId = -1;
    if (selected_tab != nullptr) {
        rct_protoId = proto_get_id_by_short_name((const char *)selected_tab->data);

        // Did the user just uncheck the current selection?
        if (_allTaps[idx.row()].protocol() == rct_protoId && value.toInt() == Qt::Unchecked) {
            // Yes. The code below will restore it. Rather than removing it,
            // resetting the model, and then adding it back, just return.
            // The user might want to uncheck the current selection, in which
            // case the code needs to changed to handle that.
            //
            // Note that not allowing the current first tab to be unselected does
            // have the advantage of preventing a crash from having no tabs
            // selected in the Endpoint dialog (#18250).
            return false;
        }
    }

    _allTaps[idx.row()].setChecked(value.toInt() == Qt::Checked);

    QList<int> selected;
    prefs_clear_string_list(*_recentList);
    *_recentList = NULL;

    for (int cnt = 0; cnt < _allTaps.count(); cnt++) {
        if (_allTaps[cnt].checked()) {
            int protoId = _allTaps[cnt].protocol();
            if(protoId != rct_protoId) {
                selected.append(protoId);
                char *title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(protoId)));
                *_recentList = g_list_append(*_recentList, title);
            }
        }
    }

    if (rct_protoId != -1) {
        // restore the selection by prepending it to the recent list
        char *rct_title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(rct_protoId)));
        selected.prepend(rct_protoId);
        *_recentList = g_list_prepend(*_recentList, rct_title);
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

void TrafficListSortModel::setFilter(QString filter)
{
    if ( filter.compare(_filter) != 0 ) {
        _filter = filter;
        invalidateFilter();
    }
}

bool TrafficListSortModel::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    if (sourceModel() && _filter.length() > 0) {
        QModelIndex idx = sourceModel()->index(source_row, TrafficTypesModel::COL_NAME);

        if (idx.isValid()) {
            QString name = idx.data().toString();
            if (name.contains(_filter, Qt::CaseInsensitive))
                return true;
            return false;
        }
    }

    return QSortFilterProxyModel::filterAcceptsRow(source_row, source_parent);
}


TrafficTypesList::TrafficTypesList(QWidget *parent) :
    QTreeView(parent)
{
    _name = QString();
    _model = nullptr;
    _sortModel = nullptr;

    setAlternatingRowColors(true);
    setRootIsDecorated(false);
}

void TrafficTypesList::setProtocolInfo(QString name, GList ** recentList)
{
    _name = name;

    _sortModel = new TrafficListSortModel(this);

    _model = new TrafficTypesModel(recentList, this);
    _sortModel->setSourceModel(_model);
    setModel(_sortModel);

    setSortingEnabled(true);
    sortByColumn(TrafficTypesModel::COL_NAME, Qt::AscendingOrder);

    connect(_model, &TrafficTypesModel::protocolsChanged, this, &TrafficTypesList::protocolsChanged);

    resizeColumnToContents(0);
    resizeColumnToContents(1);
}

void TrafficTypesList::selectProtocols(QList<int> protocols)
{
    if (_model) {
        _model->selectProtocols(protocols);
        emit clearFilterList();
    }
}

QList<int> TrafficTypesList::protocols(bool onlySelected) const
{
    QList<int> entries;
    for (int cnt = 0; cnt < _model->rowCount(); cnt++) {
        QModelIndex idx = _model->index(cnt, TrafficTypesModel::COL_CHECKED);
        int protoId = _model->data(idx, TrafficTypesModel::TRAFFIC_PROTOCOL).toInt();
        if (protoId > 0 && ! entries.contains(protoId)) {
            if (!onlySelected || _model->data(idx, TrafficTypesModel::TRAFFIC_IS_CHECKED).toBool())
                entries.append(protoId);
        }
    }

    return entries;
}

void TrafficTypesList::filterList(QString filter)
{
    _sortModel->setFilter(filter);
}

