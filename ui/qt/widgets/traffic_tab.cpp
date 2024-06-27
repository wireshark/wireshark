/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/proto.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/maxmind_db.h>
#include <epan/conversation_table.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/filesystem.h>

#include <ui/qt/main_application.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/traffic_tab.h>
#include <ui/qt/widgets/traffic_tree.h>
#include <ui/qt/widgets/traffic_types_list.h>
#include <ui/qt/widgets/detachable_tabwidget.h>

#include <QStringList>
#include <QTreeView>
#include <QList>
#include <QMap>
#include <QPushButton>
#include <QMenu>
#include <QSortFilterProxyModel>
#include <QTabBar>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QTextStream>
#include <QClipboard>
#include <QMessageBox>
#include <QUrl>
#include <QTemporaryFile>
#include <QHBoxLayout>

TabData::TabData() :
    _name(QString()),
    _protoId(-1)
{}

TabData::TabData(QString name, int protoId) :
    _name(name),
    _protoId(protoId)
{}

QString TabData::name() const
{
    return _name;
}

int TabData::protoId() const
{
    return _protoId;
}


TrafficTab::TrafficTab(QWidget * parent) :
    DetachableTabWidget(parent)
{
    _createModel = nullptr;
    _createDelegate = nullptr;
    _disableTaps = false;
    _nameResolution = false;
    setTabBasename(QString());
}

TrafficTab::~TrafficTab()
{}

void TrafficTab::setProtocolInfo(QString tableName, TrafficTypesList * trafficList, GList ** recentList, GList ** recentColumnList, ATapModelCallback createModel)
{
    setTabBasename(tableName);

    _allProtocols = trafficList->protocols();
    if (createModel)
        _createModel = createModel;

    _recentList = recentList;
    _recentColumnList = recentColumnList;

    setOpenTabs(trafficList->protocols(true));
}

void TrafficTab::setDelegate(ATapCreateDelegate createDelegate)
{
    if (! createDelegate)
        return;

    _createDelegate = createDelegate;


    for (int idx = 0; idx < count(); idx++) {
        if (qobject_cast<QTreeView *>(widget(idx)))
        {
            QTreeView * tree = qobject_cast<QTreeView *>(widget(idx));
            tree->setItemDelegate(createDelegate(tree));
        }
    }
}

QTreeView * TrafficTab::createTree(int protoId)
{
    TrafficTree * tree = new TrafficTree(tabBasename(), _recentColumnList, this);

    if (_createModel) {
        ATapDataModel * model = _createModel(protoId, "");
        model->setParent(tree);
        connect(model, &ATapDataModel::tapListenerChanged, tree, &TrafficTree::tapListenerEnabled);

        model->enableTap();

        if (_createDelegate)
        {
            tree->setItemDelegate(_createDelegate(tree));
        }

        TrafficDataFilterProxy * proxyModel = new TrafficDataFilterProxy(tree);
        proxyModel->setSourceModel(model);
        tree->setModel(proxyModel);

        QItemSelectionModel * ism = new QItemSelectionModel(proxyModel, tree);
        tree->setSelectionModel(ism);
        connect(ism, &QItemSelectionModel::currentChanged, this, &TrafficTab::doCurrentIndexChange);

        tree->applyRecentColumns();

        tree->sortByColumn(0, Qt::AscendingOrder);

        connect(proxyModel, &TrafficDataFilterProxy::modelReset, this, [tree]() {
            if (tree->model()->rowCount() > 0) {
                for (int col = 0; col < tree->model()->columnCount(); col++)
                    tree->resizeColumnToContents(col);
            }
        });
        connect(proxyModel, &TrafficDataFilterProxy::modelReset, this, &TrafficTab::modelReset);

        /* If the columns for the tree have changed, contact the tab. By also having the tab
         * columns changed signal connecting back to the tree, it will propagate to all trees
         * registered with this tab. Attention, this heavily relies on the fact, that all
         * tree data models are identical */
        connect(tree, &TrafficTree::columnsHaveChanged, this, &TrafficTab::columnsHaveChanged);
        connect(this, &TrafficTab::columnsHaveChanged, tree, &TrafficTree::columnsChanged);
    }

    return tree;
}

void TrafficTab::useAbsoluteTime(bool absolute)
{
    for(int idx = 0; idx < count(); idx++)
    {
        ATapDataModel * atdm = dataModelForTabIndex(idx);
        if (atdm)
            atdm->useAbsoluteTime(absolute);
    }
}

void TrafficTab::useNanosecondTimestamps(bool nanoseconds)
{
    for(int idx = 0; idx < count(); idx++)
    {
        ATapDataModel * atdm = dataModelForTabIndex(idx);
        if (atdm)
            atdm->useNanosecondTimestamps(nanoseconds);
    }
}

void TrafficTab::disableTap()
{
    for(int idx = 0; idx < count(); idx++)
    {
        ATapDataModel * atdm = dataModelForTabIndex(idx);
        if (atdm)
            atdm->disableTap();
    }

    _disableTaps = true;
    emit disablingTaps();
}

void TrafficTab::setOpenTabs(QList<int> protocols)
{
    QList<int> tabs = _tabs.keys();
    QList<int> remove;
    blockSignals(true);

    foreach(int protocol, protocols)
    {
        if (! tabs.contains(protocol)) {
            insertProtoTab(protocol, false);
        }
        tabs.removeAll(protocol);
    }

    foreach(int protocol, tabs)
        removeProtoTab(protocol, false);

    blockSignals(false);

    emit tabsChanged(_tabs.keys());
    emit retapRequired();
}

void TrafficTab::insertProtoTab(int protoId, bool emitSignals)
{
    QList<int> lUsed = _tabs.keys();

    if (lUsed.contains(protoId) && lUsed.count() != count())
    {
        _tabs.clear();
        for (int idx = 0; idx < count(); idx++) {
            TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(idx));
            _tabs.insert(tabData.protoId(), idx);
        }
        lUsed = _tabs.keys();
    }

    if (protoId <= 0 || lUsed.contains(protoId))
        return;

    QList<int> lFull = _allProtocols;
    int idx = (int) lFull.indexOf(protoId);
    if (idx < 0)
        return;

    QList<int> part = lFull.mid(0, idx);
    int insertAt = 0;
    if (part.count() > 0) {
        for (int cnt = idx - 1; cnt >= 0; cnt--) {
            if (lUsed.contains(part[cnt]) && part[cnt] != protoId) {
                insertAt = (int) lUsed.indexOf(part[cnt]) + 1;
                break;
            }
        }
    }

    QTreeView * tree = createTree(protoId);
    QString tableName = proto_get_protocol_short_name(find_protocol_by_id(protoId));
    TabData tabData(tableName, protoId);
    QVariant storage;
    storage.setValue(tabData);
    if (tree->model()->rowCount() > 0)
        tableName += QString(" %1 %2").arg(UTF8_MIDDLE_DOT).arg(tree->model()->rowCount());

    int tabId = -1;
    if (insertAt > -1)
        tabId = insertTab(insertAt, tree, tableName);
    else
        tabId = addTab(tree, tableName);
    if (tabId >= 0)
        tabBar()->setTabData(tabId, storage);

    // Identify the last known opened tab
    int lastOpened_protoId = -1;
    GList *selected_tab = g_list_first(*_recentList);
    if (selected_tab != nullptr) {
        lastOpened_protoId = proto_get_id_by_short_name((const char *)selected_tab->data);
    }

    /* We reset the correct tab idxs. That operations is costly, but it is only
     * called during this operation and ensures, that other operations do not
     * need to iterate, but rather can lookup the indeces. */
    _tabs.clear();
    for (int idx = 0; idx < count(); idx++) {
        TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(idx));
        _tabs.insert(tabData.protoId(), idx);
    }

    // Restore the last known opened tab
    if(lastOpened_protoId == protoId) {
        setCurrentIndex(tabId);
    }

    if (emitSignals) {
        emit tabsChanged(_tabs.keys());
        emit retapRequired();
    }
}

void TrafficTab::removeProtoTab(int protoId, bool emitSignals)
{
    if (_tabs.keys().contains(protoId)) {
        for(int idx = 0; idx < count(); idx++) {
            TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(idx));
            if (protoId == tabData.protoId()) {
                removeTab(idx);
                break;
            }
        }
    }

    /* We reset the correct tab idxs. That operations is costly, but it is only
    * called during this operation and ensures, that other operations do not
    * need to iterate, but rather can lookup the indeces. */
    _tabs.clear();
    for (int idx = 0; idx < count(); idx++) {
        TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(idx));
        _tabs.insert(tabData.protoId(), idx);
    }

    if (emitSignals) {
        emit tabsChanged(_tabs.keys());
        emit retapRequired();
    }
}

void TrafficTab::doCurrentIndexChange(const QModelIndex & cur, const QModelIndex &)
{
    if (! cur.isValid())
        return;

    const TrafficDataFilterProxy * proxy = qobject_cast<const TrafficDataFilterProxy *>(cur.model());
    if (! proxy)
        return;

    ATapDataModel * model = qobject_cast<ATapDataModel *>(proxy->sourceModel());
    if (! model)
        return;

    int tabId = _tabs[model->protoId()];
    emit tabDataChanged(tabId);
}

QVariant TrafficTab::currentItemData(int role)
{
    QTreeView * tree = qobject_cast<QTreeView *>(currentWidget());
    if (tree) {
        QModelIndex idx = tree->selectionModel()->currentIndex();
        /* In case no selection has been made yet, we select the topmostleft index,
         * to ensure proper handling. Especially ConversationDialog depends on this
         * method always returning data */
        if (!idx.isValid()) {
            TrafficDataFilterProxy * model = modelForTabIndex(currentIndex());
            idx = model->index(0, 0);
        }
        return idx.data(role);
    }

    return QVariant();
}

void TrafficTab::modelReset()
{
    if (! qobject_cast<TrafficDataFilterProxy *>(sender()))
        return;

    TrafficDataFilterProxy * qsfpm = qobject_cast<TrafficDataFilterProxy *>(sender());
    if (!qsfpm || ! qobject_cast<ATapDataModel *>(qsfpm->sourceModel()))
        return;

    ATapDataModel * atdm = qobject_cast<ATapDataModel *>(qsfpm->sourceModel());
    int protoId = atdm->protoId();
    if (!_tabs.keys().contains(protoId))
        return;

    int tabIdx = _tabs[protoId];
    TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(tabIdx));

    if (tabData.protoId() == protoId) {
        if (qsfpm->rowCount() == 0)
            setTabText(tabIdx, tabData.name());
        else
            setTabText(tabIdx, tabData.name() + QString(" %1 %2").arg(UTF8_MIDDLE_DOT).arg(qsfpm->rowCount()));
    }

    emit tabDataChanged(tabIdx);
}

TrafficDataFilterProxy * TrafficTab::modelForTabIndex(int tabIdx)
{
    if (tabIdx == -1)
        tabIdx = currentIndex();

    return modelForWidget(widget(tabIdx));
}

TrafficDataFilterProxy * TrafficTab::modelForWidget(QWidget * searchWidget)
{
    if (qobject_cast<QTreeView *>(searchWidget)) {
        QTreeView * tree = qobject_cast<QTreeView *>(searchWidget);
        if (qobject_cast<TrafficDataFilterProxy *>(tree->model())) {
            return qobject_cast<TrafficDataFilterProxy *>(tree->model());
        }
    }

    return nullptr;
}

ATapDataModel * TrafficTab::dataModelForTabIndex(int tabIdx)
{
    if (tabIdx == -1)
        tabIdx = currentIndex();

    return dataModelForWidget(widget(tabIdx));
}

ATapDataModel * TrafficTab::dataModelForWidget(QWidget * searchWidget)
{
    TrafficDataFilterProxy * qsfpm = modelForWidget(searchWidget);
    if (qsfpm && qobject_cast<ATapDataModel *>(qsfpm->sourceModel())) {
        return qobject_cast<ATapDataModel *>(qsfpm->sourceModel());
    }
    return nullptr;
}

void TrafficTab::setFilter(QString filter)
{
    for (int idx = 0; idx < count(); idx++ )
    {
        ATapDataModel * atdm = dataModelForTabIndex(idx);
        if (! atdm)
            continue;
        atdm->setFilter(filter);
    }
}

void TrafficTab::setNameResolution(bool checked)
{
    if (checked == _nameResolution)
        return;

    for (int idx = 0; idx < count(); idx++ )
    {
        ATapDataModel * atdm = dataModelForTabIndex(idx);
        if (! atdm)
            continue;
        atdm->setResolveNames(checked);

    }

    _nameResolution = checked;

    /* Send the signal, that all tabs have potentially changed */
    emit tabDataChanged(-1);
}

bool TrafficTab::hasNameResolution(int tabIdx)
{
    int tab = tabIdx == -1 || tabIdx >= count() ? currentIndex() : tabIdx;
    ATapDataModel * dataModel = dataModelForTabIndex(tab);
    if (! dataModel)
        return false;

    return dataModel->allowsNameResolution();
}

QMenu * TrafficTab::createCopyMenu(QWidget *parent)
{
    TrafficTree * tree = qobject_cast<TrafficTree *>(currentWidget());
    if ( ! tree)
        return nullptr;

    return tree->createCopyMenu(parent);
}

#ifdef HAVE_MAXMINDDB
bool TrafficTab::hasGeoIPData(int tabIdx)
{
    int tab = tabIdx == -1 || tabIdx >= count() ? currentIndex() : tabIdx;

    ATapDataModel * dataModel = dataModelForTabIndex(tab);
    return dataModel->hasGeoIPData();
}

bool
TrafficTab::writeGeoIPMapFile(QFile * fp, bool json_only, TrafficDataFilterProxy * model)
{
    QTextStream out(fp);

    if (!json_only) {
        QFile ipmap(get_datafile_path("ipmap.html"));

        if (!ipmap.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, tr("Map file error"), tr("Could not open base file %1 for reading: %2")
                .arg(get_datafile_path("ipmap.html"))
                .arg(g_strerror(errno))
            );
            return false;
        }

        /* Copy ipmap.html to map file. */
        QTextStream in(&ipmap);
        QString line;
        while (in.readLineInto(&line)) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
            out << line << Qt::endl;
#else
            out << line << endl;
#endif
        }

        out << QString("<script id=\"ipmap-data\" type=\"application/json\">\n");
    }

    /*
     * Writes a feature for each resolved address, the output will look like:
     *  {
     *    "type": "FeatureCollection",
     *    "features": [
     *      {
     *        "type": "Feature",
     *        "geometry": {
     *          "type": "Point",
     *          "coordinates": [ -97.821999, 37.750999 ]
     *        },
     *        "properties": {
     *          "ip": "8.8.4.4",
     *          "autonomous_system_number": 15169,
     *          "autonomous_system_organization": "Google LLC",
     *          "city": "(omitted, but key is shown for documentation reasons)",
     *          "country": "United States",
     *          "radius": 1000,
     *          "packets": 1,
     *          "bytes": 1543
     *        }
     *      }
     *    ]
     *  }
     */

    QJsonObject root;
    root["type"] = "FeatureCollection";
    QJsonArray features;

    /* Append map data. */
    for(int row = 0; row < model->rowCount(QModelIndex()); row++)
    {
        QModelIndex index = model->mapToSource(model->index(row, 0));
        ATapDataModel *dataModel = qobject_cast<ATapDataModel *>(model->sourceModel());
        const mmdb_lookup_t * result = VariantPointer<const mmdb_lookup_t>::asPtr(dataModel->data(index, ATapDataModel::GEODATA_LOOKUPTABLE));

        if (!maxmind_db_has_coords(result)) {
            // result could be NULL if the caller did not trigger a lookup
            // before. result->found could be false if no MMDB entry exists.
            continue;
        }

        QJsonObject arrEntry;
        arrEntry["type"] = "Feature";
        QJsonObject geometry;
        geometry["type"] = "Point";
        QJsonArray coordinates;
        coordinates.append(QJsonValue(result->longitude));
        coordinates.append(QJsonValue(result->latitude));
        geometry["coordinates"] = coordinates;
        arrEntry["geometry"] = geometry;

        QJsonObject property;
        property["ip"] = dataModel->data(index, ATapDataModel::GEODATA_ADDRESS).toString();
        if (result->as_number && result->as_org) {
            property["autonomous_system_number"] = QJsonValue((int)(result->as_number));
            property["autonomous_system_organization"] = QJsonValue(result->as_org);
        }

        if (result->city)
            property["city"] = result->city;
        if (result->country)
            property["country"] = result->country;
        if (result->accuracy)
            property["radius"] = QJsonValue(result->accuracy);

        if (qobject_cast<EndpointDataModel *>(dataModel)) {
            EndpointDataModel * endpointModel = qobject_cast<EndpointDataModel *>(dataModel);
            property["packets"] = endpointModel->data(index.siblingAtColumn(EndpointDataModel::ENDP_COLUMN_PACKETS)).toString();
            property["bytes"] = endpointModel->data(index.siblingAtColumn(EndpointDataModel::ENDP_COLUMN_BYTES)).toString();
        }
        arrEntry["properties"] = property;
        features.append(arrEntry);
    }
    root["features"] = features;
    QJsonDocument doc;
    doc.setObject(root);

    out << doc.toJson();

    if (!json_only)
        out << QString("</script>\n");

    out.flush();

    return true;
}

QUrl TrafficTab::createGeoIPMap(bool json_only, int tabIdx)
{
    int tab = tabIdx == -1 || tabIdx >= count() ? currentIndex() : tabIdx;
    ATapDataModel * dataModel = dataModelForTabIndex(tab);
    if (! (dataModel && dataModel->hasGeoIPData())) {
        QMessageBox::warning(this, tr("Map file error"), tr("No endpoints available to map"));
        return QUrl();
    }

    QString tempname = QString("%1/ipmapXXXXXX.html").arg(QDir::tempPath());
    QTemporaryFile tf(tempname);
    if (!tf.open()) {
        QMessageBox::warning(this, tr("Map file error"), tr("Unable to create temporary file"));
        return QUrl();
    }

    if (!writeGeoIPMapFile(&tf, json_only, modelForTabIndex(tab))) {
        tf.close();
        return QUrl();
    }

    tf.setAutoRemove(false);
    return QUrl::fromLocalFile(tf.fileName());
}
#endif

void TrafficTab::detachTab(int tabIdx, QPoint pos) {
    ATapDataModel * model = dataModelForTabIndex(tabIdx);
    if (!model)
        return;

    TrafficTree * tree = qobject_cast<TrafficTree *>(widget(tabIdx));
    if (!tree)
        return;

    connect(this, &TrafficTab::disablingTaps ,tree , &TrafficTree::disableTap);
    DetachableTabWidget::detachTab(tabIdx, pos);

    removeProtoTab(model->protoId());
}

void TrafficTab::attachTab(QWidget * content, QString name)
{
    ATapDataModel * model = dataModelForWidget(content);
    if (!model) {
        attachTab(content, name);
        return;
    }

    insertProtoTab(model->protoId());
}
