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

#include "ui/recent.h"

#include <ui/qt/widgets/traffic_tab.h>
#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/main_application.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/filter_action.h>

#include <QVector>
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

static gboolean iterateProtocols(const void *key, void *value, void *userdata)
{
    QMap<int, QString> *protocols = (QMap<int, QString> *)userdata;
    register_ct_t* ct = (register_ct_t*)value;
    const QString title = (const gchar*)key;
    int proto_id = get_conversation_proto_id(ct);
    protocols->insert(proto_id, title);

    return FALSE;
}

TrafficTab::TrafficTab(QWidget * parent) :
    QTabWidget(parent)
{
    _createModel = nullptr;
    _disableTaps = false;
    _nameResolution = false;
    _tableName = QString();
    _cliId = 0;
    _saveRaw = true;
    _exportRole = ATapDataModel::UNFORMATTED_DISPLAYDATA;
    _recentList = nullptr;
}

TrafficTab::~TrafficTab()
{
    prefs_clear_string_list(*_recentList);
    *_recentList = NULL;

    QVector<int> protocols = selectedProtocols();
    foreach (int protoId, protocols)
    {
        char *title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(protoId)));
        *_recentList = g_list_append(*_recentList, title);
    }
}

void TrafficTab::setProtocolInfo(QString tableName, GList ** recentList, ATapModelCallback createModel)
{
    _tableName = tableName;
    _recentList = recentList;
    if (createModel)
        _createModel = createModel;

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

    QWidget * container = new QWidget(this);
    container->setFixedHeight(tabBar()->height());
    container->setSizePolicy(QSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed));

    QHBoxLayout * layout = new QHBoxLayout(container);
    layout->setContentsMargins(1, 0, 1, 0);
   
    QPushButton * cornerButton = new QPushButton(tr("%1 Types").arg(tableName));
    cornerButton->setFixedHeight(tabBar()->height());
    cornerButton->setSizePolicy(QSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed));
    QMenu * cornerMenu = new QMenu();
    conversation_table_iterate_tables(iterateProtocols, &_allTaps);
    foreach (int protoId, _allTaps.keys())
    {
        QAction * endPoint = new QAction(_allTaps[protoId], this);
        endPoint->setProperty("protocol", QVariant::fromValue(protoId));
        endPoint->setCheckable(true);
        endPoint->setChecked(_protocols.contains(protoId));
        connect(endPoint, &QAction::triggered, this, &TrafficTab::toggleTab);
        cornerMenu->addAction(endPoint);
    }
    cornerButton->setMenu(cornerMenu);

    layout->addWidget(cornerButton);
    setCornerWidget(container, Qt::TopRightCorner);

    updateTabs();
}

void TrafficTab::toggleTab(bool checked)
{
    QAction * orig = qobject_cast<QAction *>(sender());
    if (!orig || ! orig->property("protocol").isValid())
        return;

    int protocol = orig->property("protocol").toInt();
    if (!checked && _protocols.contains(protocol))
        _protocols.removeAll(protocol);
    else if (checked && ! _protocols.contains(protocol))
        _protocols.append(protocol);

    updateTabs();
}

void TrafficTab::setFirstTab(int cliId)
{
    _cliId = cliId;

    // Bring the command-line specified type to the front.
    if ((_cliId > 0) && (get_conversation_by_proto_id(_cliId))) {
        _protocols.removeAll(_cliId);
        _protocols.prepend(_cliId);
    }

    updateTabs();
}

void TrafficTab::setDelegate(int column, ATapCreateDelegate createDelegate)
{
    if (! createDelegate || column < 0)
        return;

    if (_createDelegates.keys().contains(column))
        _createDelegates.remove(column);
    _createDelegates.insert(column, createDelegate);


    for (int idx = 0; idx < count(); idx++) {
        int setColumn = column;
        ATapDataModel * model = modelForTabIndex(idx);
        if (model->portsAreHidden()) {
            if (model->modelType() == ATapDataModel::DATAMODEL_ENDPOINT && column > EndpointDataModel::ENDP_COLUMN_PORT)
                setColumn -= 1;
            else if (model->modelType() == ATapDataModel::DATAMODEL_CONVERSATION && column > ConversationDataModel::CONV_COLUMN_DST_PORT)
                setColumn -= 2;
        }
        if (qobject_cast<QTreeView *>(widget(idx)))
        {
            QTreeView * tree = qobject_cast<QTreeView *>(widget(idx));
            tree->setItemDelegateForColumn(setColumn, createDelegate(tree));
        }
    }
}

QTreeView * TrafficTab::createTree(int protoId)
{
    QTreeView * tree = new QTreeView(this);
    if (_createModel) {
        ATapDataModel * model = _createModel(protoId, "");
        model->enableTap();
        tree->setAlternatingRowColors(true);
        tree->setRootIsDecorated(false);
        tree->setSortingEnabled(true);

        foreach(int col, _createDelegates.keys())
        {
            if (_createDelegates[col])
            {
                ATapCreateDelegate creator = _createDelegates[col];
                tree->setItemDelegateForColumn(col, creator(tree));
            }
        }

        tree->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(tree, &QTreeView::customContextMenuRequested, this, &TrafficTab::customContextMenuRequested);
        QSortFilterProxyModel * proxyModel = new QSortFilterProxyModel();
        proxyModel->setSourceModel(model);
        tree->setModel(proxyModel);

        QItemSelectionModel * ism = new QItemSelectionModel(proxyModel, tree);
        tree->setSelectionModel(ism);
        connect(ism, &QItemSelectionModel::currentChanged, this, &TrafficTab::doCurrentIndexChange);

        tree->sortByColumn(0, Qt::AscendingOrder);

        connect(proxyModel, &QSortFilterProxyModel::modelReset, this, [tree]() {
            if (tree->model()->rowCount() > 0) {
                for (int col = 0; col < tree->model()->columnCount(); col++)
                    tree->resizeColumnToContents(col);
            }
        });
        connect(proxyModel, &QSortFilterProxyModel::modelReset, this, &TrafficTab::modelReset);
    }

    return tree;
}

QVector<int> TrafficTab::selectedProtocols() const
{
    QVector<int> result = QVector<int>::fromList(_tabs.keys());
    return result;
}

void TrafficTab::useAbsoluteTime(bool absolute)
{
    for(int idx = 0; idx < count(); idx++)
    {
        ATapDataModel * atdm = modelForTabIndex(idx);
        if (atdm)
            atdm->useAbsoluteTime(absolute);
    }
}

void TrafficTab::useNanosecondTimestamps(bool nanoseconds)
{
    for(int idx = 0; idx < count(); idx++)
    {
        ATapDataModel * atdm = modelForTabIndex(idx);
        if (atdm)
            atdm->useNanosecondTimestamps(nanoseconds);
    }
}

void TrafficTab::disableTap()
{
    for(int idx = 0; idx < count(); idx++)
    {
        ATapDataModel * atdm = modelForTabIndex(idx);
        if (atdm)
            atdm->disableTap();
    }

    _disableTaps = true;
    cornerWidget()->setEnabled(false);
}

void TrafficTab::updateTabs()
{
    QList<int> keys = _tabs.keys();

    /* Adding new Tabs */
    foreach (int proto, _protocols) {
        if (!keys.contains(proto)) {
            QTreeView * tree = createTree(proto);
            QString tableName = proto_get_protocol_short_name(find_protocol_by_id(proto));
            TabData tabData(tableName, proto);
            QVariant storage;
            storage.setValue(tabData);
            if (tree->model()->rowCount() > 0)
                tableName += QString(" %1 %2").arg(UTF8_MIDDLE_DOT).arg(tree->model()->rowCount());

            int tabId = addTab(tree, tableName);
            tabBar()->setTabData(tabId, storage);
        }
    }

    /* Removing tabs no longer required */
    foreach(int key, keys)
    {
        if ( _protocols.contains(key))
            keys.removeAll(key);
    }

    /* Counting down, otherwise removing a tab will shift the indeces */
    for(int idx = count(); idx > 0; idx--) {
        TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(idx - 1));
        if (keys.contains(tabData.protoId()))
            removeTab(idx - 1);
    }

    /* We reset the correct tab idxs. That operations is costly, but it is only
     * called during this operation and ensures, that other operations do not
     * need to iterate, but rather can lookup the indeces. */
    _tabs.clear();
    for (int idx = 0; idx < count(); idx++) {
        TabData tabData = qvariant_cast<TabData>(tabBar()->tabData(idx));
        _tabs.insert(tabData.protoId(), idx);
    }
}

void TrafficTab::doCurrentIndexChange(const QModelIndex & cur, const QModelIndex &)
{
    if (! cur.isValid())
        return;

    const QSortFilterProxyModel * proxy = qobject_cast<const QSortFilterProxyModel *>(cur.model());
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
            ATapDataModel * model = modelForTabIndex(currentIndex());
            idx = model->index(0, 0);
        }
        return idx.data(role);
    }

    return QVariant();
}

void TrafficTab::modelReset()
{
    if (! qobject_cast<QSortFilterProxyModel *>(sender()))
        return;

    QSortFilterProxyModel * qsfpm = qobject_cast<QSortFilterProxyModel *>(sender());
    if (! qobject_cast<ATapDataModel *>(qsfpm->sourceModel()))
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

ATapDataModel * TrafficTab::modelForTabIndex(int tabIdx)
{
    if (tabIdx == -1)
        tabIdx = currentIndex();

    if (qobject_cast<QTreeView *>(widget(tabIdx))) {
        QTreeView * tree = qobject_cast<QTreeView *>(widget(tabIdx));
        if (qobject_cast<QSortFilterProxyModel *>(tree->model())) {
            QSortFilterProxyModel * qsfpm = qobject_cast<QSortFilterProxyModel *>(tree->model());
            if (qobject_cast<ATapDataModel *>(qsfpm->sourceModel())) {
                return qobject_cast<ATapDataModel *>(qsfpm->sourceModel());
            }
        }
    }

    return nullptr;
}

void TrafficTab::setFilter(QString filter)
{
    for (int idx = 0; idx < count(); idx++ )
    {
        ATapDataModel * atdm = modelForTabIndex(idx);
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
        ATapDataModel * atdm = modelForTabIndex(idx);
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
    ATapDataModel * dataModel = modelForTabIndex(tab);
    if (! dataModel)
        return false;

    return dataModel->allowsNameResolution();
}

static QMap<FilterAction::ActionDirection, int> fad_to_cd_;

static void initDirection()
{
    if (fad_to_cd_.count() == 0) {
        fad_to_cd_[FilterAction::ActionDirectionAToFromB] = CONV_DIR_A_TO_FROM_B;
        fad_to_cd_[FilterAction::ActionDirectionAToB] = CONV_DIR_A_TO_B;
        fad_to_cd_[FilterAction::ActionDirectionAFromB] = CONV_DIR_A_FROM_B;
        fad_to_cd_[FilterAction::ActionDirectionAToFromAny] = CONV_DIR_A_TO_FROM_ANY;
        fad_to_cd_[FilterAction::ActionDirectionAToAny] = CONV_DIR_A_TO_ANY;
        fad_to_cd_[FilterAction::ActionDirectionAFromAny] = CONV_DIR_A_FROM_ANY;
        fad_to_cd_[FilterAction::ActionDirectionAnyToFromB] = CONV_DIR_ANY_TO_FROM_B;
        fad_to_cd_[FilterAction::ActionDirectionAnyToB] = CONV_DIR_ANY_TO_B;
        fad_to_cd_[FilterAction::ActionDirectionAnyFromB] = CONV_DIR_ANY_FROM_B;
    }
}

QMenu * TrafficTab::createActionSubMenu(FilterAction::Action cur_action, QModelIndex idx, bool isConversation)
{
    initDirection();

    conv_item_t * conv_item = nullptr;
    if (isConversation)
    {
        ConversationDataModel * model = qobject_cast<ConversationDataModel *>(modelForTabIndex());
        if (model)
            conv_item = model->itemForRow(idx.row());
    }

    QMenu * subMenu = new QMenu(FilterAction::actionName(cur_action));
    subMenu->setEnabled(!_disableTaps);
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        if (isConversation && conv_item) {
            QMenu *subsubmenu = subMenu->addMenu(FilterAction::actionTypeName(at));
            subsubmenu->setEnabled(!_disableTaps);
            foreach (FilterAction::ActionDirection ad, FilterAction::actionDirections()) {
                FilterAction *fa = new FilterAction(subsubmenu, cur_action, at, ad);
                fa->setEnabled(!_disableTaps);
                QString filter = get_conversation_filter(conv_item, (conv_direction_e) fad_to_cd_[fa->actionDirection()]);
                fa->setProperty("filter", filter);
                subsubmenu->addAction(fa);
                connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
            }
        } else {
            FilterAction *fa = new FilterAction(subMenu, cur_action, at);
            fa->setEnabled(!_disableTaps);
            fa->setProperty("filter", idx.data(ATapDataModel::DISPLAY_FILTER));
            subMenu->addAction(fa);

            connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
        }
    }

    return subMenu;
}

void TrafficTab::customContextMenuRequested(const QPoint &pos)
{
    if (! qobject_cast<QTreeView *>(sender()))
        return;

    QTreeView * tree = qobject_cast<QTreeView *>(sender());
    QModelIndex idx = tree->indexAt(pos);

    QMenu ctxMenu;

    bool isConv = false;
    QSortFilterProxyModel * proxy = qobject_cast<QSortFilterProxyModel *>(tree->model());
    if (proxy) {
        ConversationDataModel * model = qobject_cast<ConversationDataModel *>(proxy->sourceModel());
        if (model)
            isConv = true;
    }

    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionApply, idx, isConv));
    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionPrepare, idx, isConv));
    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionFind, idx, isConv));
    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionColorize, idx, isConv));

    ctxMenu.addSeparator();
    ctxMenu.addMenu(createCopyMenu());

    ctxMenu.addSeparator();
    QAction * act = ctxMenu.addAction(tr("Resize all columns to content"));
    connect(act, &QAction::triggered, [tree]() {
        for (int col = 0; col < tree->model()->columnCount(); col++)
            tree->resizeColumnToContents(col);
    });

    ctxMenu.exec(tree->mapToGlobal(pos));
}

void TrafficTab::filterActionTriggered()
{
    FilterAction *fa = qobject_cast<FilterAction *>(sender());
    if (!fa)
        return;

    QString filter = fa->property("filter").toString();
    if (filter.length() > 0)
        emit filterAction(filter, fa->action(), fa->actionType());
}

QMenu * TrafficTab::createCopyMenu(QWidget *parent)
{
    QMenu *copy_menu = new QMenu(tr("Copy %1 table").arg(_tableName), parent);
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in CSV (Comma Separated Values) format."));
    ca->setProperty("copy_as", TrafficTab::CLIPBOARD_CSV);
    connect(ca, &QAction::triggered, this, &TrafficTab::clipboardAction);
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the YAML data serialization format."));
    ca->setProperty("copy_as", TrafficTab::CLIPBOARD_YAML);
    connect(ca, &QAction::triggered, this, &TrafficTab::clipboardAction);
    ca = copy_menu->addAction(tr("as Json"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the Json data serialization format."));
    ca->setProperty("copy_as", TrafficTab::CLIPBOARD_JSON);
    connect(ca, &QAction::triggered, this, &TrafficTab::clipboardAction);

    copy_menu->addSeparator();
    ca = copy_menu->addAction(tr("Save data as raw"));
    ca->setToolTip(tr("Disable data formatting for export/clipboard and save as raw data"));
    ca->setCheckable(true);
    ca->setChecked(_exportRole == ATapDataModel::UNFORMATTED_DISPLAYDATA);
    connect(ca, &QAction::triggered, this, &TrafficTab::toggleSaveRaw);

    return copy_menu;
}

void TrafficTab::toggleSaveRaw()
{
    if (_exportRole == ATapDataModel::UNFORMATTED_DISPLAYDATA)
        _exportRole = Qt::DisplayRole;
    else
        _exportRole = ATapDataModel::UNFORMATTED_DISPLAYDATA;
}

void TrafficTab::clipboardAction()
{
    QAction * ca = qobject_cast<QAction *>(sender());
    if (ca && ca->property("copy_as").isValid())
        copyToClipboard((eTrafficTabClipboard)ca->property("copy_as").toInt());
}

void TrafficTab::copyToClipboard(eTrafficTabClipboard type, int tabIdx)
{
    int idx = tabIdx < 0 || tabIdx >= count() ? currentIndex() : tabIdx;

    QSortFilterProxyModel * model = nullptr;
    if (qobject_cast<QTreeView *>(widget(idx))) {
        QTreeView * tree = qobject_cast<QTreeView *>(widget(idx));
        if (qobject_cast<QSortFilterProxyModel *>(tree->model())) {
            model = qobject_cast<QSortFilterProxyModel *>(tree->model());
        }
    }
    if (!model)
        return;

    QString clipText;
    QTextStream stream(&clipText, QIODevice::Text);

    if (type == CLIPBOARD_CSV) {
        for (int row = 0; row < model->rowCount(); row++) {
            QStringList rdsl;
            for (int col = 0; col < model->columnCount(); col++) {
                QModelIndex idx = model->index(row, col);
                QVariant v = model->data(idx, _exportRole);
                if (!v.isValid()) {
                    rdsl << "\"\"";
                } else if (v.userType() == QMetaType::QString) {
                    rdsl << QString("\"%1\"").arg(v.toString());
                } else {
                    rdsl << v.toString();
                }
            }
            stream << rdsl.join(",") << '\n';
        }
    } else if (type == CLIPBOARD_YAML) {
        stream << "---" << '\n';
        for (int row = 0; row < model->rowCount(); row++) {
            stream << "-" << '\n';
            for (int col = 0; col < model->columnCount(); col++) {
                QModelIndex idx = model->index(row, col);
                QVariant v = model->data(idx, _exportRole);
                stream << " - " << v.toString() << '\n';
            }
        }
    } else if (type == CLIPBOARD_JSON) {
        QMap<int, QString> headers;
        for (int cnt = 0; cnt < model->columnCount(); cnt++)
            headers.insert(cnt, model->headerData(cnt, Qt::Horizontal, Qt::DisplayRole).toString());

        QJsonArray records;

        for (int row = 0; row < model->rowCount(); row++) {
            QJsonObject rowData;
            foreach(int col, headers.keys()) {
                QModelIndex idx = model->index(row, col);
                rowData.insert(headers[col], model->data(idx, _exportRole).toString());
            }
            records.push_back(rowData);
        }

        QJsonDocument json;
        json.setArray(records);
        stream << json.toJson();
    }

    mainApp->clipboard()->setText(stream.readAll());
}

#ifdef HAVE_MAXMINDDB
bool TrafficTab::hasGeoIPData(int tabIdx)
{
    int tab = tabIdx == -1 || tabIdx >= count() ? currentIndex() : tabIdx;

    ATapDataModel * dataModel = modelForTabIndex(tab);
    return dataModel->hasGeoIPData();
}

bool
TrafficTab::writeGeoIPMapFile(QFile * fp, bool json_only, ATapDataModel * dataModel)
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
    for(int row = 0; row < dataModel->rowCount(QModelIndex()); row++)
    {
        QModelIndex index = dataModel->index(row, 0);
        const mmdb_lookup_t * result = VariantPointer<const mmdb_lookup_t>::asPtr(dataModel->data(index, ATapDataModel::GEODATA_LOOKUPTABLE));

        if (!maxmind_db_has_coords(result)) {
            // result could be NULL if the caller did not trigger a lookup
            // before. result->found could be FALSE if no MMDB entry exists.
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
            property["packets"] = endpointModel->data(endpointModel->index(row, EndpointDataModel::ENDP_COLUMN_PACKETS)).toString();
            property["bytes"] = endpointModel->data(endpointModel->index(row, EndpointDataModel::ENDP_COLUMN_BYTES)).toString();
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
    ATapDataModel * dataModel = modelForTabIndex(tab);
    if (! dataModel || ! hasGeoIPData(tabIdx)) {
        QMessageBox::warning(this, tr("Map file error"), tr("No endpoints available to map"));
        return QUrl();
    }

    QString tempname = QString("%1/ipmapXXXXXX.html").arg(QDir::tempPath());
    QTemporaryFile tf(tempname);
    if (!tf.open()) {
        QMessageBox::warning(this, tr("Map file error"), tr("Unable to create temporary file"));
        return QUrl();
    }

    if (!writeGeoIPMapFile(&tf, json_only, dataModel)) {
        tf.close();
        return QUrl();
    }

    tf.setAutoRemove(false);
    return QUrl::fromLocalFile(tf.fileName());
}
#endif
