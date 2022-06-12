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
#include <wsutil/str_util.h>

#include "ui/recent.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/main_application.h>
#include <ui/qt/main_window.h>
#include <ui/qt/filter_action.h>
#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/traffic_tree.h>

#include <QVector>
#include <QStringList>
#include <QTreeView>
#include <QList>
#include <QMap>
#include <QMenu>
#include <QSortFilterProxyModel>
#include <QTextStream>
#include <QClipboard>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>

TrafficTree::TrafficTree(QString baseName, QWidget *parent) :
    QTreeView(parent)
{
    _tapEnabled = true;
    _saveRaw = true;
    _baseName = baseName;
    _exportRole = ATapDataModel::UNFORMATTED_DISPLAYDATA;

    setAlternatingRowColors(true);
    setRootIsDecorated(false);
    setSortingEnabled(true);
    setContextMenuPolicy(Qt::CustomContextMenu);
    
    connect(this, &QTreeView::customContextMenuRequested, this, &TrafficTree::customContextMenu);
}

void TrafficTree::tapListenerEnabled(bool enable)
{
    _tapEnabled = enable;
}

ATapDataModel * TrafficTree::dataModel()
{
    QSortFilterProxyModel * proxy = qobject_cast<QSortFilterProxyModel *>(model());
    if (proxy)
        return qobject_cast<ATapDataModel *>(proxy->sourceModel());
    return nullptr;
}

void TrafficTree::customContextMenu(const QPoint &pos)
{
    if (sender() != this)
        return;

    QMenu ctxMenu;
    bool isConv = false;

    QModelIndex idx = indexAt(pos);
    ConversationDataModel * model = qobject_cast<ConversationDataModel *>(dataModel());
    if (model)
        isConv = true;

    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionApply, idx, isConv));
    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionPrepare, idx, isConv));
    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionFind, idx, isConv));
    ctxMenu.addMenu(createActionSubMenu(FilterAction::ActionColorize, idx, isConv));

    ctxMenu.addSeparator();
    ctxMenu.addMenu(createCopyMenu());

    ctxMenu.addSeparator();
    QAction * act = ctxMenu.addAction(tr("Resize all columns to content"));
    connect(act, &QAction::triggered, this, &TrafficTree::resizeAction);

    ctxMenu.exec(mapToGlobal(pos));
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

QMenu * TrafficTree::createActionSubMenu(FilterAction::Action cur_action, QModelIndex idx, bool isConversation)
{
    initDirection();

    conv_item_t * conv_item = nullptr;
    if (isConversation)
    {
        ConversationDataModel * model = qobject_cast<ConversationDataModel *>(dataModel());
        if (model)
            conv_item = model->itemForRow(idx.row());
    }

    QMenu * subMenu = new QMenu(FilterAction::actionName(cur_action));
    subMenu->setEnabled(_tapEnabled);
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        if (isConversation && conv_item) {
            QMenu *subsubmenu = subMenu->addMenu(FilterAction::actionTypeName(at));
            foreach (FilterAction::ActionDirection ad, FilterAction::actionDirections()) {
                FilterAction *fa = new FilterAction(subsubmenu, cur_action, at, ad);
                QString filter = get_conversation_filter(conv_item, (conv_direction_e) fad_to_cd_[fa->actionDirection()]);
                fa->setProperty("filter", filter);
                subsubmenu->addAction(fa);
                connect(fa, &QAction::triggered, this, &TrafficTree::useFilterAction);
            }
        } else {
            FilterAction *fa = new FilterAction(subMenu, cur_action, at);
            fa->setProperty("filter", idx.data(ATapDataModel::DISPLAY_FILTER));
            subMenu->addAction(fa);

            connect(fa, &QAction::triggered, this, &TrafficTree::useFilterAction);
        }
    }

    return subMenu;
}

QMenu * TrafficTree::createCopyMenu(QWidget *parent)
{
    QMenu *copy_menu = new QMenu(tr("Copy %1 table").arg(_baseName), parent);
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in CSV (Comma Separated Values) format."));
    ca->setProperty("copy_as", TrafficTree::CLIPBOARD_CSV);
    connect(ca, &QAction::triggered, this, &TrafficTree::clipboardAction);
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the YAML data serialization format."));
    ca->setProperty("copy_as", TrafficTree::CLIPBOARD_YAML);
    connect(ca, &QAction::triggered, this, &TrafficTree::clipboardAction);
    ca = copy_menu->addAction(tr("as Json"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the Json data serialization format."));
    ca->setProperty("copy_as", TrafficTree::CLIPBOARD_JSON);
    connect(ca, &QAction::triggered, this, &TrafficTree::clipboardAction);

    copy_menu->addSeparator();
    ca = copy_menu->addAction(tr("Save data as raw"));
    ca->setToolTip(tr("Disable data formatting for export/clipboard and save as raw data"));
    ca->setCheckable(true);
    ca->setChecked(_exportRole == ATapDataModel::UNFORMATTED_DISPLAYDATA);
    connect(ca, &QAction::triggered, this, &TrafficTree::toggleSaveRawAction);

    return copy_menu;
}

void TrafficTree::useFilterAction()
{
    FilterAction *fa = qobject_cast<FilterAction *>(sender());
    if (!fa || !_tapEnabled)
        return;

    QString filter = fa->property("filter").toString();
    if (filter.length() > 0)
    {
        MainWindow * mainWin = (MainWindow *)(mainApp->mainWindow());
        mainWin->setDisplayFilter(filter, fa->action(), fa->actionType());
    }
}

void TrafficTree::clipboardAction()
{
    QAction * ca = qobject_cast<QAction *>(sender());
    if (ca && ca->property("copy_as").isValid())
        copyToClipboard((eTrafficTreeClipboard)ca->property("copy_as").toInt());
}

void TrafficTree::resizeAction()
{
    for (int col = 0; col < model()->columnCount(); col++)
        resizeColumnToContents(col);
}

void TrafficTree::toggleSaveRawAction()
{
    if (_exportRole == ATapDataModel::UNFORMATTED_DISPLAYDATA)
        _exportRole = Qt::DisplayRole;
    else
        _exportRole = ATapDataModel::UNFORMATTED_DISPLAYDATA;
}

void TrafficTree::copyToClipboard(eTrafficTreeClipboard type)
{
    ATapDataModel * model = dataModel();
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

void TrafficTree::disableTap()
{
    ATapDataModel * model = dataModel();
    if (!model)
        return;
    model->disableTap();
}
