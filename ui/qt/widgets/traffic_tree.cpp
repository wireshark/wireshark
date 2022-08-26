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
#include <ui/qt/widgets/traffic_tab.h>
#include <ui/qt/widgets/traffic_tree.h>

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
#include <QHeaderView>
#include <QWidgetAction>
#include <QLineEdit>
#include <QActionGroup>

MenuEditAction::MenuEditAction(QString text, QString hintText, QObject * parent) :
    QWidgetAction(parent),
    _hintText(hintText),
    _text(text),
    _lineEdit(nullptr)
{}

QWidget * MenuEditAction::createWidget(QWidget *parent) {
    _lineEdit = new QLineEdit(parent);
    _lineEdit->setAlignment(Qt::AlignRight);
    _lineEdit->setText(_text);
    _lineEdit->setPlaceholderText(_hintText);
    connect(_lineEdit, &QLineEdit::returnPressed, this, &MenuEditAction::triggerEntry);
    return _lineEdit;
}

void MenuEditAction::triggerEntry() {
    if (_lineEdit)
        _text = _lineEdit->text();

    emit trigger();
}

QString MenuEditAction::text() const {
    return _text;
}


TrafficTreeHeaderView::TrafficTreeHeaderView(GList ** recentColumnList, QWidget * parent):
    QHeaderView(Qt::Horizontal, parent)
{
    _recentColumnList = recentColumnList;

    setContextMenuPolicy(Qt::CustomContextMenu);

    _actions = new QActionGroup(this);

    QAction * filterAction = _actions->addAction(tr("Less than"));
    filterAction->setCheckable(true);
    filterAction->setChecked(true);
    filterAction->setProperty("filter_action", (int)TrafficDataFilterProxy::TRAFFIC_DATA_LESS);
    filterAction = _actions->addAction(tr("Greater than"));
    filterAction->setCheckable(true);
    filterAction->setProperty("filter_action", (int)TrafficDataFilterProxy::TRAFFIC_DATA_GREATER);
    filterAction = _actions->addAction(tr("Equal"));
    filterAction->setCheckable(true);
    filterAction->setProperty("filter_action", (int)TrafficDataFilterProxy::TRAFFIC_DATA_EQUAL);

    connect(this, &QHeaderView::customContextMenuRequested, this, &TrafficTreeHeaderView::headerContextMenu);
}

TrafficTreeHeaderView::~TrafficTreeHeaderView()
{}

void TrafficTreeHeaderView::headerContextMenu(const QPoint &pos)
{
    TrafficTree * tree = qobject_cast<TrafficTree *>(parent());
    if (!tree)
        return;

    TrafficDataFilterProxy * proxy = qobject_cast<TrafficDataFilterProxy *>(tree->model());
    if (sender() != this || ! proxy)
        return;

    QMenu * ctxMenu = new QMenu(this);
    ctxMenu->setAttribute(Qt::WA_DeleteOnClose);

    QAction * headerAction = ctxMenu->addAction(tr("Columns to display"));
    headerAction->setEnabled(false);

    for (int col = 0; col < tree->dataModel()->columnCount(); col++)
    {
        QString name = tree->dataModel()->headerData(col).toString();
        QAction * action = new QAction(name);
        action->setCheckable(true);
        action->setChecked(proxy->columnVisible(col));
        action->setProperty("col_nr", col);
        ctxMenu->addAction(action);

        connect(action, &QAction::triggered, this, &TrafficTreeHeaderView::columnTriggered);
    }

    ctxMenu->addSeparator();

    int column = logicalIndexAt(pos);

    bool is_address = false;
    QModelIndex sourceIdx = proxy->mapToSource(proxy->index(0, column));
    if (qobject_cast<EndpointDataModel *>(proxy->sourceModel()) && sourceIdx.column() == EndpointDataModel::ENDP_COLUMN_ADDR) {
        is_address = true;
    } else if (qobject_cast<ConversationDataModel *>(proxy->sourceModel()) && (sourceIdx.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR ||
        sourceIdx.column() == ConversationDataModel::CONV_COLUMN_DST_ADDR)) {
        is_address = true;
    }

    if (! is_address) {
        QString columnText = model()->headerData(column, Qt::Horizontal).toString();
        QAction * filterAction = ctxMenu->addAction(tr("Filter %1 by").arg(columnText));
        filterAction->setEnabled(false);
        ctxMenu->addActions(_actions->actions());

        MenuEditAction * editAction = new MenuEditAction(_filterText, tr("Enter filter value"));
        editAction->setProperty("column", column);
        ctxMenu->addAction(editAction);
        connect(editAction, &MenuEditAction::triggered, this, &TrafficTreeHeaderView::filterColumn);
    }

    connect(ctxMenu, &QMenu::triggered, this, &TrafficTreeHeaderView::menuActionTriggered);

    ctxMenu->popup(mapToGlobal(pos));
}

void TrafficTreeHeaderView::applyRecent()
{
    TrafficTree * tree = qobject_cast<TrafficTree *>(parent());
    if (!tree)
        return;

    QList<int> columns;
    for (GList * endTab = *_recentColumnList; endTab; endTab = endTab->next) {
        QString colStr = QString((const char *)endTab->data);
        bool ok = false;
        int col = colStr.toInt(&ok);
        if (ok)
            columns << col;
    }

    if (columns.count() > 0) {
        TrafficDataFilterProxy * proxy = qobject_cast<TrafficDataFilterProxy *>(tree->model());
        for (int col = 0; col < tree->dataModel()->columnCount(); col++) {
            proxy->setColumnVisibility(col, columns.contains(col));
        }
    }
}

void TrafficTreeHeaderView::columnTriggered(bool checked)
{
    TrafficTree * tree = qobject_cast<TrafficTree *>(parent());
    if (!tree)
        return;

    TrafficDataFilterProxy * proxy = qobject_cast<TrafficDataFilterProxy *>(tree->model());
    QAction * entry = qobject_cast<QAction *>(sender());
    if (! proxy || ! entry || ! entry->property("col_nr").isValid())
        return;

    int col = entry->property("col_nr").toInt();
    proxy->setColumnVisibility(col, checked);

    prefs_clear_string_list(*_recentColumnList);
    *_recentColumnList = NULL;

    QList<int> visible;

    for (int col = 0; col < tree->dataModel()->columnCount(); col++) {
        if (proxy->columnVisible(col)) {
            visible << col;
            gchar *nr = qstring_strdup(QString::number(col));
            *_recentColumnList = g_list_append(*_recentColumnList, nr);
        }
    }

    emit columnsHaveChanged(visible);
}

void TrafficTreeHeaderView::menuActionTriggered(QAction * act)
{
    if (_actions && _actions->actions().contains(act)) {
        QMenu * menu = qobject_cast<QMenu *>(sender());
        if (menu) {
            MenuEditAction * menuAction = nullptr;
            foreach(QAction * _act, menu->actions()) {
                if (qobject_cast<MenuEditAction *>(_act)) {
                    menuAction = qobject_cast<MenuEditAction *>(_act);
                    break;
                }
            }

            int column = menuAction ? menuAction->property("column").toInt() : -1;
            if (column >= 0) {
                _filterText = menuAction->text().trimmed();
                if (_filterText.length() == 0)
                    column = -1;
                int filterOn = act->property("filter_action").toInt();

                emit filterOnColumn(column, filterOn, _filterText);
            }
        }
    }
}

void TrafficTreeHeaderView::filterColumn(bool)
{
    MenuEditAction * menuAction = qobject_cast<MenuEditAction *>(sender());
    if (!menuAction)
        return;

    int filterOn = TrafficDataFilterProxy::TRAFFIC_DATA_LESS;
    foreach(QAction * act, _actions->actions()) {
        if (act->isChecked() && act->property("filter_action").isValid()) {
            filterOn = act->property("filter_action").toInt();
            break;
        }
    }

    int column = menuAction->property("column").toInt();
    _filterText = menuAction->text().trimmed();
    if (_filterText.length() == 0)
        column = -1;

    emit filterOnColumn(column, filterOn, _filterText);
}


TrafficDataFilterProxy::TrafficDataFilterProxy(QObject *parent) :
    QSortFilterProxyModel(parent),
    _filterColumn(-1),
    _filterOn(-1),
    _filterText(QString())
{}

void TrafficDataFilterProxy::filterForColumn(int column, int filterOn, QString filterText)
{
    if (filterOn < 0 || filterOn > TrafficDataFilterProxy::TRAFFIC_DATA_EQUAL)
        column = -1;

    _filterColumn = column;
    _filterOn = filterOn;
    _filterText = filterText;
    invalidateFilter();
}

int TrafficDataFilterProxy::mapToSourceColumn(int proxyColumn) const
{
    ATapDataModel * model = qobject_cast<ATapDataModel *>(sourceModel());
    int column = proxyColumn;
    if (model) {

        if (qobject_cast<EndpointDataModel *>(model))
        {
            if (model->portsAreHidden() && column > EndpointDataModel::ENDP_COLUMN_ADDR)
                column++;
            if (! model->showTotalColumn()) {
                if (column > EndpointDataModel::ENDP_COLUMN_BYTES)
                    column+=2;
            }
        } else if (qobject_cast<ConversationDataModel *>(model)) {
            if (model->portsAreHidden()) {
                if (column > ConversationDataModel::CONV_COLUMN_SRC_ADDR)
                    column++;
                if (column > ConversationDataModel::CONV_COLUMN_DST_ADDR)
                    column++;
            }
            ConversationDataModel * convModel = qobject_cast<ConversationDataModel *>(model);
            if (convModel->showConversationId() && column > ConversationDataModel::CONV_COLUMN_BYTES)
                column++;
            if (! model->showTotalColumn()) {
                if (column > ConversationDataModel::CONV_COLUMN_BYTES)
                    column+=2;
            }
        }
    }

    return column;
}

bool TrafficDataFilterProxy::filterAcceptsRow(int source_row, const QModelIndex &source_parent) const
{
    ATapDataModel * dataModel = qobject_cast<ATapDataModel *>(sourceModel());
    if (dataModel) {
        bool isFiltered = dataModel->data(dataModel->index(source_row, 0), ATapDataModel::ROW_IS_FILTERED).toBool();
        if (isFiltered && dataModel->filter().length() > 0)
            return false;

        int sourceColumn = mapToSourceColumn(_filterColumn);
        QModelIndex srcIdx = dataModel->index(source_row, sourceColumn);
        if (srcIdx.isValid()) {
            QVariant data = srcIdx.data(ATapDataModel::UNFORMATTED_DISPLAYDATA);

            bool filtered = false;
            if (_filterOn == TrafficDataFilterProxy::TRAFFIC_DATA_LESS)
                filtered = data.toLongLong() < _filterText.toLongLong();
            else if (_filterOn == TrafficDataFilterProxy::TRAFFIC_DATA_GREATER)
                filtered = data.toLongLong() > _filterText.toLongLong();
            else if (_filterOn == TrafficDataFilterProxy::TRAFFIC_DATA_EQUAL) {
                filtered = data.toLongLong() == _filterText.toLongLong();
            }

            if (!filtered)
                return false;
        }
    }

    return QSortFilterProxyModel::filterAcceptsRow(source_row, source_parent);
}

bool TrafficDataFilterProxy::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    if (! source_left.isValid() || ! qobject_cast<const ATapDataModel *>(source_left.model()))
        return false;
    if (! source_right.isValid() || ! qobject_cast<const ATapDataModel *>(source_right.model()))
        return false;

    ATapDataModel * model = qobject_cast<ATapDataModel *>(sourceModel());

    if (! model || source_left.model() != model || source_right.model() != model)
        return false;

    QVariant datA = source_left.data(ATapDataModel::UNFORMATTED_DISPLAYDATA);
    QVariant datB = source_right.data(ATapDataModel::UNFORMATTED_DISPLAYDATA);

    bool is_address = false;
    if (qobject_cast<EndpointDataModel *>(model) && source_left.column() == EndpointDataModel::ENDP_COLUMN_ADDR &&
        source_left.column() == source_right.column()) {
        is_address = true;
    } else if (qobject_cast<ConversationDataModel *>(model) && (source_left.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR ||
        source_left.column() == ConversationDataModel::CONV_COLUMN_DST_ADDR) && source_left.column() == source_right.column()) {
        is_address = true;
    }

    if (is_address) {
        bool result = false;
        bool identical = false;
        int addressTypeA = model->data(source_left, ATapDataModel::DATA_ADDRESS_TYPE).toInt();
        int addressTypeB = model->data(source_right, ATapDataModel::DATA_ADDRESS_TYPE).toInt();
        if (addressTypeA != 0 && addressTypeB != 0 && addressTypeA != addressTypeB) {
            result = addressTypeA < addressTypeB;
        } else if (addressTypeA != 0 && addressTypeA == addressTypeB) {

            if (addressTypeA == AT_IPv4) {
                quint32 valA = model->data(source_left, ATapDataModel::DATA_IPV4_INTEGER).value<quint32>();
                quint32 valB = model->data(source_right, ATapDataModel::DATA_IPV4_INTEGER).value<quint32>();

                result = valA < valB;
                identical = valA == valB;
            } else if (addressTypeA == AT_NUMERIC) {
                quint32 valA = datA.toInt();
                quint32 valB = datB.toInt();
                result = valA < valB;
                identical = valA == valB;
            } else {
                result = QString::compare(datA.toString(), datB.toString(), Qt::CaseInsensitive) < 0;
                identical = QString::compare(datA.toString(), datB.toString(), Qt::CaseInsensitive) == 0;
            }

            int portColumn = EndpointDataModel::ENDP_COLUMN_PORT;
            if (identical && qobject_cast<ConversationDataModel *>(model)) {
                QModelIndex tstA, tstB;
                if (source_left.column() == ConversationDataModel::CONV_COLUMN_SRC_ADDR) {
                    portColumn = ConversationDataModel::CONV_COLUMN_SRC_PORT;
                    int col = ConversationDataModel::CONV_COLUMN_DST_ADDR;
                    tstA = model->index(source_left.row(), col);
                    tstB = model->index(source_right.row(), col);
                } else if (source_left.column() == ConversationDataModel::CONV_COLUMN_DST_ADDR) {
                    portColumn = ConversationDataModel::CONV_COLUMN_DST_PORT;
                    int col = ConversationDataModel::CONV_COLUMN_SRC_ADDR;
                    tstA = model->index(source_left.row(), col);
                    tstB = model->index(source_right.row(), col);
                }

                if (addressTypeA == AT_IPv4) {
                    quint32 valX = model->data(tstA, ATapDataModel::DATA_IPV4_INTEGER).value<quint32>();
                    quint32 valY = model->data(tstB, ATapDataModel::DATA_IPV4_INTEGER).value<quint32>();

                    result = valX < valY;
                    identical = valX == valY;
                } else {
                    result = QString::compare(model->data(tstA).toString().toLower(), model->data(tstB).toString(), Qt::CaseInsensitive) < 0;
                    identical = QString::compare(model->data(tstA).toString().toLower(), model->data(tstB).toString(), Qt::CaseInsensitive) == 0;
                }
            }

            if (! result && identical && ! model->portsAreHidden()) {
                int portA = model->data(model->index(source_left.row(), portColumn)).toInt();
                int portB = model->data(model->index(source_right.row(), portColumn)).toInt();
                return portA < portB;
            }
        }

        return result;
    }

    if (datA.canConvert<double>() && datB.canConvert<double>())
        return datA.toDouble() < datB.toDouble();

    return QSortFilterProxyModel::lessThan(source_left, source_right);
}

bool TrafficDataFilterProxy::filterAcceptsColumn(int source_column, const QModelIndex &) const
{
    if (hideColumns_.contains(source_column))
        return false;

    ATapDataModel * model = qobject_cast<ATapDataModel *>(sourceModel());
    if (model) {
        if (model->portsAreHidden()) {
            if (qobject_cast<EndpointDataModel *>(model) && source_column == EndpointDataModel::ENDP_COLUMN_PORT)
                return false;
            if (qobject_cast<ConversationDataModel *>(model) &&
                (source_column == ConversationDataModel::CONV_COLUMN_SRC_PORT || source_column == ConversationDataModel::CONV_COLUMN_DST_PORT))
                return false;
        }
        if (! model->showTotalColumn()) {
            if (qobject_cast<EndpointDataModel *>(model) &&
                (source_column == EndpointDataModel::ENDP_COLUMN_PACKETS_TOTAL || source_column == EndpointDataModel::ENDP_COLUMN_BYTES_TOTAL))
                return false;
            if (qobject_cast<ConversationDataModel *>(model) &&
                (source_column == ConversationDataModel::CONV_COLUMN_PACKETS_TOTAL || source_column == ConversationDataModel::CONV_COLUMN_BYTES_TOTAL))
                return false;
        }
        if (qobject_cast<ConversationDataModel *>(model)) {
            ConversationDataModel * convModel = qobject_cast<ConversationDataModel *>(model);
            if (source_column == ConversationDataModel::CONV_COLUMN_CONV_ID && ! convModel->showConversationId())
                return false;
        }
    }

    return true;
}

void TrafficDataFilterProxy::setColumnVisibility(int column, bool visible)
{
    hideColumns_.removeAll(column);
    if (!visible)
        hideColumns_.append(column);
    invalidateFilter();
}

bool TrafficDataFilterProxy::columnVisible(int column) const
{
    return ! hideColumns_.contains(column);
}


TrafficTree::TrafficTree(QString baseName, GList ** recentColumnList, QWidget *parent) :
    QTreeView(parent)
{
    _tapEnabled = true;
    _saveRaw = true;
    _baseName = baseName;
    _exportRole = ATapDataModel::UNFORMATTED_DISPLAYDATA;
    _header = nullptr;

    setAlternatingRowColors(true);
    setRootIsDecorated(false);
    setSortingEnabled(true);
    setContextMenuPolicy(Qt::CustomContextMenu);

    _header = new TrafficTreeHeaderView(recentColumnList);
    setHeader(_header);

    connect(_header, &TrafficTreeHeaderView::columnsHaveChanged, this, &TrafficTree::columnsHaveChanged);
    connect(this, &QTreeView::customContextMenuRequested, this, &TrafficTree::customContextMenu);
}

void TrafficTree::setModel(QAbstractItemModel * model)
{
    if (model) {
        TrafficDataFilterProxy * proxy = qobject_cast<TrafficDataFilterProxy *>(model);
        if (proxy) {
            connect(_header, &TrafficTreeHeaderView::filterOnColumn, proxy, &TrafficDataFilterProxy::filterForColumn);
        }
    }

    QTreeView::setModel(model);
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

    QMenu * ctxMenu = new QMenu(this);
    ctxMenu->setAttribute(Qt::WA_DeleteOnClose);
    bool isConv = false;

    QModelIndex idx = indexAt(pos);
    ConversationDataModel * model = qobject_cast<ConversationDataModel *>(dataModel());
    if (model)
        isConv = true;

    ctxMenu->addMenu(createActionSubMenu(FilterAction::ActionApply, idx, isConv));
    ctxMenu->addMenu(createActionSubMenu(FilterAction::ActionPrepare, idx, isConv));
    ctxMenu->addMenu(createActionSubMenu(FilterAction::ActionFind, idx, isConv));
    ctxMenu->addMenu(createActionSubMenu(FilterAction::ActionColorize, idx, isConv));

    ctxMenu->addSeparator();
    ctxMenu->addMenu(createCopyMenu());

    ctxMenu->addSeparator();
    QAction * act = ctxMenu->addAction(tr("Resize all columns to content"));
    connect(act, &QAction::triggered, this, &TrafficTree::resizeAction);

    ctxMenu->popup(mapToGlobal(pos));
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
    bool hasConvId = false;
    if (isConversation)
    {
        ConversationDataModel * model = qobject_cast<ConversationDataModel *>(dataModel());
        if (model) {
            conv_item = model->itemForRow(idx.row());
            hasConvId = model->showConversationId(idx.row());
        }
    }

    QMenu * subMenu = new QMenu(FilterAction::actionName(cur_action));
    subMenu->setEnabled(_tapEnabled);
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        if (isConversation && conv_item) {
            QMenu *subsubmenu = subMenu->addMenu(FilterAction::actionTypeName(at));
            if (hasConvId && (cur_action == FilterAction::ActionApply || cur_action == FilterAction::ActionPrepare)) {
                QString filter = QString("%1.stream eq %2").arg(conv_item->ctype == CONVERSATION_TCP ? "tcp" : "udp").arg(conv_item->conv_id);
                FilterAction * act = new FilterAction(subsubmenu, cur_action, at, tr("Filter on stream id"));
                act->setProperty("filter", filter);
                subsubmenu->addAction(act);
                connect(act, &QAction::triggered, this, &TrafficTree::useFilterAction);
            }
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
    ca = copy_menu->addAction(tr("as JSON"));
    ca->setToolTip(tr("Copy all values of this page to the clipboard in the JSON data serialization format."));
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

void TrafficTree::applyRecentColumns()
{
    if (_header)
        _header->applyRecent();
}

void TrafficTree::columnsChanged(QList<int> columns)
{
    TrafficDataFilterProxy * proxy = qobject_cast<TrafficDataFilterProxy *>(model());
    if (!proxy)
        return;

    for (int col = 0; col < dataModel()->columnCount(); col++) {
        proxy->setColumnVisibility(col, columns.contains(col));
    }

    resizeAction();
}
