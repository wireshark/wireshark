/* pluginifdemo_main.cpp
 *
 * Author: Roland Knall <rknall@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <plugins/epan/pluginifdemo/ui/pluginifdemo_main.h>
#include <ui_pluginifdemo_main.h>

#include <config.h>

#include <ui/uihandler.h>

#include <QWidget>
#include <QLineEdit>
#include <QListView>
#include <QStandardItemModel>

PluginIfType::PluginIfType(const QString &label, const ext_toolbar_item_t &itemType)
    : m_label(label), m_itemType(itemType)
{}

QString PluginIfType::label() const { return m_label; }
ext_toolbar_item_t PluginIfType::itemType() const { return m_itemType; }

PluginIfTypeModel::PluginIfTypeModel(QObject * parent)
    :QAbstractListModel(parent)
{
}

void PluginIfTypeModel::addPluginIfType(const PluginIfType &ifType)
{
    beginInsertRows(QModelIndex(), rowCount(), rowCount());
    m_pluginIfTypes << ifType;
    endInsertRows();
}

int PluginIfTypeModel::rowCount(const QModelIndex &) const
{
    return m_pluginIfTypes.count();
}

QVariant PluginIfTypeModel::data(const QModelIndex & idx, int role) const
{
    if ( idx.row() < 0 || idx.row() >= m_pluginIfTypes.count() )
        return QVariant();

    const PluginIfType &ifType = m_pluginIfTypes[idx.row()];
    if ( role == Qt::UserRole )
    {
        return ifType.itemType();
    } else if ( role == Qt::DisplayRole ) {
        return ifType.label();
    }

    return QVariant();
}

PluginIfTypeSortFilterProxyModel::PluginIfTypeSortFilterProxyModel(QObject * parent)
:QSortFilterProxyModel(parent)
{
    m_filterType = EXT_TOOLBAR_BOOLEAN;
}

void PluginIfTypeSortFilterProxyModel::setFilterElement(ext_toolbar_item_t filterType)
{
    m_filterType = filterType;
    invalidateFilter();
}

bool PluginIfTypeSortFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex dataIndex = sourceModel()->index(sourceRow, 0, sourceParent);
    QVariant varData = sourceModel()->data(dataIndex, Qt::UserRole);
    if ( varData.isValid() && varData.toInt() == (int) m_filterType )
            return true;

    return false;
}

PluginIFDemo_Main::PluginIFDemo_Main(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PluginIFDemo_Main)
{
    ui->setupUi(this);

    _toolbar = 0;
    sourceModel = new PluginIfTypeModel(this);
    proxyModel = new PluginIfTypeSortFilterProxyModel(this);
    proxyModel->setSourceModel(sourceModel);
    ui->cmbElements->setModel(proxyModel);

    listModel = new QStandardItemModel(this);
    ui->lstItems->setModel(listModel);

    indexModel = new QStandardItemModel(this);
    ui->cmbEntryIndex->setModel(indexModel);

    ui->logView->setModel(new QStandardItemModel(ui->logView));

    ui->tabInterfaceTypes->setCurrentIndex(0);

    connect ( GuiHandler::getInstance(), SIGNAL(reset(void)), this, SLOT(closeDialog()) );
    connect ( GuiHandler::getInstance(), SIGNAL(logChanged(QString)), this, SLOT(logChanged(QString)) );
}

PluginIFDemo_Main::~PluginIFDemo_Main()
{
    delete ui;
}

void PluginIFDemo_Main::setToolbar(ext_toolbar_t * &toolbar)
{
    _toolbar = toolbar;

    GList * walker = toolbar->children;
    while ( walker && walker->data )
    {
        ext_toolbar_t * entry = (ext_toolbar_t *)walker->data;
        if ( entry && entry->type == EXT_TOOLBAR_ITEM && entry->name )
            sourceModel->addPluginIfType(PluginIfType(QString(entry->name), entry->item_type));
        walker = g_list_next(walker);
    }
}

void PluginIFDemo_Main::closeDialog()
{
    this->close();
}

void PluginIFDemo_Main::on_buttonBox_clicked(QAbstractButton *button _U_)
{
    this->close();
}

void PluginIFDemo_Main::logChanged(QString message)
{
    QStandardItemModel * model = (QStandardItemModel *) ui->logView->model();
    model->appendRow(new QStandardItem(message));
}

void PluginIFDemo_Main::on_btnSendButtonText_clicked()
{
    if ( ! _toolbar )
        return;

    ext_toolbar_t  *item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item )
        return;

    QString entryText = ui->txtButtonName->text();
    bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

    ext_toolbar_update_value(item, (gpointer) entryText.toStdString().c_str(), silent);
}

void PluginIFDemo_Main::on_btnSendText_clicked()
{
    if ( ! _toolbar )
        return;

    ext_toolbar_t  *item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item )
        return;

    QString entryText = ui->txtEdit->text();
    bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

    ext_toolbar_update_value(item, (gpointer) entryText.toStdString().c_str(), silent);
}

void PluginIFDemo_Main::on_chkTestCheckbox_stateChanged(int newState)
{
    if ( ! _toolbar )
        return;

    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item )
        return;
    bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

    ext_toolbar_update_value(item, GINT_TO_POINTER(newState == Qt::Checked ? 1 : 0), silent);
}

void PluginIFDemo_Main::on_tabInterfaceTypes_currentChanged(int newTab)
{
    proxyModel->setFilterElement((ext_toolbar_item_t) newTab);
}

void PluginIFDemo_Main::on_cmbElements_currentTextChanged(const QString & newText)
{
    if ( ! _toolbar )
        return;

    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, newText.toStdString().c_str());
    if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
        return;

    listModel->clear();
    indexModel->clear();

    GList * walker = item->values;
    while ( walker && walker->data )
    {
        ext_toolbar_value_t * listItem = (ext_toolbar_value_t *)walker->data;
        QString content = QString("%1: %2").arg(listItem->value).arg(listItem->display);
        listModel->appendRow(new QStandardItem(content));
        indexModel->appendRow(new QStandardItem(listItem->value));

        walker = g_list_next(walker);
    }

}

void PluginIFDemo_Main::on_btnEnable_clicked()
{
    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item )
        return;

    ext_toolbar_update_data_set_active(item, true);
}

void PluginIFDemo_Main::on_btnDisable_clicked()
{
    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item )
        return;

    ext_toolbar_update_data_set_active(item, false);
}

void PluginIFDemo_Main::on_btnAddItem_clicked()
{
    if ( ui->txtNewItemDisplay->text().length() <= 0 || ui->txtNewItemValue->text().length() <= 0 )
        return;

    QString content = QString("%1: %2").arg(ui->txtNewItemValue->text()).arg(ui->txtNewItemDisplay->text());

    QList<QStandardItem *> items = listModel->findItems(content);
    if ( items.count() > 0 )
        return;
    items = listModel->findItems(QString("%1: ").arg(ui->txtNewItemValue->text()), Qt::MatchStartsWith);
    if ( items.count() > 0 )
        return;

    listModel->appendRow(new QStandardItem(content));

    if ( ui->chkAddRemoveImmediate->checkState() == Qt::Checked )
    {
        ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
        if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
            return;

        bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

        gchar * value = g_strdup(ui->txtNewItemValue->text().toUtf8().constData());
        gchar * display = g_strdup(ui->txtNewItemDisplay->text().toUtf8().constData());
        ext_toolbar_update_data_add_entry(item, display, value, silent);
        g_free(value);
        g_free(display);
    }
}

void PluginIFDemo_Main::on_btnRemoveItem_clicked()
{
    QItemSelectionModel * selModel = ui->lstItems->selectionModel();

    if ( selModel->selectedIndexes().count() == 0 )
        return;

    QModelIndexList selIndeces = selModel-> selectedIndexes();
    foreach(QModelIndex idx, selIndeces)
    {
        if ( ui->chkAddRemoveImmediate->checkState() == Qt::Checked )
        {
            ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
            if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
                return;

            bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

            QString content = listModel->data(idx).toString();
            int pos = content.indexOf(":");

            gchar * value = g_strdup(content.left(pos).toUtf8().constData() );
            /* -2 because removal of : and space */
            gchar * display = g_strdup(content.right(content.size() - pos - 2).toUtf8().constData());
            ext_toolbar_update_data_remove_entry(item, display, value, silent);
            g_free(value);
            g_free(display);
        }

        listModel->removeRow(idx.row());
    }
}

void PluginIFDemo_Main::on_btnSendList_clicked()
{
    if ( ! _toolbar )
        return;

    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
        return;

    GList * items = NULL;

    for( int i = 0; i < listModel->rowCount(); i++ )
    {
        QString content = listModel->data(listModel->index(i, 0)).toString();
        int pos = content.indexOf(":");

        ext_toolbar_value_t * valEntry = g_new0(ext_toolbar_value_t, 1);
        valEntry->value = g_strdup(content.left(pos).toStdString().c_str() );
        valEntry->display = g_strdup(content.right(content.size() - pos + 1).toStdString().c_str());

        items = g_list_append(items, valEntry);
    }

    bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

    ext_toolbar_update_data(item, items , silent);
}

void PluginIFDemo_Main::on_btnSendUpdateItem_clicked()
{
    if ( ! _toolbar )
        return;

    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
        return;

    QString cmbIndexText = ui->cmbEntryIndex->currentText();
    QString displayValue = ui->txtUpdateDisplayValue->text();
    if ( displayValue.length() == 0 )
        return;

    bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

    ext_toolbar_update_data_by_index(item,
            (gpointer) displayValue.toStdString().c_str(), (gpointer) cmbIndexText.toStdString().c_str(), silent );
}

void PluginIFDemo_Main::on_lstItems_clicked(const QModelIndex &idx)
{
    if ( ! _toolbar || ! idx.isValid() )
        return;

    ext_toolbar_t * item = ext_toolbar_entry_by_label(_toolbar, ui->cmbElements->currentText().toStdString().c_str());
    if ( ! item || item->item_type != EXT_TOOLBAR_SELECTOR )
        return;

    bool silent = ui->chkSilent->checkState() == Qt::Checked ? true : false;

    QString content = listModel->data(listModel->index(idx.row(), 0)).toString();
    int pos = content.indexOf(":");

    gchar * idxData = g_strdup(content.left(pos).toUtf8().constData() );

    ext_toolbar_update_value(item, idxData, silent);
    g_free(idxData);

}
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
