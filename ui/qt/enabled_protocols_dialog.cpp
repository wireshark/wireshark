/* enabled_protocols_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "enabled_protocols_dialog.h"
#include <ui_enabled_protocols_dialog.h>

#include <QElapsedTimer>

#include <epan/prefs.h>

#include "wireshark_application.h"

EnabledProtocolsDialog::EnabledProtocolsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::EnabledProtocolsDialog),
    enabled_protocols_model_(new EnabledProtocolsModel()),
    proxyModel_(new EnabledProtocolsProxyModel(this))
{
    ui->setupUi(this);
    loadGeometry();

    proxyModel_->setSourceModel(enabled_protocols_model_);
    ui->protocol_tree_->setModel(proxyModel_);

    setWindowTitle(wsApp->windowTitleString(tr("Enabled Protocols")));

    // Some protocols have excessively long names. Instead of calling
    // resizeColumnToContents, pick a reasonable-ish em width and apply it.
    int one_em = ui->protocol_tree_->fontMetrics().height();
    ui->protocol_tree_->setColumnWidth(EnabledProtocolsModel::colProtocol, one_em * 18);

    ui->cmbSearchType->addItem(tr("Everywhere"), QVariant::fromValue(EnabledProtocolsProxyModel::EveryWhere));
    ui->cmbSearchType->addItem(tr("Only Protocols"), QVariant::fromValue(EnabledProtocolsProxyModel::OnlyProtocol));
    ui->cmbSearchType->addItem(tr("Only Description"), QVariant::fromValue(EnabledProtocolsProxyModel::OnlyDescription));
    ui->cmbSearchType->addItem(tr("Only enabled protocols"), QVariant::fromValue(EnabledProtocolsProxyModel::EnabledItems));
    ui->cmbSearchType->addItem(tr("Only disabled protocols"), QVariant::fromValue(EnabledProtocolsProxyModel::DisabledItems));

    ui->cmbProtocolType->addItem(tr("any protocol"), QVariant::fromValue(EnabledProtocolItem::Any));
    ui->cmbProtocolType->addItem(tr("non-heuristic protocols"), QVariant::fromValue(EnabledProtocolItem::Standard));
    ui->cmbProtocolType->addItem(tr("heuristic protocols"), QVariant::fromValue(EnabledProtocolItem::Heuristic));

    fillTree();
}

EnabledProtocolsDialog::~EnabledProtocolsDialog()
{
    delete ui;
    delete proxyModel_;
    delete enabled_protocols_model_;
}

void EnabledProtocolsDialog::fillTree()
{
    enabled_protocols_model_->populate();
    //it's recommended to sort after list is populated
    proxyModel_->sort(EnabledProtocolsModel::colProtocol);
    ui->protocol_tree_->expandAll();
}

void EnabledProtocolsDialog::on_invert_button__clicked()
{
    proxyModel_->setItemsEnable(EnabledProtocolsProxyModel::Invert);
    ui->protocol_tree_->expandAll();
}

void EnabledProtocolsDialog::on_enable_all_button__clicked()
{
    proxyModel_->setItemsEnable(EnabledProtocolsProxyModel::Enable);
    ui->protocol_tree_->expandAll();
}

void EnabledProtocolsDialog::on_disable_all_button__clicked()
{
    proxyModel_->setItemsEnable(EnabledProtocolsProxyModel::Disable);
    ui->protocol_tree_->expandAll();
}

void EnabledProtocolsDialog::searchFilterChange()
{
    EnabledProtocolsProxyModel::SearchType type = EnabledProtocolsProxyModel::EveryWhere;
    EnabledProtocolItem::EnableProtocolType protocol = EnabledProtocolItem::Any;
    QString search_re = ui->search_line_edit_->text();

    if (ui->cmbSearchType->currentData().canConvert<EnabledProtocolsProxyModel::SearchType>())
        type = ui->cmbSearchType->currentData().value<EnabledProtocolsProxyModel::SearchType>();

    if (ui->cmbProtocolType->currentData().canConvert<EnabledProtocolItem::EnableProtocolType>())
        protocol = ui->cmbProtocolType->currentData().value<EnabledProtocolItem::EnableProtocolType>();

    proxyModel_->setFilter(search_re, type, protocol);
    /* If items are filtered out, then filtered back in, the tree remains collapsed
       Force an expansion */
    ui->protocol_tree_->expandAll();
}

void EnabledProtocolsDialog::on_search_line_edit__textChanged(const QString &)
{
    searchFilterChange();
}

void EnabledProtocolsDialog::on_cmbSearchType_currentIndexChanged(int)
{
    searchFilterChange();
}

void EnabledProtocolsDialog::on_cmbProtocolType_currentIndexChanged(int)
{
    searchFilterChange();
}

void EnabledProtocolsDialog::on_buttonBox_accepted()
{
    enabled_protocols_model_->applyChanges();
}

void EnabledProtocolsDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_ENABLED_PROTOCOLS_DIALOG);
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
