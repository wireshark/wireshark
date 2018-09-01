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

    QTimer::singleShot(0, this, SLOT(fillTree()));
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
    enabled_protocols_model_->invertEnabled();
}

void EnabledProtocolsDialog::on_enable_all_button__clicked()
{
    enabled_protocols_model_->enableAll();
}

void EnabledProtocolsDialog::on_disable_all_button__clicked()
{
    enabled_protocols_model_->disableAll();
}

void EnabledProtocolsDialog::on_search_line_edit__textChanged(const QString &search_re)
{
    proxyModel_->setFilter(search_re);
    /* If items are filtered out, then filtered back in, the tree remains collapsed
       Force an expansion */
    ui->protocol_tree_->expandAll();
}

void EnabledProtocolsDialog::on_buttonBox_accepted()
{
    enabled_protocols_model_->applyChanges();
}

#if 0
// If we ever find and fix the bug behind queueAppSignal we can re-enable
// this.
void EnabledProtocolsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == ui->buttonBox->button(QDialogButtonBox::Apply))
    {
        applyChanges(TRUE);
    }
}
#endif

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
