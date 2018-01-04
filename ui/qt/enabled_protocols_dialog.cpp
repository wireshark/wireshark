/* enabled_protocols_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

    //"Remove" Save button
    if (!prefs.gui_use_pref_save)
        ui->buttonBox->button(QDialogButtonBox::Save)->setHidden(true);

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
        // if we don't have a Save button, just save the settings now
        applyChanges(!prefs.gui_use_pref_save);
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
