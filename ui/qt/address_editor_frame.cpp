/* address_editor_frame.h
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

#include "config.h"

#include <glib.h>

#include "file.h"
#include "frame_tvbuff.h"

#include "epan/addr_resolv.h"
#include "epan/epan_dissect.h"
#include "epan/frame_data.h"

#include "address_editor_frame.h"
#include <ui_address_editor_frame.h>

#include <QPushButton>

#include "qt_ui_utils.h"

// To do:
// - Fill in currently resolved address.

AddressEditorFrame::AddressEditorFrame(QWidget *parent) :
    AccordionFrame(parent),
    ui(new Ui::AddressEditorFrame),
    cap_file_(NULL)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif
}

AddressEditorFrame::~AddressEditorFrame()
{
    delete ui;
}

void AddressEditorFrame::editAddresses(CaptureFile &cf, int column)
{
    cap_file_ = cf.capFile();

    if (!cap_file_->current_frame) {
        on_buttonBox_rejected();
        return;
    }

    if (!cf_read_record(cap_file_, cap_file_->current_frame)) {
        on_buttonBox_rejected();
        return; // error reading the frame
    }

    epan_dissect_t edt;
    QStringList addresses;

    ui->addressComboBox->clear();

    epan_dissect_init(&edt, cap_file_->epan, FALSE, FALSE);
    col_custom_prime_edt(&edt, &cap_file_->cinfo);

    epan_dissect_run(&edt, cap_file_->cd_t, &cap_file_->phdr,
        frame_tvbuff_new_buffer(cap_file_->current_frame, &cap_file_->buf), cap_file_->current_frame, &cap_file_->cinfo);
    epan_dissect_fill_in_columns(&edt, TRUE, TRUE);

    /* First check selected column */
    if (isAddressColumn(&cap_file_->cinfo, column)) {
        addresses << cap_file_->cinfo.col_expr.col_expr_val[column];
    }

    for (int col = 0; col < cap_file_->cinfo.num_cols; col++) {
        /* Then check all columns except the selected */
        if ((col != column) && (isAddressColumn(&cap_file_->cinfo, col))) {
            addresses << cap_file_->cinfo.col_expr.col_expr_val[col];
        }
    }

    epan_dissect_cleanup(&edt);

    ui->addressComboBox->addItems(addresses);
    ui->nameLineEdit->setFocus();
    updateWidgets();
}

void AddressEditorFrame::updateWidgets()
{
    bool ok_enable = false;
    if (ui->addressComboBox->count() > 0 && !ui->nameLineEdit->text().isEmpty()) {
        ok_enable = true;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok_enable);
}

void AddressEditorFrame::on_nameResolutionPreferencesToolButton_clicked()
{
    static const QString module_name = "nameres";
    on_buttonBox_rejected();
    emit showNameResolutionPreferences(module_name);
}

void AddressEditorFrame::on_addressComboBox_currentIndexChanged(const QString &)
{
    updateWidgets();
}

void AddressEditorFrame::on_nameLineEdit_textEdited(const QString &)
{
    updateWidgets();
}

void AddressEditorFrame::on_nameLineEdit_returnPressed()
{
    if (ui->buttonBox->button(QDialogButtonBox::Ok)->isEnabled()) {
        on_buttonBox_accepted();
    }
}

void AddressEditorFrame::on_buttonBox_accepted()
{
    if (ui->addressComboBox->count() < 1 || ui->nameLineEdit->text().isEmpty()) {
        return;
    }
    QString addr = ui->addressComboBox->currentText();
    QString name = ui->nameLineEdit->text();
    if (!cf_add_ip_name_from_string(cap_file_, addr.toUtf8().constData(), name.toUtf8().constData())) {
        QString error_msg = tr("Can't assign %1 to %2").arg(name).arg(addr);
        emit editAddressStatus(error_msg);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        return;
    }
    on_buttonBox_rejected();
    emit redissectPackets();
}

void AddressEditorFrame::on_buttonBox_rejected()
{
    ui->addressComboBox->clear();
    ui->nameLineEdit->clear();
    animatedHide();
}

bool AddressEditorFrame::isAddressColumn(epan_column_info *cinfo, int column)
{
    if (!cinfo || column < 0 || column >= cinfo->num_cols) return false;

    if (((cinfo->columns[column].col_fmt == COL_DEF_SRC) ||
         (cinfo->columns[column].col_fmt == COL_RES_SRC) ||
         (cinfo->columns[column].col_fmt == COL_DEF_DST) ||
         (cinfo->columns[column].col_fmt == COL_RES_DST)) &&
        strlen(cinfo->col_expr.col_expr_val[column]))
    {
        return true;
    }

    return false;
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
