/* resolved_addresses_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "resolved_addresses_dialog.h"
#include <ui_resolved_addresses_dialog.h>

#include "config.h"

#include <glib.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <wiretap/wtap.h>

#include <QMenu>
#include <QPushButton>
#include <QTextCursor>
#include <QSortFilterProxyModel>

#include "capture_file.h"
#include "wireshark_application.h"

#include <ui/qt/models/astringlist_list_model.h>
#include <ui/qt/models/resolved_addresses_models.h>

const QString no_entries_ = QObject::tr("No entries.");
const QString entry_count_ = QObject::tr("%1 entries.");

ResolvedAddressesDialog::ResolvedAddressesDialog(QWidget *parent, QString captureFile, wtap* wth) :
    GeometryStateDialog(parent),
    ui(new Ui::ResolvedAddressesDialog),
    file_name_(tr("[no file]"))
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    QStringList title_parts = QStringList() << tr("Resolved Addresses");

    if (captureFile.isEmpty()) {
        file_name_ = captureFile;
        title_parts << file_name_;
    }
    setWindowTitle(wsApp->windowTitleString(title_parts));

    ui->plainTextEdit->setFont(wsApp->monospaceFont());
    ui->plainTextEdit->setReadOnly(true);
    ui->plainTextEdit->setWordWrapMode(QTextOption::NoWrap);

    if (wth) {
        // might return null
        wtap_block_t nrb_hdr;

        /*
            * XXX - support multiple NRBs.
            */
        nrb_hdr = wtap_file_get_nrb(wth);
        if (nrb_hdr != NULL) {
            char *str;

            /*
                * XXX - support multiple comments.
                */
            if (wtap_block_get_nth_string_option_value(nrb_hdr, OPT_COMMENT, 0, &str) == WTAP_OPTTYPE_SUCCESS) {
                comment_ = str;
            }
        }
    }

    fillBlocks();

    ethSortModel = new AStringListListSortFilterProxyModel(this);
    ethTypeModel = new AStringListListSortFilterProxyModel(this);
    EthernetAddressModel * ethModel = new EthernetAddressModel(this);
    ethSortModel->setSourceModel(ethModel);
    ethSortModel->setColumnToFilter(1);
    ethSortModel->setColumnToFilter(2);
    ethSortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    ethTypeModel->setSourceModel(ethSortModel);
    ethTypeModel->setColumnToFilter(0);
    ethTypeModel->setColumnToHide(0);
    ui->tblAddresses->setModel(ethTypeModel);
    ui->tblAddresses->resizeColumnsToContents();
    ui->tblAddresses->horizontalHeader()->setStretchLastSection(true);
    ui->tblAddresses->sortByColumn(1, Qt::AscendingOrder);
    ui->cmbDataType->addItems(ethModel->filterValues());

    portSortModel = new AStringListListSortFilterProxyModel(this);
    portTypeModel = new AStringListListSortFilterProxyModel(this);
    PortsModel * portModel = new PortsModel(this);
    portSortModel->setSourceModel(portModel);
    portSortModel->setColumnAsNumeric(1);
    portSortModel->setColumnToFilter(0);
    portSortModel->setColumnToFilter(1);
    portSortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    portTypeModel->setSourceModel(portSortModel);
    portTypeModel->setColumnToFilter(2);
    ui->tblPorts->setModel(portTypeModel);
    ui->tblPorts->resizeColumnsToContents();
    ui->tblPorts->horizontalHeader()->setStretchLastSection(true);
    ui->tblPorts->sortByColumn(1, Qt::AscendingOrder);
    ui->cmbPortFilterType->addItems(portModel->filterValues());
}

ResolvedAddressesDialog::~ResolvedAddressesDialog()
{
    delete ui;
}

void ResolvedAddressesDialog::on_cmbDataType_currentIndexChanged(QString)
{
    if (! ethSortModel)
        return;

    QString filter = ui->cmbDataType->currentText();
    if (ui->cmbDataType->currentIndex() == 0)
    {
        filter.clear();
        ethTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterNone, 0);
    }
    else
        ethTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterByEquivalent, 0);
    ethTypeModel->setFilter(filter);
}

void ResolvedAddressesDialog::on_txtSearchFilter_textChanged(QString)
{
    QString filter = ui->txtSearchFilter->text();
    if (!ethSortModel || (!filter.isEmpty() && filter.length() < 3))
        return;

    ethSortModel->setFilter(filter);
}

void ResolvedAddressesDialog::on_cmbPortFilterType_currentIndexChanged(QString)
{
    if (! portSortModel)
        return;

    QString filter = ui->cmbPortFilterType->currentText();
    if (ui->cmbPortFilterType->currentIndex() == 0)
    {
        filter.clear();
        portTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterNone, 2);
    }
    else
        portTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterByEquivalent, 2);
    portTypeModel->setFilter(filter);
}

void ResolvedAddressesDialog::on_txtPortFilter_textChanged(QString val)
{
    if (! portSortModel)
        return;

    portSortModel->setFilter(val);
}

void ResolvedAddressesDialog::changeEvent(QEvent *event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            fillBlocks();
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}

void ResolvedAddressesDialog::fillBlocks()
{
    setUpdatesEnabled(false);
    ui->plainTextEdit->clear();

    QString lines;
    ui->plainTextEdit->appendPlainText(tr("# Resolved addresses found in %1").arg(file_name_));

    if (ui->actionComment->isChecked()) {
        lines = "\n";
        lines.append(tr("# Comments\n#\n# "));
        if (!comment_.isEmpty()) {
            lines.append("\n\n");
            lines.append(comment_);
            lines.append("\n");
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    ui->plainTextEdit->moveCursor(QTextCursor::Start);
    setUpdatesEnabled(true);
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
