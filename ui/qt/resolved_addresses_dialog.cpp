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

#include "file.h"

#include "epan/addr_resolv.h"
#include <wiretap/wtap.h>

#include <QMenu>
#include <QPushButton>
#include <QTextCursor>
#include <QSortFilterProxyModel>

#include "capture_file.h"
#include "main_application.h"

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

    copy_bt_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);

    save_bt_ = ui->buttonBox->addButton(tr("Save as…"), QDialogButtonBox::ActionRole);
    connect(save_bt_, &QPushButton::clicked, this, &ResolvedAddressesDialog::saveAs);

    if (!captureFile.isEmpty()) {
        file_name_ = captureFile;
        title_parts << file_name_;
    }
    setWindowTitle(mainApp->windowTitleString(title_parts));

    ui->plainTextEdit->setFont(mainApp->monospaceFont());
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
    ethSortModel->setColumnsToFilter(QList<int>() << 1 << 2);
    ethSortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    ethTypeModel->setSourceModel(ethSortModel);
    ethTypeModel->setColumnToFilter(0);
    ethTypeModel->setColumnToHide(0);
    ui->tblAddresses->setModel(ethTypeModel);
    ui->tblAddresses->resizeColumnsToContents();
    ui->tblAddresses->sortByColumn(1, Qt::AscendingOrder);
    ui->cmbDataType->addItems(ethModel->filterValues());

    portSortModel = new AStringListListSortFilterProxyModel(this);
    portTypeModel = new AStringListListSortFilterProxyModel(this);
    PortsModel * portModel = new PortsModel(this);
    portSortModel->setSourceModel(portModel);
    portSortModel->setColumnAsNumeric(PORTS_COL_PORT);
    portSortModel->setColumnsToFilter(QList<int>() << PORTS_COL_NAME << PORTS_COL_PROTOCOL);
    portSortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    portTypeModel->setSourceModel(portSortModel);
    portTypeModel->setColumnToFilter(PORTS_COL_PROTOCOL);
    portTypeModel->setColumnAsNumeric(PORTS_COL_PORT);
    ui->tblPorts->setModel(portTypeModel);
    ui->tblPorts->resizeColumnsToContents();
    ui->tblPorts->sortByColumn(PORTS_COL_PORT, Qt::AscendingOrder);
    ui->cmbPortFilterType->addItems(portModel->filterValues());

    tabChanged(ui->tabWidget->currentIndex());
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, &ResolvedAddressesDialog::tabChanged);
}

ResolvedAddressesDialog::~ResolvedAddressesDialog()
{
    delete ui;
}

void ResolvedAddressesDialog::tabChanged(int index)
{
    QWidget *currentTab = ui->tabWidget->widget(index);
    ResolvedAddressesView *addressView = nullptr;
    if (currentTab != nullptr) {
        addressView = currentTab->findChild<ResolvedAddressesView*>();
        if (addressView != nullptr) {
            QMenu* oldMenu = copy_bt_->menu();
            copy_bt_->setMenu(addressView->createCopyMenu(false, copy_bt_));
            if (oldMenu != nullptr) {
                delete oldMenu;
            }
        }
    }
    foreach (QAbstractButton *button, ui->buttonBox->buttons()) {
        if (ui->buttonBox->buttonRole(button) == QDialogButtonBox::ActionRole) {
            button->setEnabled(addressView != nullptr);
        }
    }
}

void ResolvedAddressesDialog::on_cmbDataType_currentIndexChanged(int index)
{
    if (! ethSortModel)
        return;

    QString filter = ui->cmbDataType->itemText(index);
    if (index == 0)
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

void ResolvedAddressesDialog::on_cmbPortFilterType_currentIndexChanged(int index)
{
    if (! portSortModel)
        return;

    QString filter = ui->cmbPortFilterType->itemText(index);
    if (index == 0)
    {
        filter.clear();
        portTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterNone, PORTS_COL_PROTOCOL);
    }
    else
        portTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterByEquivalent, PORTS_COL_PROTOCOL);
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

void ResolvedAddressesDialog::saveAs()
{
    QWidget *currentTab = ui->tabWidget->currentWidget();
    if (currentTab == nullptr) {
        return;
    }

    ResolvedAddressesView *addressView = currentTab->findChild<ResolvedAddressesView*>();
    if (addressView == nullptr) {
        return;
    }

    addressView->saveAs();
}
