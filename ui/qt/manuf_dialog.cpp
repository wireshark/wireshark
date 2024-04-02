/*
 * manuf_dialog.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include "manuf_dialog.h"
#include <ui_manuf_dialog.h>

#include <cstdio>
#include <cstdint>
#include <QComboBox>
#include <QStandardItemModel>
#include <QPushButton>
#include <QRegularExpression>
#include <QClipboard>
#include <QAction>
#include <QButtonGroup>
#include <QCheckBox>

#include "main_application.h"
#include <epan/manuf.h>
#include <epan/strutil.h>
#include <wsutil/regex.h>
#include <utils/qt_ui_utils.h>

#define PLACEHOLDER_SEARCH_ADDR "Search address"
#define PLACEHOLDER_SEARCH_NAME "Search name"

ManufDialog::ManufDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ManufDialog)
{
    ui->setupUi(this);
    loadGeometry();

    model_ = new ManufTableModel(this);
    proxy_model_ = new ManufSortFilterProxyModel(this);
    proxy_model_->setSourceModel(model_);

    ui->manufTableView->setModel(proxy_model_);
    ui->manufTableView->setContextMenuPolicy(Qt::ActionsContextMenu);
    ui->manufTableView->setColumnHidden(ManufTableModel::COL_SHORT_NAME, true);

    QAction *select_action = new QAction(tr("Select all"), ui->manufTableView);
    ui->manufTableView->addAction(select_action);
    connect(select_action, &QAction::triggered, ui->manufTableView, &QTableView::selectAll);

    QAction *copy_action = new QAction(tr("Copy"), ui->manufTableView);
    ui->manufTableView->addAction(copy_action);
    connect(copy_action, &QAction::triggered, this, &ManufDialog::copyToClipboard);

    QPushButton *find_button = ui->buttonBox->addButton(tr("Find"), QDialogButtonBox::ActionRole);
    find_button->setDefault(true);
    connect(find_button, &QPushButton::clicked, this, &ManufDialog::on_editingFinished);

    QPushButton *clear_button = ui->buttonBox->addButton(tr("Clear"), QDialogButtonBox::ActionRole);
    connect(clear_button, &QPushButton::clicked, this, &ManufDialog::clearFilter);

    QPushButton *copy_button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);
    connect(copy_button, &QPushButton::clicked, this, &ManufDialog::copyToClipboard);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    connect(ui->radioButtonGroup, &QButtonGroup::buttonClicked, this, &ManufDialog::on_searchToggled);
    connect(ui->radioButtonGroup, &QButtonGroup::buttonClicked, this, &ManufDialog::on_editingFinished);
#else
    connect(ui->radioButtonGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked), this, &ManufDialog::on_searchToggled);
    connect(ui->radioButtonGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked), this, &ManufDialog::on_editingFinished);
#endif
    connect(ui->checkShortNameButton, &QCheckBox::stateChanged, this, &ManufDialog::on_shortNameStateChanged);

    ui->manufLineEdit->setPlaceholderText(tr(PLACEHOLDER_SEARCH_ADDR));

    ui->hintLabel->clear();
}

ManufDialog::~ManufDialog()
{
    delete ui;
}

void ManufDialog::searchVendor(QString &text)
{
    QRegularExpression name_re;

    name_re = QRegularExpression(text, QRegularExpression::CaseInsensitiveOption);
    if (!name_re.isValid()) {
        ui->hintLabel->setText(QString("<small><i>Invalid regular expression: %1</i></small>").arg(name_re.errorString()));
        return;
    }

    proxy_model_->setFilterName(name_re);
    ui->hintLabel->setText(QString("<small><i>Found %1 matches for \"%2\"</i></small>").arg(proxy_model_->rowCount()).arg(text));
}

static QByteArray convertMacAddressToByteArray(const QString &bytesString)
{
    GByteArray *bytes = g_byte_array_new();

    if (!hex_str_to_bytes(qUtf8Printable(bytesString), bytes, false)
                                || bytes->len == 0 || bytes->len > 6) {
        g_byte_array_free(bytes, true);
        return QByteArray();
    }

    /* Mask out multicast/locally administered flags. */
    bytes->data[0] &= 0xFC;

    return gbytearray_free_to_qbytearray(bytes);
}

QString convertToMacAddress(const QByteArray& byteArray) {
    QString macAddress;
    for (int i = 0; i < byteArray.size(); ++i) {
        macAddress += QString("%1").arg(static_cast<quint8>(byteArray[i]), 2, 16, QChar('0'));
        if (i != byteArray.size() - 1) {
            macAddress += ":";
        }
    }
    return macAddress.toUpper();
}

void ManufDialog::searchPrefix(QString &text)
{
    QByteArray addr;

    addr = convertMacAddressToByteArray(text);
    if (addr.isEmpty()) {
        ui->hintLabel->setText(QString("<small><i>\"%1\" is not a valid MAC address</i></small>").arg(text));
        return;
    }

    proxy_model_->setFilterAddress(addr);
    ui->hintLabel->setText(QString("<small><i>Found %1 matches for \"%2\"</i></small>").arg(proxy_model_->rowCount()).arg(convertToMacAddress(addr)));
}

void ManufDialog::on_searchToggled(void)
{
    if (ui->ouiRadioButton->isChecked())
        ui->manufLineEdit->setPlaceholderText(tr(PLACEHOLDER_SEARCH_ADDR));
    else if (ui->vendorRadioButton->isChecked())
        ui->manufLineEdit->setPlaceholderText(tr(PLACEHOLDER_SEARCH_NAME));
    else
        ws_assert_not_reached();
}

void ManufDialog::on_editingFinished(void)
{
    QString text = ui->manufLineEdit->text();

    if (text.isEmpty())
        return;

    if (ui->ouiRadioButton->isChecked())
        searchPrefix(text);
    else if (ui->vendorRadioButton->isChecked())
        searchVendor(text);
    else
        ws_assert_not_reached();
}

void ManufDialog::on_shortNameStateChanged(int state)
{
    ui->manufTableView->setColumnHidden(ManufTableModel::COL_SHORT_NAME, state ? false : true);
}

void ManufDialog::clearFilter()
{
    proxy_model_->clearFilter();
    ui->manufLineEdit->clear();
    ui->hintLabel->clear();
}

void ManufDialog::copyToClipboard() {
    QModelIndexList selectedIndexes = ui->manufTableView->selectionModel()->selectedIndexes();

    std::sort(selectedIndexes.begin(), selectedIndexes.end(), [](const QModelIndex &a, const QModelIndex &b) {
        return a.row() < b.row() || (a.row() == b.row() && a.column() < b.column());
    });

    QAbstractItemModel *model = ui->manufTableView->model();
    QString copiedData;

    int previousRow = -1;

    for (const QModelIndex& selectedIndex : selectedIndexes) {
        // If the row changed, add a newline character
        if (selectedIndex.row() != previousRow) {
            if (!copiedData.isEmpty()) {
                copiedData += "\n";
            }
            previousRow = selectedIndex.row();
        }
        else {
            // If not the first column in the row, add a tab character
            copiedData += "\t";
        }

        // Add the cell data to the string
        copiedData += model->data(selectedIndex).toString();
    }

    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(copiedData);
}
