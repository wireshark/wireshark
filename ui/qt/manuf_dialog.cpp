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

#include "main_application.h"
#include <epan/manuf.h>
#include <epan/strutil.h>
#include <wsutil/regex.h>

#define PLACEHOLDER_SEARCH_ADDR "Search address"
#define PLACEHOLDER_SEARCH_NAME "Search name"

ManufDialog::ManufDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ManufDialog)
{
    ui->setupUi(this);

    model_ = new ManufTableModel(this);
    ui->manufTableView->setModel(model_);
    ui->manufTableView->setContextMenuPolicy(Qt::ActionsContextMenu);

    QAction *select_action = new QAction(tr("Select all"));
    connect(select_action, &QAction::triggered, ui->manufTableView, &QTableView::selectAll);
    ui->manufTableView->addAction(select_action);

    QAction *copy_action = new QAction(tr("Copy"));
    connect(copy_action, &QAction::triggered, this, &ManufDialog::copyToClipboard);
    ui->manufTableView->addAction(copy_action);

    QPushButton *find_button = ui->buttonBox->addButton(tr("Find"), QDialogButtonBox::ActionRole);
    find_button->setDefault(true);
    connect(find_button, &QPushButton::clicked, this, &ManufDialog::on_editingFinished);

    QPushButton *copy_button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);
    connect(copy_button, &QPushButton::clicked, this, &ManufDialog::copyToClipboard);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    connect(ui->radioButtonGroup, &QButtonGroup::buttonClicked, this, &ManufDialog::on_searchToggled);
    connect(ui->radioButtonGroup, &QButtonGroup::buttonClicked, this, &ManufDialog::on_editingFinished);
#else
    connect(ui->radioButtonGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked), this, &ManufDialog::on_searchToggled);
    connect(ui->radioButtonGroup, QOverload<QAbstractButton *>::of(&QButtonGroup::buttonClicked), this, &ManufDialog::on_editingFinished);
#endif

    ui->manufLineEdit->setPlaceholderText(tr(PLACEHOLDER_SEARCH_ADDR));

    ui->hintLabel->clear();
}

ManufDialog::~ManufDialog()
{
    delete ui;
}

#define ADDR_BUFSIZE 32

static const char *snprint_addr(const uint8_t addr[6], int mask, char *buf, size_t buf_size)
{
    if (mask == 24)
        std::snprintf(buf, buf_size,
                    "%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8,
                    addr[0], addr[1], addr[2]);
    else if (mask == 0 || mask == 48)
        std::snprintf(buf, buf_size,
                    "%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8,
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    else
        std::snprintf(buf, buf_size,
                    "%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 ":%02" PRIX8 "/%d",
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], mask);
    return buf;
}

void ManufDialog::searchVendor(QString &text)
{
    ws_regex_t *re;
    ws_manuf_iter_t iter;
    struct ws_manuf buf[3], *ptr;
    QString output;

    model_->clear();

    char *err_msg = NULL;
    re = ws_regex_compile_ex(qUtf8Printable(text), -1, &err_msg, WS_REGEX_CASELESS);
    if (err_msg != nullptr) {
        ui->hintLabel->setText(QString("<small><i>Invalid regular expression: %1</i></small>").arg(QString::fromUtf8(err_msg)));
        g_free(err_msg);
        return;
    }

    ws_manuf_iter_init(&iter);
    while ((ptr = ws_manuf_iter_next(&iter, buf))) {
        if (ws_regex_matches(re, ptr->long_name)) {
            char addr_str[ADDR_BUFSIZE];
            snprint_addr(ptr->addr, ptr->mask, addr_str, sizeof(addr_str));
            QString prefix = QString::fromUtf8(addr_str);
            QString short_name = QString::fromUtf8(ptr->short_name);
            QString vendor_name = QString::fromUtf8(ptr->long_name);
            model_->addRecord(prefix, short_name, vendor_name);
        }
    }

    ws_regex_free(re);

    if (model_->rowCount() > 0) {
        output = QString("Found %1 matches for \"%2\"").arg(model_->rowCount()).arg(text);
    }
    else {
        output = QString("\"%1\" not found").arg(text);
    }
    ui->hintLabel->setText(QString("<small><i>%1</i></small>").arg(output));
}

static bool text_to_addr(const char *str, uint8_t buf[6])
{
    GByteArray *bytes = g_byte_array_new();

    if (!hex_str_to_bytes(str, bytes, FALSE) || bytes->len > 6) {
        g_byte_array_free(bytes, TRUE);
        return false;
    }

    memset(buf, 0, 6);
    memcpy(buf, bytes->data, bytes->len);
    g_byte_array_free(bytes, TRUE);

    /* Mask out locally administered/multicast flag. */
    buf[0] &= 0xFC;

    return true;
}

void ManufDialog::searchPrefix(QString &text)
{
    struct ws_manuf result, *ptr;
    uint8_t addr_buf[6];
    char addr_str[ADDR_BUFSIZE];

    model_->clear();

    if (!text_to_addr(qUtf8Printable(text), addr_buf)) {
        ui->hintLabel->setText(QString("<small><i>\"%1\" is not a valid MAC address</i></small>").arg(text));
        return;
    }

    ptr = ws_manuf_lookup(addr_buf, &result);
    if (ptr == nullptr) {
        snprint_addr(addr_buf, 0, addr_str, sizeof(addr_str));
        ui->hintLabel->setText(QString("<small><i>\"%1\" not found</i></small>").arg(addr_str));
        return;
    }

    snprint_addr(result.addr, result.mask, addr_str, sizeof(addr_str));
    QString prefix = QString::fromUtf8(addr_str);
    QString short_name = QString::fromUtf8(result.short_name);
    QString vendor_name = QString::fromUtf8(result.long_name);
    model_->addRecord(prefix, short_name, vendor_name);

    snprint_addr(addr_buf, 0, addr_str, sizeof(addr_str));
    ui->hintLabel->setText(QString("<small><i>Found \"%1\"</i></small>").arg(addr_str));
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
