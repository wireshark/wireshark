/* imsi_list_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "imsi_list_dialog.h"
#include <ui_imsi_list_dialog.h>

#include "file.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "progress_frame.h"
#include "main_application.h"

ImsiListDialog::ImsiListDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ImsiListDialog),
    parent_(parent)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 3 / 4, parent.height() * 2 / 3);
    setWindowSubtitle(tr("IMSI List"));

    model_ = new QStandardItemModel(this);
    model_->setColumnCount(5);
    model_->setHorizontalHeaderLabels(QStringList()
        << tr("IMSI")
        << tr("Packets")
        << tr("First Frame")
        << tr("Last Frame")
        << tr("Protocols"));
    ui->imsiTreeView->setModel(model_);
    ui->imsiTreeView->sortByColumn(2, Qt::AscendingOrder); /* Sort by first frame */

    connect(ui->imsiTreeView->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(updateWidgets()));

    /* Double-click applies filter for that IMSI */
    connect(ui->imsiTreeView, &QTreeView::doubleClicked,
            this, &ImsiListDialog::onImsiDoubleClicked);

    prepare_button_ = ui->buttonBox->addButton(tr("Prepare Filter"), QDialogButtonBox::ActionRole);
    prepare_button_->setToolTip(tr("Prepare a display filter matching selected IMSIs."));
    connect(prepare_button_, &QPushButton::clicked, this, &ImsiListDialog::prepareFilter);

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    /* Register tap listener */
    const char *filter = NULL;
    if (cap_file_.isValid() && cap_file_.capFile()->dfilter) {
        filter = cap_file_.capFile()->dfilter;
        ui->displayFilterCheckBox->setChecked(true);
    }
    registerTapListener("imsi", this, filter,
                        TL_REQUIRES_NOTHING,
                        tapReset, tapPacket, tapDraw);

    /* Connect checkbox AFTER initial registration to avoid double-tap */
    connect(ui->displayFilterCheckBox, &QCheckBox::toggled,
            this, &ImsiListDialog::displayFilterCheckBoxToggled);

    updateWidgets();

    if (cap_file_.isValid()) {
        cap_file_.delayedRetapPackets();
    }
}

ImsiListDialog::~ImsiListDialog()
{
    resetData();
    delete ui;
}

void ImsiListDialog::captureFileClosing()
{
    ui->displayFilterCheckBox->setEnabled(false);
    WiresharkDialog::captureFileClosing();
}

/* Static tap callbacks */
void ImsiListDialog::tapReset(void *tapdata)
{
    ImsiListDialog *dialog = static_cast<ImsiListDialog*>(tapdata);
    dialog->resetData();
}

tap_packet_status ImsiListDialog::tapPacket(void *tapdata, packet_info *pinfo _U_,
                                            epan_dissect_t *edt _U_, const void *data,
                                            tap_flags_t flags _U_)
{
    ImsiListDialog *dialog = static_cast<ImsiListDialog*>(tapdata);
    const tap_imsi_info_t *tap_info = static_cast<const tap_imsi_info_t*>(data);

    if (!tap_info || !tap_info->imsi)
        return TAP_PACKET_DONT_REDRAW;

    QString imsi_str = QString::fromUtf8(tap_info->imsi);
    QString protocol = tap_info->protocol ? QString::fromUtf8(tap_info->protocol) : QString();

    /* Update or create IMSI entry */
    ImsiEntry *entry = dialog->imsi_entries_.value(imsi_str, nullptr);
    if (!entry) {
        entry = new ImsiEntry();
        entry->imsi = imsi_str;
        entry->packet_count = 0;
        entry->first_frame = tap_info->frame_number;
        entry->last_frame = tap_info->frame_number;
        dialog->imsi_entries_.insert(imsi_str, entry);
    }

    /* Deduplicate: only count each frame once per IMSI */
    if (!entry->seen_frames.contains(tap_info->frame_number)) {
        entry->seen_frames.insert(tap_info->frame_number);
        entry->packet_count++;
        if (tap_info->frame_number > entry->last_frame)
            entry->last_frame = tap_info->frame_number;
    }

    /* Always collect protocols, even from duplicate tap calls */
    if (!protocol.isEmpty() && !entry->protocols.contains(protocol))
        entry->protocols.append(protocol);

    return TAP_PACKET_REDRAW;
}

void ImsiListDialog::tapDraw(void *tapdata)
{
    ImsiListDialog *dialog = static_cast<ImsiListDialog*>(tapdata);
    dialog->updateModel();
}

/* Data management */
void ImsiListDialog::resetData()
{
    qDeleteAll(imsi_entries_);
    imsi_entries_.clear();
}

void ImsiListDialog::updateModel()
{
    model_->removeRows(0, model_->rowCount());

    QList<ImsiEntry*> entries = imsi_entries_.values();
    /* Sort by first_frame */
    std::sort(entries.begin(), entries.end(), [](const ImsiEntry *a, const ImsiEntry *b) {
        return a->first_frame < b->first_frame;
    });

    for (const ImsiEntry *entry : entries) {
        QList<QStandardItem*> row;
        QStandardItem *imsi_item = new QStandardItem(entry->imsi);
        imsi_item->setData(entry->imsi, Qt::UserRole);

        QStandardItem *count_item = new QStandardItem();
        count_item->setData((int)entry->packet_count, Qt::DisplayRole);

        QStandardItem *first_item = new QStandardItem();
        first_item->setData((int)entry->first_frame, Qt::DisplayRole);

        QStandardItem *last_item = new QStandardItem();
        last_item->setData((int)entry->last_frame, Qt::DisplayRole);

        QStandardItem *proto_item = new QStandardItem(entry->protocols.join(", "));

        row << imsi_item << count_item << first_item << last_item << proto_item;
        model_->appendRow(row);
    }

    for (int i = 0; i < model_->columnCount(); i++) {
        ui->imsiTreeView->resizeColumnToContents(i);
    }

    ui->hintLabel->setText(tr("<small>%1 IMSIs found. Double-click to filter.</small>").arg(imsi_entries_.size()));
}

/* Slots */
void ImsiListDialog::updateWidgets()
{
    bool has_selection = ui->imsiTreeView->selectionModel()->hasSelection();
    prepare_button_->setEnabled(has_selection);
}

void ImsiListDialog::onImsiDoubleClicked(const QModelIndex &index)
{
    if (!index.isValid()) return;

    /* Get IMSI from column 0 of the clicked row */
    QModelIndex imsi_index = model_->index(index.row(), 0);
    QString imsi = imsi_index.data(Qt::UserRole).toString();
    if (imsi.isEmpty()) return;

    QString filter = QString("e212.assoc.imsi == \"%1\"").arg(imsi);
    emit updateFilter(filter, true);
}

void ImsiListDialog::prepareFilter()
{
    QStringList filter_parts;
    foreach (QModelIndex index, ui->imsiTreeView->selectionModel()->selectedRows(0)) {
        QString imsi = index.data(Qt::UserRole).toString();
        if (!imsi.isEmpty())
            filter_parts << QString("e212.assoc.imsi == \"%1\"").arg(imsi);
    }

    if (filter_parts.isEmpty()) return;

    QString filter;
    if (filter_parts.size() == 1) {
        filter = filter_parts.first();
    } else {
        filter = "(" + filter_parts.join(" || ") + ")";
    }

    emit updateFilter(filter, true);
}

void ImsiListDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == ui->buttonBox->button(QDialogButtonBox::Close)) {
        close();
    }
}

void ImsiListDialog::displayFilterCheckBoxToggled(bool checked)
{
    if (!cap_file_.isValid()) return;

    const char *filter = NULL;
    if (checked && cap_file_.capFile()->dfilter) {
        filter = cap_file_.capFile()->dfilter;
    }

    removeTapListeners();
    registerTapListener("imsi", this, filter,
                        TL_REQUIRES_NOTHING,
                        tapReset, tapPacket, tapDraw);
    cap_file_.delayedRetapPackets();
}
