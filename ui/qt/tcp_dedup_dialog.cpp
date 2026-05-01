/* tcp_dedup_dialog.cpp
 * Dialog display for duplication detection table
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tcp_dedup_dialog.h"

#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <epan/prefs-int.h>
#include <ui/tap-tcp-stream.h>
#include <wsutil/nstime.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

/* Column indices */
enum {
    COL_DEDUP_TIME = 0,
    COL_DEDUP_DELTA,
    COL_DEDUP_FRAME,
    COL_DEDUP_COUNT,
    COL_DEDUP_FRAMES,
    COL_DEDUP_INFO,
    COL_DEDUP_COUNT_
};

QSet<TcpDedupDialog *> TcpDedupDialog::live_instances_;

TcpDedupDialog::TcpDedupDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    stream_(UINT32_MAX),
    first_stream_pkt_(true),
    table_(new QTableWidget(this)),
    button_box_(new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this)),
    stream_edit_(nullptr)
{
    live_instances_.insert(this);
    prev_stream_ts_ = {0, 0};

    setAttribute(Qt::WA_DeleteOnClose, true);
    setWindowSubtitle(tr("TCP Duplication Table"));

    stream_ = select_tcpip_session(cap_file_.capFile());
    if (stream_ == UINT32_MAX) {
        done(QDialog::Rejected);
        return;
    }

    pref_t *dup_pref = prefs_find_preference(prefs_find_module("tcp"), "detect_duplicate_packets");
    if (!dup_pref || !prefs_get_bool_value(dup_pref, pref_current)) {
        table_->hide();
        QLabel *msg = new QLabel(
            tr("The \"Detect duplication (capture-level) packets\" preference must be enabled in\n"
               "Preferences \xe2\x86\x92 Protocols \xe2\x86\x92 TCP to use this table."),
            this);
        msg->setAlignment(Qt::AlignCenter);

        connect(button_box_, &QDialogButtonBox::rejected, this, &QDialog::reject);

        QVBoxLayout *layout = new QVBoxLayout(this);
        layout->addWidget(msg);
        layout->addWidget(button_box_);
        setLayout(layout);

        adjustSize();
        setFixedSize(sizeHint());
        setResult(QDialog::Accepted);
        return;
    }

    table_->setColumnCount(COL_DEDUP_COUNT_);
    table_->setHorizontalHeaderLabels({
        tr("Time"), tr("Delta"), tr("Frame Number"),
        tr("Duplication Total"), tr("Frame List"), tr("Info")
    });
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setVisible(false);

    stream_edit_ = new QLineEdit(this);
    stream_edit_->setValidator(new QIntValidator(0, INT_MAX, stream_edit_));
    stream_edit_->setText(QString::number(stream_));
    stream_edit_->setFixedWidth(80);
    stream_edit_->setAlignment(Qt::AlignRight);

    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        QTableWidgetItem *item = table_->item(row, COL_DEDUP_FRAME);
        if (item) emit goToPacket(item->data(Qt::UserRole).toInt());
    });

    connect(stream_edit_, &QLineEdit::returnPressed, this, [this]() {
        bool ok;
        uint32_t new_stream = stream_edit_->text().toUInt(&ok);
        if (!ok || new_stream == stream_)
            return;
        stream_ = new_stream;
        cap_file_.retapPackets();
    });

    connect(button_box_, &QDialogButtonBox::rejected, this, &QDialog::reject);
    if (auto *btn = button_box_->button(QDialogButtonBox::Close))
        btn->setAutoDefault(false);

    QHBoxLayout *bottom_hbox = new QHBoxLayout;
    bottom_hbox->addWidget(new QLabel(tr("Stream:"), this));
    bottom_hbox->addWidget(stream_edit_);
    bottom_hbox->addStretch();
    bottom_hbox->addWidget(button_box_);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->addWidget(table_);
    layout->addLayout(bottom_hbox);
    setLayout(layout);

    resize(parent.width() * 2 / 3, parent.height() / 2);

    registerTapListener("tcp", this, nullptr, TL_REQUIRES_COLUMNS, tapReset, tapPacket, tapDraw);
    cap_file_.retapPackets();
    setResult(QDialog::Accepted);
}

TcpDedupDialog::~TcpDedupDialog()
{
    /* Remove from the live-instances set first, so any tap callback that
     * fires after this point sees a stale tapdata and bails out. */
    live_instances_.remove(this);
    /* Safety net: ensure the tap listener can never outlive the dialog. If
     * reject()/accept() already ran, the list is empty and this is a no-op. */
    removeTapListeners();
    /* Drop any posted Qt events (mouse, key, etc.) targeting this dialog or
     * any of its child widgets. Without this, an event already in the queue
     * for a child can be delivered after the child is destroyed and segfault
     * inside QWidget::event. */
    QCoreApplication::removePostedEvents(this);
    for (QObject *child : findChildren<QObject *>()) {
        QCoreApplication::removePostedEvents(child);
    }
}

void TcpDedupDialog::tapReset(void *tapdata)
{
    TcpDedupDialog *d = static_cast<TcpDedupDialog *>(tapdata);
    if (!live_instances_.contains(d))
        return;
    d->groups_.clear();
    d->prev_stream_ts_ = {0, 0};
    d->first_stream_pkt_ = true;
}

tap_packet_status TcpDedupDialog::tapPacket(void *tapdata, _packet_info *pinfo,
                                             epan_dissect *, const void *data,
                                             tap_flags_t)
{
    TcpDedupDialog *d = static_cast<TcpDedupDialog *>(tapdata);
    if (!live_instances_.contains(d))
        return TAP_PACKET_DONT_REDRAW;
    const tcp_info_t *tcph = static_cast<const tcp_info_t *>(data);

    if (tcph->th_stream != d->stream_)
        return TAP_PACKET_DONT_REDRAW;

    /* Compute delta from previous stream packet before updating the tracker. */
    double delta_secs = -1.0;
    if (!d->first_stream_pkt_) {
        nstime_t delta;
        nstime_delta(&delta, &pinfo->abs_ts, &d->prev_stream_ts_);
        delta_secs = nstime_to_sec(&delta);
    }
    d->prev_stream_ts_ = pinfo->abs_ts;
    d->first_stream_pkt_ = false;

    /* We still need to track all stream packets for delta, but only accumulate
     * dedup groups for packets that went through dedup analysis. */
    if (tcph->th_dup_count == 0)
        return TAP_PACKET_DONT_REDRAW;

    uint32_t orig      = tcph->th_dup_orig_frame;
    uint32_t frame_num = pinfo->num;

    DedupGroup &group = d->groups_[orig];
    if (group.frames.isEmpty()) {
        group.first_abs_ts = pinfo->abs_ts;
        group.delta_secs   = delta_secs;
        group.orig_frame   = orig;
        group.max_count    = tcph->th_dup_count;
        const char *info   = col_get_text(pinfo->cinfo, COL_INFO);
        group.info         = info ? QString(info) : QString();
    } else if (tcph->th_dup_count > group.max_count) {
        group.max_count = tcph->th_dup_count;
    }
    if (!group.frames.contains(frame_num))
        group.frames.append(frame_num);

    return TAP_PACKET_REDRAW;
}

void TcpDedupDialog::tapDraw(void *tapdata)
{
    TcpDedupDialog *d = static_cast<TcpDedupDialog *>(tapdata);
    if (!live_instances_.contains(d))
        return;
    d->populateTable();
}

void TcpDedupDialog::populateTable()
{
    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    for (const DedupGroup &g : groups_) {
        if (g.max_count < 2)
            continue;

        int row = table_->rowCount();
        table_->insertRow(row);

        /* Time — local time-of-day as HH:mm:ss.zzz */
        qint64 ms = (qint64)g.first_abs_ts.secs * 1000LL
                    + g.first_abs_ts.nsecs / 1000000;
        QString time_str = QDateTime::fromMSecsSinceEpoch(ms).toString("HH:mm:ss.zzz");
        QTableWidgetItem *time_item = new QTableWidgetItem(time_str);
        time_item->setData(Qt::UserRole, ms);
        table_->setItem(row, COL_DEDUP_TIME, time_item);

        /* Delta — seconds since previous stream packet */
        QString delta_str = (g.delta_secs < 0.0)
                            ? QStringLiteral("-")
                            : QString::number(g.delta_secs, 'f', 6);
        QTableWidgetItem *delta_item = new QTableWidgetItem(delta_str);
        delta_item->setData(Qt::UserRole, g.delta_secs);
        table_->setItem(row, COL_DEDUP_DELTA, delta_item);

        /* Frame Number */
        QTableWidgetItem *frame_item = new QTableWidgetItem(QString::number(g.orig_frame));
        frame_item->setData(Qt::UserRole, static_cast<int>(g.orig_frame));
        table_->setItem(row, COL_DEDUP_FRAME, frame_item);

        /* Dedup Count */
        QTableWidgetItem *count_item = new QTableWidgetItem(QString::number(g.max_count));
        count_item->setData(Qt::UserRole, static_cast<int>(g.max_count));
        table_->setItem(row, COL_DEDUP_COUNT, count_item);

        /* Frame List */
        QStringList parts;
        for (uint32_t f : g.frames)
            parts << QString("#%1").arg(f);
        table_->setItem(row, COL_DEDUP_FRAMES, new QTableWidgetItem(parts.join(", ")));

        /* Info */
        table_->setItem(row, COL_DEDUP_INFO, new QTableWidgetItem(g.info));
    }

    table_->resizeColumnsToContents();
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSortingEnabled(true);
    table_->sortByColumn(COL_DEDUP_TIME, Qt::AscendingOrder);
}
