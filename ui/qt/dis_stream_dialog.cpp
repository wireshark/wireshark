/* dis_stream_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "dis_stream_dialog.h"

#include "dis_audio_stream.h"

#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QFormLayout>
#include <QSignalBlocker>
#include <QTextStream>
#include <QVBoxLayout>

#include "epan/addr_resolv.h"

#include "main_application.h"

DisStreamDialog *DisStreamDialog::pinstance_ = nullptr;
std::mutex DisStreamDialog::mutex_;

enum {
    dis_col_start_time = 0,
    dis_col_end_time,
    dis_col_src_addr,
    dis_col_src_port,
    dis_col_dst_addr,
    dis_col_dst_port,
    dis_col_radio,
    dis_col_entity,
    dis_col_signal_pkts,
    dis_col_tx_pkts,
    dis_col_lost,
    dis_col_max_delta,
    dis_col_mean_jitter,
    dis_col_max_jitter,
    dis_col_problem,
    dis_col_count
};

static constexpr int disstream_ptr_role = Qt::UserRole + 100;

bool
DisStreamDialog::DisStreamTreeWidgetItem::operator<(const QTreeWidgetItem &other) const
{
    int sort_col = treeWidget() ? treeWidget()->sortColumn() : 0;
    QVariant lhs = data(sort_col, Qt::UserRole);
    QVariant rhs = other.data(sort_col, Qt::UserRole);

    if (lhs.isValid() && rhs.isValid()) {
        if (lhs.metaType().id() == QMetaType::Double || rhs.metaType().id() == QMetaType::Double) {
            return lhs.toDouble() < rhs.toDouble();
        }

        return lhs.toLongLong() < rhs.toLongLong();
    }

    return QTreeWidgetItem::operator<(other);
}

DisStreamDialog *
DisStreamDialog::openDisStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!pinstance_) {
        pinstance_ = new DisStreamDialog(parent, cf, packet_list);
    }

    return pinstance_;
}

DisStreamDialog::DisStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list) :
    WiresharkDialog(parent, cf),
    stream_tree_(new QTreeWidget(this)),
    button_box_(new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this)),
    filter_button_(nullptr),
    play_button_(nullptr),
    stop_button_(nullptr),
    analyze_button_(nullptr),
    need_redraw_(false),
    packet_list_(packet_list)
#ifdef QT_MULTIMEDIA_LIB
    , audio_stream_(new DisAudioStream(this))
#endif
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    QFormLayout *summary_layout = new QFormLayout;

    setWindowSubtitle(tr("DIS Streams"));

    layout->addLayout(summary_layout);

    stream_tree_->setRootIsDecorated(false);
    stream_tree_->setAlternatingRowColors(true);
    stream_tree_->setSortingEnabled(true);
    stream_tree_->setSelectionMode(QAbstractItemView::SingleSelection);
    stream_tree_->setUniformRowHeights(true);
    stream_tree_->setContextMenuPolicy(Qt::ActionsContextMenu);
    stream_tree_->setColumnCount(dis_col_count);
    stream_tree_->setHeaderLabels(QStringList()
        << tr("Start")
        << tr("End")
        << tr("Src Address")
        << tr("Src Port")
        << tr("Dst Address")
        << tr("Dst Port")
        << tr("Radio")
        << tr("Entity")
        << tr("Signal")
        << tr("Tx")
        << tr("Lost")
        << tr("Max Delta (ms)")
        << tr("Mean Jitter (ms)")
        << tr("Max Jitter (ms)")
        << tr("Pb"));
    stream_tree_->header()->setSortIndicator(dis_col_start_time, Qt::AscendingOrder);
    stream_tree_->header()->setSectionResizeMode(QHeaderView::ResizeToContents);

    layout->addWidget(stream_tree_);

    filter_button_ = button_box_->addButton(tr("Prepare Filter"), QDialogButtonBox::ActionRole);
    play_button_ = button_box_->addButton(tr("Play"), QDialogButtonBox::ActionRole);
    stop_button_ = button_box_->addButton(tr("Stop"), QDialogButtonBox::ActionRole);
    analyze_button_ = button_box_->addButton(tr("Analyze"), QDialogButtonBox::ActionRole);
    layout->addWidget(button_box_);

    connect(button_box_, &QDialogButtonBox::rejected, this, &DisStreamDialog::reject);
    connect(filter_button_, &QPushButton::clicked, this, &DisStreamDialog::onPrepareFilter);
    connect(analyze_button_, &QPushButton::clicked, this, &DisStreamDialog::onAnalyzeStream);
#ifdef QT_MULTIMEDIA_LIB
    connect(play_button_, &QPushButton::clicked, this, &DisStreamDialog::onPlayStream);
    connect(stop_button_, &QPushButton::clicked, this, &DisStreamDialog::onStopStream);
    connect(audio_stream_, &DisAudioStream::playbackStateChanged,
        this, &DisStreamDialog::onPlaybackStateChanged);
#endif
    connect(stream_tree_, &QTreeWidget::itemSelectionChanged, this, &DisStreamDialog::onStreamSelectionChanged);
    connect(stream_tree_, &QTreeWidget::itemDoubleClicked, this, &DisStreamDialog::onStreamItemDoubleClicked);
    connect(&cap_file_, &CaptureFile::captureEvent, this, &DisStreamDialog::onCaptureEvent);

    if (packet_list_) {
        connect(this, SIGNAL(goToPacket(int)), packet_list_, SLOT(goToPacket(int)));
    }
    connect(this, SIGNAL(updateFilter(QString, bool)), &parent, SLOT(filterPackets(QString, bool)));

    memset(&tapinfo_, 0, sizeof(tapinfo_));
    tapinfo_.mode = DISSTREAM_TAP_ANALYSE;
    tapinfo_.tap_reset = tapReset;
    tapinfo_.tap_draw = tapDraw;

    register_tap_listener_disstream(&tapinfo_, NULL, NULL);

    if (cap_file_.isValid()) {
        cap_file_.delayedRetapPackets();
    }

    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);
    updateWidgets();
}

DisStreamDialog::~DisStreamDialog()
{
    std::lock_guard<std::mutex> lock(mutex_);

#ifdef QT_MULTIMEDIA_LIB
    audio_stream_->stopPlayback();
#endif

    disstream_reset(&tapinfo_);
    remove_tap_listener_disstream(&tapinfo_);
    pinstance_ = nullptr;
}

void
DisStreamDialog::captureFileClosing()
{
#ifdef QT_MULTIMEDIA_LIB
    audio_stream_->stopPlayback();
#endif
    remove_tap_listener_disstream(&tapinfo_);
    disstream_reset(&tapinfo_);
}

void
DisStreamDialog::captureFileClosed()
{
#ifdef QT_MULTIMEDIA_LIB
    audio_stream_->stopPlayback();
#endif
    stream_tree_->clear();
}

void
DisStreamDialog::tapReset(disstream_tapinfo_t *tapinfo _U_)
{
    if (!pinstance_) {
        return;
    }

    pinstance_->need_redraw_ = true;
}

void
DisStreamDialog::tapDraw(disstream_tapinfo_t *tapinfo _U_)
{
    if (!pinstance_) {
        return;
    }

    pinstance_->need_redraw_ = true;
    QMetaObject::invokeMethod(pinstance_, [=]() { pinstance_->updateStreams(); }, Qt::QueuedConnection);
}

disstream_info_t *
DisStreamDialog::selectedStream() const
{
    QTreeWidgetItem *current = stream_tree_->currentItem();
    if (!current) {
        return nullptr;
    }

    quintptr ptr = current->data(0, disstream_ptr_role).value<quintptr>();
    return reinterpret_cast<disstream_info_t *>(ptr);
}

void
DisStreamDialog::updateStreams()
{
    GList *list;
    disstream_info_t *previous = selectedStream();
    QTreeWidgetItem *item_to_select = nullptr;

    if (!need_redraw_ || fileClosed()) {
        updateWidgets();
        return;
    }

    QSignalBlocker signal_blocker(stream_tree_);

    stream_tree_->setSortingEnabled(false);
    stream_tree_->clear();

    list = g_list_first(tapinfo_.strinfo_list);
    while (list) {
        disstream_info_t *stream_info = (disstream_info_t *)list->data;
        DisStreamTreeWidgetItem *item;
        char *src_addr;
        char *dst_addr;

        item = new DisStreamTreeWidgetItem(stream_tree_);
        item->setData(0, disstream_ptr_role, QVariant::fromValue((quintptr)stream_info));
        if ((previous && previous == stream_info) || (!previous && !item_to_select)) {
            item_to_select = item;
        }

        src_addr = address_to_display(NULL, &stream_info->id.src_addr);
        dst_addr = address_to_display(NULL, &stream_info->id.dst_addr);

        item->setText(dis_col_start_time, QString::number(nstime_to_sec(&stream_info->start_rel_time), 'f', 6));
        item->setData(dis_col_start_time, Qt::UserRole, nstime_to_sec(&stream_info->start_rel_time));

        item->setText(dis_col_end_time, QString::number(nstime_to_sec(&stream_info->stop_rel_time), 'f', 6));
        item->setData(dis_col_end_time, Qt::UserRole, nstime_to_sec(&stream_info->stop_rel_time));

        item->setText(dis_col_src_addr, src_addr);
        item->setText(dis_col_src_port, QString::number(stream_info->id.src_port));
        item->setData(dis_col_src_port, Qt::UserRole, (int)stream_info->id.src_port);

        item->setText(dis_col_dst_addr, dst_addr);
        item->setText(dis_col_dst_port, QString::number(stream_info->id.dst_port));
        item->setData(dis_col_dst_port, Qt::UserRole, (int)stream_info->id.dst_port);

        item->setText(dis_col_radio, QStringLiteral("0x%1").arg(stream_info->id.radio_id, 4, 16, QChar('0')));
        item->setData(dis_col_radio, Qt::UserRole, (int)stream_info->id.radio_id);

        item->setText(dis_col_entity, QStringLiteral("%1/%2/%3")
            .arg(stream_info->id.entity_id_site)
            .arg(stream_info->id.entity_id_appl)
            .arg(stream_info->id.entity_id_entity));

        item->setText(dis_col_signal_pkts, QString::number(stream_info->signal_packet_count));
        item->setData(dis_col_signal_pkts, Qt::UserRole, (int)stream_info->signal_packet_count);

        item->setText(dis_col_tx_pkts, QString::number(stream_info->transmitter_packet_count));
        item->setData(dis_col_tx_pkts, Qt::UserRole, (int)stream_info->transmitter_packet_count);

        item->setText(dis_col_lost, QString::number(stream_info->estimated_lost_packets));
        item->setData(dis_col_lost, Qt::UserRole, (int)stream_info->estimated_lost_packets);

        item->setText(dis_col_max_delta, QString::number(stream_info->max_delta_ms, 'f', 3));
        item->setData(dis_col_max_delta, Qt::UserRole, stream_info->max_delta_ms);

        item->setText(dis_col_mean_jitter, QString::number(stream_info->mean_jitter_ms, 'f', 3));
        item->setData(dis_col_mean_jitter, Qt::UserRole, stream_info->mean_jitter_ms);

        item->setText(dis_col_max_jitter, QString::number(stream_info->max_jitter_ms, 'f', 3));
        item->setData(dis_col_max_jitter, Qt::UserRole, stream_info->max_jitter_ms);

        item->setText(dis_col_problem, stream_info->problem ? tr("X") : QString());
        item->setTextAlignment(dis_col_problem, Qt::AlignCenter);

        wmem_free(NULL, src_addr);
        wmem_free(NULL, dst_addr);

        list = g_list_next(list);
    }

    stream_tree_->setSortingEnabled(true);
    stream_tree_->sortByColumn(stream_tree_->header()->sortIndicatorSection(),
        stream_tree_->header()->sortIndicatorOrder());
    if (item_to_select) {
        stream_tree_->setCurrentItem(item_to_select);
    }

    need_redraw_ = false;
    updateWidgets();
}

void
DisStreamDialog::updateWidgets()
{
    bool has_capture = cap_file_.isValid() && !fileClosed();
    disstream_info_t *stream_info = selectedStream();
    bool has_selection = stream_info != nullptr;
    bool has_audio_data = has_selection && stream_info->signal_packets && stream_info->signal_packets->len > 0;

    stream_tree_->setEnabled(has_capture);
    filter_button_->setEnabled(has_capture && has_selection);
    play_button_->setEnabled(has_capture && has_audio_data);
    analyze_button_->setEnabled(has_capture && has_selection);
#ifdef QT_MULTIMEDIA_LIB
    stop_button_->setEnabled(audio_stream_->isPlaying());
#else
    stop_button_->setEnabled(false);
#endif
}

void
DisStreamDialog::onStreamSelectionChanged()
{
#ifdef QT_MULTIMEDIA_LIB
    disstream_info_t *stream_info = selectedStream();

    if (audio_stream_->currentStream() != nullptr &&
        audio_stream_->currentStream() != stream_info &&
        (audio_stream_->isPlaying() || audio_stream_->isPaused())) {
        audio_stream_->stopPlayback();
    }
#endif
    updateWidgets();
}

void
DisStreamDialog::onStreamItemDoubleClicked(QTreeWidgetItem *item, int column _U_)
{
    quintptr ptr;
    disstream_info_t *stream_info;

    if (!item) {
        return;
    }

    ptr = item->data(0, disstream_ptr_role).value<quintptr>();
    stream_info = reinterpret_cast<disstream_info_t *>(ptr);
    if (stream_info && stream_info->first_packet_num > 0) {
        emit goToPacket((int)stream_info->first_packet_num);
    }
}

void
DisStreamDialog::onPrepareFilter()
{
    disstream_info_t *stream_info = selectedStream();
    QString filter;

    if (!stream_info) {
        return;
    }

    filter = QStringLiteral(
        "dis && udp.srcport==%1 && udp.dstport==%2 && "
        "dis.radio.radio_id==%3 && dis.entity_id_site==%4 && "
        "dis.entity_id_application==%5 && dis.entity_id_entity==%6")
        .arg(stream_info->id.src_port)
        .arg(stream_info->id.dst_port)
        .arg(stream_info->id.radio_id)
        .arg(stream_info->id.entity_id_site)
        .arg(stream_info->id.entity_id_appl)
        .arg(stream_info->id.entity_id_entity);

    emit updateFilter(filter, true);
}

void
DisStreamDialog::onAnalyzeStream()
{
    disstream_info_t *stream_info = selectedStream();
    QWidget *parent_widget = qobject_cast<QWidget *>(parent());

    if (!stream_info) {
        return;
    }

    if (!parent_widget) {
        parent_widget = this;
    }

    DisStreamAnalysisDialog *dialog = DisStreamAnalysisDialog::openDisStreamAnalysisDialog(
        *parent_widget, cap_file_, packet_list_);
    dialog->selectStream(stream_info);
    dialog->show();
    dialog->raise();
    dialog->activateWindow();
}

#ifdef QT_MULTIMEDIA_LIB
void
DisStreamDialog::onPlayStream()
{
    disstream_info_t *stream_info = selectedStream();
    QString error_message;

    if (!audio_stream_->playDisStream(stream_info, error_message)) {
        QMessageBox::warning(this, tr("DIS Playback"), error_message);
        return;
    }
    updateWidgets();
}

void
DisStreamDialog::onStopStream()
{
    audio_stream_->stopPlayback();
    updateWidgets();
}

void
DisStreamDialog::onPlaybackStateChanged(QAudio::State state _U_)
{
    updateWidgets();
}
#endif

void
DisStreamDialog::onCaptureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap) {
        need_redraw_ = true;
    }

    updateStreams();
}
