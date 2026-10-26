/* dis_stream_analysis_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "dis_stream_analysis_dialog.h"

#include "dis_audio_stream.h"

#include <QComboBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QMouseEvent>
#include <QVBoxLayout>

#include "epan/addr_resolv.h"

#include "ui/qt/utils/zoom_scaling.h"
#include "ui/qt/utils/plot_theme.h"
#include "ui/qt/utils/theme_manager.h"
#include "ui/qt/widgets/qcustomplot.h"

DisStreamAnalysisDialog *DisStreamAnalysisDialog::pinstance_ = nullptr;
std::mutex DisStreamAnalysisDialog::mutex_;

enum {
    dis_pkt_col_frame = 0,
    dis_pkt_col_time,
    dis_pkt_col_delta,
    dis_pkt_col_jitter,
    dis_pkt_col_lost,
    dis_pkt_col_status,
    dis_pkt_col_count
};

static constexpr int dis_frame_num_role = Qt::UserRole + 110;

DisStreamAnalysisDialog *
DisStreamAnalysisDialog::openDisStreamAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!pinstance_) {
        pinstance_ = new DisStreamAnalysisDialog(parent, cf, packet_list);
    }

    return pinstance_;
}

void
DisStreamAnalysisDialog::selectStream(disstream_info_t *stream_info)
{
    if (!stream_info) {
        have_requested_stream_ = false;
        return;
    }

    if (have_requested_stream_) {
        disstream_id_free(&requested_stream_id_);
    }
    disstream_id_copy(&stream_info->id, &requested_stream_id_);
    have_requested_stream_ = true;

    for (int i = 0; i < stream_combo_->count(); i++) {
        quintptr ptr = stream_combo_->itemData(i).value<quintptr>();
        disstream_info_t *candidate = reinterpret_cast<disstream_info_t *>(ptr);
        if (candidate && disstream_id_equal(&candidate->id, &stream_info->id)) {
            stream_combo_->setCurrentIndex(i);
            return;
        }
    }
}

DisStreamAnalysisDialog::DisStreamAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list) :
    WiresharkDialog(parent, cf),
    stream_combo_(new QComboBox(this)),
    audio_plot_(new QCustomPlot(this)),
    packet_tree_(new QTreeWidget(this)),
    duration_label_(new QLabel(this)),
    packets_label_(new QLabel(this)),
    signal_label_(new QLabel(this)),
    tx_label_(new QLabel(this)),
    lost_label_(new QLabel(this)),
    jitter_label_(new QLabel(this)),
    delta_label_(new QLabel(this)),
    codec_label_(new QLabel(this)),
    hint_label_(new QLabel(this)),
    playback_progress_(new QProgressBar(this)),
    playback_time_label_(new QLabel(this)),
    button_box_(new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this)),
    play_button_(nullptr),
    stop_button_(nullptr),
    goto_button_(nullptr),
    start_marker_pos_(nullptr),
    playback_marker_pos_(nullptr),
    start_marker_time_(0.0),
    playback_marker_time_(0.0),
    need_redraw_(false),
    have_requested_stream_(false),
    packet_list_(packet_list)
#ifdef QT_MULTIMEDIA_LIB
    , audio_stream_(new DisAudioStream(this))
#endif
{
    QVBoxLayout *layout = new QVBoxLayout(this);
    QFormLayout *form_layout = new QFormLayout;

    setWindowSubtitle(tr("DIS Stream Analysis"));

    form_layout->addRow(tr("Stream"), stream_combo_);
    form_layout->addRow(tr("Codec"), codec_label_);
    form_layout->addRow(tr("Duration (s)"), duration_label_);
    form_layout->addRow(tr("Packets"), packets_label_);
    form_layout->addRow(tr("Signal Packets"), signal_label_);
    form_layout->addRow(tr("Transmitter Packets"), tx_label_);
    form_layout->addRow(tr("Estimated Lost"), lost_label_);
    form_layout->addRow(tr("Jitter (mean/max ms)"), jitter_label_);
    form_layout->addRow(tr("Delta (mean/max ms)"), delta_label_);

    layout->addLayout(form_layout);

    audio_plot_->setMinimumHeight(220);
    ZoomScaling::scaleSizeLimits(audio_plot_);
    audio_plot_->legend->setVisible(true);
    audio_plot_->xAxis->setLabel(tr("Capture Time (s)"));
    audio_plot_->yAxis->setLabel(tr("Amplitude"));
    audio_plot_->setInteraction(QCP::iRangeDrag, true);
    audio_plot_->setInteraction(QCP::iRangeZoom, true);
    start_marker_pos_ = new QCPItemStraightLine(audio_plot_);
    start_marker_pos_->setVisible(false);
    playback_marker_pos_ = new QCPItemStraightLine(audio_plot_);
    playback_marker_pos_->setVisible(false);
    PlotTheme::track(audio_plot_, [this]() {
        start_marker_pos_->setPen(QPen(ThemeManager::instance()->color(ThemeManager::AccentSuccess), 3));
        playback_marker_pos_->setPen(QPen(PlotTheme::textColor(), 1));
    });

    layout->addWidget(audio_plot_);

    hint_label_->setTextFormat(Qt::RichText);
    hint_label_->setWordWrap(true);
    layout->addWidget(hint_label_);

    QHBoxLayout *progress_layout = new QHBoxLayout;
    playback_progress_->setRange(0, 1000);
    playback_progress_->setValue(0);
    playback_progress_->setTextVisible(false);
    playback_time_label_->setText(tr("0.000 / 0.000 s"));
    progress_layout->addWidget(new QLabel(tr("Playback"), this));
    progress_layout->addWidget(playback_progress_);
    progress_layout->addWidget(playback_time_label_);
    layout->addLayout(progress_layout);

    packet_tree_->setRootIsDecorated(false);
    packet_tree_->setAlternatingRowColors(true);
    packet_tree_->setSortingEnabled(true);
    packet_tree_->setSelectionMode(QAbstractItemView::SingleSelection);
    packet_tree_->setUniformRowHeights(true);
    packet_tree_->setColumnCount(dis_pkt_col_count);
    packet_tree_->setHeaderLabels(QStringList()
        << tr("Packet")
        << tr("Time (s)")
        << tr("Delta (ms)")
        << tr("Jitter (ms)")
        << tr("Lost")
        << tr("Status"));
    packet_tree_->header()->setStretchLastSection(false);
    packet_tree_->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    packet_tree_->sortByColumn(dis_pkt_col_frame, Qt::AscendingOrder);
    layout->addWidget(packet_tree_);

    goto_button_ = button_box_->addButton(tr("Go To First Packet"), QDialogButtonBox::ActionRole);
    play_button_ = button_box_->addButton(tr("Play"), QDialogButtonBox::ActionRole);
    stop_button_ = button_box_->addButton(tr("Stop"), QDialogButtonBox::ActionRole);
    layout->addWidget(button_box_);

    connect(stream_combo_, qOverload<int>(&QComboBox::currentIndexChanged), this, &DisStreamAnalysisDialog::onStreamChanged);
    connect(packet_tree_, &QTreeWidget::itemDoubleClicked, this, &DisStreamAnalysisDialog::onPacketRowActivated);
    connect(audio_plot_, &QCustomPlot::mouseDoubleClick, this, &DisStreamAnalysisDialog::onGraphDoubleClicked);
    connect(button_box_, &QDialogButtonBox::rejected, this, &DisStreamAnalysisDialog::reject);
    connect(goto_button_, &QPushButton::clicked, this, &DisStreamAnalysisDialog::onGoToPacket);
#ifdef QT_MULTIMEDIA_LIB
    connect(play_button_, &QPushButton::clicked, this, &DisStreamAnalysisDialog::onPlayPauseStream);
    connect(stop_button_, &QPushButton::clicked, this, &DisStreamAnalysisDialog::onStopStream);
    connect(audio_stream_, &DisAudioStream::playbackProgress,
        this, &DisStreamAnalysisDialog::onPlaybackProgress);
    connect(audio_stream_, &DisAudioStream::playbackStateChanged,
        this, &DisStreamAnalysisDialog::onPlaybackStateChanged);
#endif
    connect(&cap_file_, &CaptureFile::captureEvent, this, &DisStreamAnalysisDialog::onCaptureEvent);

    if (packet_list_) {
        connect(this, SIGNAL(goToPacket(int)), packet_list_, SLOT(goToPacket(int)));
    }

    memset(&tapinfo_, 0, sizeof(tapinfo_));
    tapinfo_.mode = DISSTREAM_TAP_ANALYSE;
    tapinfo_.tap_reset = tapReset;
    tapinfo_.tap_draw = tapDraw;

    register_tap_listener_disstream(&tapinfo_, NULL, NULL);

    if (cap_file_.isValid()) {
        cap_file_.delayedRetapPackets();
    }

    loadGeometry(parent.width() * 2 / 3, parent.height() * 2 / 3);
    updateWidgets();
}

DisStreamAnalysisDialog::~DisStreamAnalysisDialog()
{
    std::lock_guard<std::mutex> lock(mutex_);

#ifdef QT_MULTIMEDIA_LIB
    audio_stream_->stopPlayback();
#endif
    if (have_requested_stream_) {
        disstream_id_free(&requested_stream_id_);
    }
    disstream_reset(&tapinfo_);
    remove_tap_listener_disstream(&tapinfo_);
    pinstance_ = nullptr;
}

void
DisStreamAnalysisDialog::captureFileClosing()
{
#ifdef QT_MULTIMEDIA_LIB
    audio_stream_->stopPlayback();
#endif
    remove_tap_listener_disstream(&tapinfo_);
    disstream_reset(&tapinfo_);
}

void
DisStreamAnalysisDialog::captureFileClosed()
{
#ifdef QT_MULTIMEDIA_LIB
    audio_stream_->stopPlayback();
#endif
    stream_combo_->clear();
    packet_tree_->clear();
}

void
DisStreamAnalysisDialog::tapReset(disstream_tapinfo_t *tapinfo _U_)
{
    if (!pinstance_) {
        return;
    }

    pinstance_->need_redraw_ = true;
}

void
DisStreamAnalysisDialog::tapDraw(disstream_tapinfo_t *tapinfo _U_)
{
    if (!pinstance_) {
        return;
    }

    pinstance_->need_redraw_ = true;
    QMetaObject::invokeMethod(pinstance_, [=]() { pinstance_->updateStreams(); }, Qt::QueuedConnection);
}

disstream_info_t *
DisStreamAnalysisDialog::selectedStream() const
{
    quintptr ptr = stream_combo_->currentData().value<quintptr>();
    return reinterpret_cast<disstream_info_t *>(ptr);
}

void
DisStreamAnalysisDialog::updateStreams()
{
    disstream_info_t *previous = selectedStream();
    GList *list;
    int selected_index = -1;
    int idx = 0;

    if (!need_redraw_ || fileClosed()) {
        updateWidgets();
        return;
    }

    stream_combo_->blockSignals(true);
    stream_combo_->clear();

    list = g_list_first(tapinfo_.strinfo_list);
    while (list) {
        disstream_info_t *stream_info = (disstream_info_t *)list->data;
        char *src_addr = address_to_display(NULL, &stream_info->id.src_addr);
        char *dst_addr = address_to_display(NULL, &stream_info->id.dst_addr);
        QString text = QStringLiteral("%1:%2 -> %3:%4 radio=0x%5 entity=%6/%7/%8")
            .arg(src_addr)
            .arg(stream_info->id.src_port)
            .arg(dst_addr)
            .arg(stream_info->id.dst_port)
            .arg(stream_info->id.radio_id, 4, 16, QChar('0'))
            .arg(stream_info->id.entity_id_site)
            .arg(stream_info->id.entity_id_appl)
            .arg(stream_info->id.entity_id_entity);

        stream_combo_->addItem(text, QVariant::fromValue((quintptr)stream_info));
        if (have_requested_stream_ && disstream_id_equal(&stream_info->id, &requested_stream_id_)) {
            selected_index = idx;
        } else if (!have_requested_stream_ && stream_info == previous) {
            selected_index = idx;
        }
        idx++;

        wmem_free(NULL, src_addr);
        wmem_free(NULL, dst_addr);
        list = g_list_next(list);
    }

    if (selected_index >= 0) {
        stream_combo_->setCurrentIndex(selected_index);
    } else if (stream_combo_->count() > 0) {
        stream_combo_->setCurrentIndex(0);
    }

    if (have_requested_stream_ && selected_index >= 0) {
        disstream_id_free(&requested_stream_id_);
        have_requested_stream_ = false;
    }

    stream_combo_->blockSignals(false);
    need_redraw_ = false;
    updateAnalysis();
    updateWidgets();
}

void
DisStreamAnalysisDialog::updateAnalysis()
{
    disstream_info_t *stream_info = selectedStream();
    double duration;

    if (!stream_info) {
        start_marker_time_ = 0.0;
        setPlaybackMarker(0.0, false);
        duration_label_->setText(tr("-"));
        packets_label_->setText(tr("-"));
        signal_label_->setText(tr("-"));
        tx_label_->setText(tr("-"));
        lost_label_->setText(tr("-"));
        jitter_label_->setText(tr("-"));
        delta_label_->setText(tr("-"));
        codec_label_->setText(tr("-"));
        updatePacketRows();
        updatePlot();
        updateHintLabel();
        return;
    }

    setStartPlayMarker(selectedStartTime());

    duration = nstime_to_sec(&stream_info->stop_rel_time) - nstime_to_sec(&stream_info->start_rel_time);
    duration_label_->setText(QString::number(duration, 'f', 3));
    packets_label_->setText(QString::number(stream_info->packet_count));
    signal_label_->setText(QString::number(stream_info->signal_packet_count));
    tx_label_->setText(QString::number(stream_info->transmitter_packet_count));
    lost_label_->setText(QString::number(stream_info->estimated_lost_packets));
    jitter_label_->setText(QStringLiteral("%1 / %2")
        .arg(QString::number(stream_info->mean_jitter_ms, 'f', 3))
        .arg(QString::number(stream_info->max_jitter_ms, 'f', 3)));
    delta_label_->setText(QStringLiteral("%1 / %2")
        .arg(QString::number(stream_info->mean_delta_ms, 'f', 3))
        .arg(QString::number(stream_info->max_delta_ms, 'f', 3)));
    codec_label_->setText(stream_info->payload_type_str ? stream_info->payload_type_str : tr("Unknown"));
    updatePacketRows();
    updatePlot();
    updateHintLabel();
}

void
DisStreamAnalysisDialog::updatePacketRows()
{
    disstream_info_t *stream_info = selectedStream();

    packet_tree_->setSortingEnabled(false);
    packet_tree_->clear();

    if (!stream_info || !stream_info->signal_packets || stream_info->signal_packets->len == 0) {
        packet_tree_->setSortingEnabled(true);
        return;
    }

    for (guint i = 0; i < stream_info->signal_packets->len; i++) {
        disstream_packet_t *packet = (disstream_packet_t *)g_ptr_array_index(stream_info->signal_packets, i);
        QTreeWidgetItem *item;

        if (!packet) {
            continue;
        }

        item = new QTreeWidgetItem(packet_tree_);
        item->setData(dis_pkt_col_frame, dis_frame_num_role, (uint)packet->frame_num);

        item->setText(dis_pkt_col_frame, QString::number(packet->frame_num));
        item->setData(dis_pkt_col_frame, Qt::UserRole, (uint)packet->frame_num);
        item->setText(dis_pkt_col_time, QString::number(nstime_to_sec(&packet->rel_time), 'f', 6));
        item->setData(dis_pkt_col_time, Qt::UserRole, nstime_to_sec(&packet->rel_time));
        item->setText(dis_pkt_col_delta, QString::number(packet->delta_ms, 'f', 3));
        item->setData(dis_pkt_col_delta, Qt::UserRole, packet->delta_ms);
        item->setText(dis_pkt_col_jitter, QString::number(packet->jitter_ms, 'f', 3));
        item->setData(dis_pkt_col_jitter, Qt::UserRole, packet->jitter_ms);
        item->setText(dis_pkt_col_lost, QString::number(packet->estimated_lost_added));
        item->setData(dis_pkt_col_lost, Qt::UserRole, (uint)packet->estimated_lost_added);
        item->setText(dis_pkt_col_status, packet->problem ? tr("Problem") : tr("OK"));
    }

    packet_tree_->setSortingEnabled(true);
    packet_tree_->sortByColumn(packet_tree_->header()->sortIndicatorSection(),
        packet_tree_->header()->sortIndicatorOrder());
}

void
DisStreamAnalysisDialog::updatePlot()
{
    audio_plot_->clearGraphs();
    audio_plot_->legend->setVisible(false);

#ifdef QT_MULTIMEDIA_LIB
    disstream_info_t *stream_info = selectedStream();
    QString error_message;

    if (!stream_info || !audio_stream_ || !audio_stream_->prepareVisualData(stream_info, error_message)) {
        audio_plot_->replot();
        return;
    }

    ThemeManager *tm = ThemeManager::instance();

    if (!audio_stream_->visualTimestamps().isEmpty()) {
        QCPGraph *wave_graph = audio_plot_->addGraph();
        wave_graph->setName(tr("Waveform"));
        wave_graph->setPen(QPen(tm->graphColor(1)));
        wave_graph->setData(audio_stream_->visualTimestamps(), audio_stream_->visualSamples());
        audio_plot_->legend->setVisible(true);
    }

    if (!audio_stream_->jitterTimestamps().isEmpty()) {
        QCPGraph *jitter_graph = audio_plot_->addGraph();
        jitter_graph->setName(tr("Jitter Spikes"));
        jitter_graph->setLineStyle(QCPGraph::lsNone);
        jitter_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCircle, tm->color(ThemeManager::AccentError), tm->color(ThemeManager::PaletteBase), 8));
        jitter_graph->setData(audio_stream_->jitterTimestamps(), audio_stream_->jitterSamples());
        audio_plot_->legend->setVisible(true);
    }

    if (!audio_stream_->lossTimestamps().isEmpty()) {
        QCPGraph *loss_graph = audio_plot_->addGraph();
        loss_graph->setName(tr("Estimated Loss"));
        loss_graph->setLineStyle(QCPGraph::lsNone);
        loss_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssTriangle, tm->color(ThemeManager::AccentWarning), tm->color(ThemeManager::PaletteBase), 8));
        loss_graph->setData(audio_stream_->lossTimestamps(), audio_stream_->lossSamples());
        audio_plot_->legend->setVisible(true);
    }

    if (!audio_stream_->problemTimestamps().isEmpty()) {
        QCPGraph *problem_graph = audio_plot_->addGraph();
        problem_graph->setName(tr("Problem Packets"));
        problem_graph->setLineStyle(QCPGraph::lsNone);
        problem_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDiamond, tm->color(ThemeManager::AccentInfo), tm->color(ThemeManager::PaletteBase), 8));
        problem_graph->setData(audio_stream_->problemTimestamps(), audio_stream_->problemSamples());
        audio_plot_->legend->setVisible(true);
    }

    audio_plot_->xAxis->rescale(true);
    audio_plot_->yAxis->setRange(-1.4, 1.4);
    drawStartPlayMarker();
    drawPlaybackMarker();
#endif

    audio_plot_->replot();
}

double
DisStreamAnalysisDialog::selectedStartTime() const
{
    return start_marker_time_;
}

void
DisStreamAnalysisDialog::setStartPlayMarker(double new_time)
{
    disstream_info_t *stream_info = selectedStream();

    if (!stream_info) {
        start_marker_time_ = 0.0;
        return;
    }

    const double stream_start = nstime_to_sec(&stream_info->start_rel_time);
    const double stream_stop = nstime_to_sec(&stream_info->stop_rel_time);

    if (new_time <= 0.0) {
        start_marker_time_ = stream_start;
    } else {
        start_marker_time_ = qBound(stream_start, new_time, stream_stop);
    }
}

void
DisStreamAnalysisDialog::drawStartPlayMarker()
{
    if (!start_marker_pos_) {
        return;
    }

    disstream_info_t *stream_info = selectedStream();
    if (!stream_info) {
        start_marker_pos_->setVisible(false);
        return;
    }

    start_marker_pos_->point1->setCoords(start_marker_time_, 0.0);
    start_marker_pos_->point2->setCoords(start_marker_time_, 1.0);
    start_marker_pos_->setVisible(true);
}

void
DisStreamAnalysisDialog::setPlaybackMarker(double new_time, bool visible)
{
    playback_marker_time_ = new_time;
    if (playback_marker_pos_) {
        playback_marker_pos_->setVisible(visible);
    }
}

void
DisStreamAnalysisDialog::drawPlaybackMarker()
{
    if (!playback_marker_pos_ || !playback_marker_pos_->visible()) {
        return;
    }

    playback_marker_pos_->point1->setCoords(playback_marker_time_, 0.0);
    playback_marker_pos_->point2->setCoords(playback_marker_time_, 1.0);
}

void
DisStreamAnalysisDialog::updateWidgets()
{
    bool has_capture = cap_file_.isValid() && !fileClosed();
    disstream_info_t *stream_info = selectedStream();
    bool has_selection = stream_info != nullptr;
    bool has_audio_data = has_selection && stream_info->signal_packets && stream_info->signal_packets->len > 0;

    stream_combo_->setEnabled(has_capture && stream_combo_->count() > 0);
    packet_tree_->setEnabled(has_capture && has_selection);
    playback_progress_->setEnabled(has_capture && has_selection);
    goto_button_->setEnabled(has_selection && stream_info->first_packet_num > 0);
    play_button_->setEnabled(has_capture && has_audio_data);
#ifdef QT_MULTIMEDIA_LIB
    play_button_->setText(audio_stream_->playbackState() == QAudio::ActiveState ? tr("Pause") : tr("Play"));
    stop_button_->setEnabled(audio_stream_->isPlaying());
#else
    stop_button_->setEnabled(false);
#endif
}

void
DisStreamAnalysisDialog::updateHintLabel()
{
    disstream_info_t *stream_info = selectedStream();
    QString hint = QStringLiteral("<small><i>");

    if (!stream_info) {
        hint += tr("Double click on graph to set start of playback.");
    } else {
        hint += tr("Start: %1 s. Double click on graph to set start of playback.")
            .arg(QString::number(selectedStartTime(), 'f', 6));
    }

    hint += QStringLiteral("</i></small>");
    hint_label_->setText(hint);
}

void
DisStreamAnalysisDialog::onStreamChanged(int index _U_)
{
#ifdef QT_MULTIMEDIA_LIB
    disstream_info_t *stream_info = selectedStream();

    if (audio_stream_->currentStream() != nullptr &&
        audio_stream_->currentStream() != stream_info &&
        (audio_stream_->isPlaying() || audio_stream_->isPaused())) {
        audio_stream_->stopPlayback();
        playback_progress_->setValue(0);
        playback_time_label_->setText(tr("0.000 / 0.000 s"));
    }
#endif
    updateAnalysis();
    updateWidgets();
}

void
DisStreamAnalysisDialog::onGoToPacket()
{
    disstream_info_t *stream_info = selectedStream();

    if (stream_info && stream_info->first_packet_num > 0) {
        emit goToPacket((int)stream_info->first_packet_num);
    }
}

void
DisStreamAnalysisDialog::onPacketRowActivated(QTreeWidgetItem *item, int column _U_)
{
    uint frame_num;

    if (!item) {
        return;
    }

    frame_num = item->data(dis_pkt_col_frame, dis_frame_num_role).toUInt();
    if (frame_num > 0) {
        emit goToPacket((int)frame_num);
    }
}

void
DisStreamAnalysisDialog::onGraphDoubleClicked(QMouseEvent *event)
{
    if (!event || event->button() != Qt::LeftButton) {
        return;
    }

    setStartPlayMarker(audio_plot_->xAxis->pixelToCoord(event->pos().x()));
    drawStartPlayMarker();
    updateHintLabel();
    audio_plot_->replot();
}

#ifdef QT_MULTIMEDIA_LIB
void
DisStreamAnalysisDialog::onPlayPauseStream()
{
    disstream_info_t *stream_info = selectedStream();
    QString error_message;

    if (audio_stream_->playbackState() == QAudio::ActiveState) {
        if (audio_stream_->currentStream() == stream_info) {
            audio_stream_->pausePlayback();
            updateWidgets();
            return;
        }
    }

    if (audio_stream_->isPaused()) {
        if (audio_stream_->currentStream() == stream_info) {
            audio_stream_->resumePlayback();
            updateWidgets();
            return;
        }
    }

    audio_stream_->setPlaybackStartTime(selectedStartTime());
    if (!audio_stream_->playDisStream(stream_info, error_message)) {
        QMessageBox::warning(this, tr("DIS Playback"), error_message);
        return;
    }

    playback_progress_->setValue(0);
    playback_time_label_->setText(QStringLiteral("0.000 / %1 s")
        .arg(QString::number(audio_stream_->playbackDurationSeconds(), 'f', 3)));
    updateWidgets();
}

void
DisStreamAnalysisDialog::onStopStream()
{
    audio_stream_->stopPlayback();
    playback_progress_->setValue(0);
    playback_time_label_->setText(tr("0.000 / 0.000 s"));
    setPlaybackMarker(0.0, false);
    audio_plot_->replot();
    updateWidgets();
}

void
DisStreamAnalysisDialog::onPlaybackProgress(double position_secs, double duration_secs)
{
    int progress_value = 0;

    if (duration_secs > 0.0) {
        progress_value = (int)((position_secs / duration_secs) * 1000.0);
    }
    progress_value = qBound(0, progress_value, 1000);

    playback_progress_->setValue(progress_value);
    playback_time_label_->setText(QStringLiteral("%1 / %2 s")
        .arg(QString::number(position_secs, 'f', 3))
        .arg(QString::number(duration_secs, 'f', 3)));

    const double absolute_time = selectedStartTime() + position_secs;
    setPlaybackMarker(absolute_time, true);
    drawPlaybackMarker();
    audio_plot_->replot(QCustomPlot::rpQueuedReplot);
}

void
DisStreamAnalysisDialog::onPlaybackStateChanged(QAudio::State state)
{
    if (state == QAudio::StoppedState || state == QAudio::IdleState) {
        setPlaybackMarker(0.0, false);
        audio_plot_->replot(QCustomPlot::rpQueuedReplot);
    }
    updateWidgets();
}
#endif

void
DisStreamAnalysisDialog::onCaptureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap) {
        need_redraw_ = true;
    }

    updateStreams();
}
