/* rtp_player_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/rtp_media.h>
#include <ui/tap-rtp-common.h>
#include "rtp_player_dialog.h"
#include <ui_rtp_player_dialog.h>
#include "epan/epan_dissect.h"

#include "file.h"
#include "frame_tvbuff.h"

#include "rtp_analysis_dialog.h"

#ifdef QT_MULTIMEDIA_LIB

#include <epan/dissectors/packet-rtp.h>
#include <epan/to_str.h>

#include <wsutil/report_message.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/pint.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_audio_stream.h"
#include <ui/qt/utils/tango_colors.h>
#include <widgets/rtp_audio_graph.h>
#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QAudio>
#include <QAudioDeviceInfo>
#include <QFrame>
#include <QMenu>
#include <QVBoxLayout>
#include <QTimer>

#include <QAudioFormat>
#include <QAudioOutput>
#include <ui/qt/utils/rtp_audio_silence_generator.h>

#endif // QT_MULTIMEDIA_LIB

#include <QPushButton>
#include <QToolButton>

#include <ui/qt/utils/stock_icon.h>
#include "main_application.h"

// To do:
// - Threaded decoding?

// Current and former RTP player bugs. Many have attachments that can be usef for testing.
// Bug 3368 - The timestamp line in a RTP or RTCP packet display's "Not Representable"
// Bug 3952 - VoIP Call RTP Player: audio played is corrupted when RFC2833 packets are present
// Bug 4960 - RTP Player: Audio and visual feedback get rapidly out of sync
// Bug 5527 - Adding arbitrary value to x-axis RTP player
// Bug 7935 - Wrong Timestamps in RTP Player-Decode
// Bug 8007 - UI gets confused on playing decoded audio in rtp_player
// Bug 9007 - Switching SSRC values in RTP stream
// Bug 10613 - RTP audio player crashes
// Bug 11125 - RTP Player does not show progress in selected stream in Window 7
// Bug 11409 - Wireshark crashes when using RTP player
// Bug 12166 - RTP audio player crashes

// In some places we match by conv/call number, in others we match by first frame.

enum {
    channel_col_,
    src_addr_col_,
    src_port_col_,
    dst_addr_col_,
    dst_port_col_,
    ssrc_col_,
    first_pkt_col_,
    num_pkts_col_,
    time_span_col_,
    sample_rate_col_,
    play_rate_col_,
    payload_col_,

    stream_data_col_ = src_addr_col_, // RtpAudioStream
    graph_audio_data_col_ = src_port_col_, // QCPGraph (wave)
    graph_sequence_data_col_ = dst_addr_col_, // QCPGraph (sequence)
    graph_jitter_data_col_ = dst_port_col_, // QCPGraph (jitter)
    graph_timestamp_data_col_ = ssrc_col_, // QCPGraph (timestamp)
    // first_pkt_col_ is skipped, it is used for real data
    graph_silence_data_col_ = num_pkts_col_, // QCPGraph (silence)
};

class RtpPlayerTreeWidgetItem : public QTreeWidgetItem
{
public:
    RtpPlayerTreeWidgetItem(QTreeWidget *tree) :
        QTreeWidgetItem(tree)
    {
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        // Handle numeric sorting
        switch (treeWidget()->sortColumn()) {
            case src_port_col_:
            case dst_port_col_:
            case num_pkts_col_:
            case sample_rate_col_:
                return text(treeWidget()->sortColumn()).toInt() < other.text(treeWidget()->sortColumn()).toInt();
            case play_rate_col_:
                return text(treeWidget()->sortColumn()).toInt() < other.text(treeWidget()->sortColumn()).toInt();
            case first_pkt_col_:
                int v1;
                int v2;

                v1 = data(first_pkt_col_, Qt::UserRole).toInt();
                v2 = other.data(first_pkt_col_, Qt::UserRole).toInt();

                return v1 < v2;
            default:
                // Fall back to string comparison
                return QTreeWidgetItem::operator <(other);
                break;
        }
    }
};

RtpPlayerDialog *RtpPlayerDialog::pinstance_{nullptr};
std::mutex RtpPlayerDialog::init_mutex_;
std::mutex RtpPlayerDialog::run_mutex_;

RtpPlayerDialog *RtpPlayerDialog::openRtpPlayerDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list, bool capture_running)
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (pinstance_ == nullptr)
    {
        pinstance_ = new RtpPlayerDialog(parent, cf, capture_running);
        connect(pinstance_, SIGNAL(goToPacket(int)),
                packet_list, SLOT(goToPacket(int)));
    }
    return pinstance_;
}

RtpPlayerDialog::RtpPlayerDialog(QWidget &parent, CaptureFile &cf, bool capture_running _U_) :
    WiresharkDialog(parent, cf)
#ifdef QT_MULTIMEDIA_LIB
    , ui(new Ui::RtpPlayerDialog)
    , first_stream_rel_start_time_(0.0)
    , first_stream_abs_start_time_(0.0)
    , first_stream_rel_stop_time_(0.0)
    , streams_length_(0.0)
    , start_marker_time_(0.0)
    , number_ticker_(new QCPAxisTicker)
    , datetime_ticker_(new QCPAxisTickerDateTime)
    , stereo_available_(false)
    , marker_stream_(0)
    , marker_stream_requested_out_rate_(0)
    , last_ti_(0)
    , listener_removed_(true)
    , block_redraw_(false)
    , lock_ui_(0)
    , read_capture_enabled_(capture_running)
    , silence_skipped_time_(0.0)
#endif // QT_MULTIMEDIA_LIB
{
    ui->setupUi(this);
    loadGeometry(parent.width(), parent.height());
    setWindowTitle(mainApp->windowTitleString(tr("RTP Player")));
    ui->streamTreeWidget->installEventFilter(this);
    ui->audioPlot->installEventFilter(this);
    installEventFilter(this);

#ifdef QT_MULTIMEDIA_LIB
    ui->splitter->setStretchFactor(0, 3);
    ui->splitter->setStretchFactor(1, 1);

    ui->streamTreeWidget->sortByColumn(first_pkt_col_, Qt::AscendingOrder);

    graph_ctx_menu_ = new QMenu(this);

    graph_ctx_menu_->addAction(ui->actionZoomIn);
    graph_ctx_menu_->addAction(ui->actionZoomOut);
    graph_ctx_menu_->addAction(ui->actionReset);
    graph_ctx_menu_->addSeparator();
    graph_ctx_menu_->addAction(ui->actionMoveRight10);
    graph_ctx_menu_->addAction(ui->actionMoveLeft10);
    graph_ctx_menu_->addAction(ui->actionMoveRight1);
    graph_ctx_menu_->addAction(ui->actionMoveLeft1);
    graph_ctx_menu_->addSeparator();
    graph_ctx_menu_->addAction(ui->actionGoToPacket);
    graph_ctx_menu_->addAction(ui->actionGoToSetupPacketPlot);
    set_action_shortcuts_visible_in_context_menu(graph_ctx_menu_->actions());

    ui->streamTreeWidget->setMouseTracking(true);
    connect(ui->streamTreeWidget, &QTreeWidget::itemEntered, this, &RtpPlayerDialog::itemEntered);

    connect(ui->audioPlot, &QCustomPlot::mouseMove, this, &RtpPlayerDialog::mouseMovePlot);
    connect(ui->audioPlot, &QCustomPlot::mousePress, this, &RtpPlayerDialog::graphClicked);
    connect(ui->audioPlot, &QCustomPlot::mouseDoubleClick, this, &RtpPlayerDialog::graphDoubleClicked);
    connect(ui->audioPlot, &QCustomPlot::plottableClick, this, &RtpPlayerDialog::plotClicked);

    cur_play_pos_ = new QCPItemStraightLine(ui->audioPlot);
    cur_play_pos_->setVisible(false);

    start_marker_pos_ = new QCPItemStraightLine(ui->audioPlot);
    start_marker_pos_->setPen(QPen(Qt::green,4));
    setStartPlayMarker(0);
    drawStartPlayMarker();
    start_marker_pos_->setVisible(true);

    datetime_ticker_->setDateTimeFormat("yyyy-MM-dd\nhh:mm:ss.zzz");

    ui->audioPlot->xAxis->setNumberFormat("gb");
    ui->audioPlot->xAxis->setNumberPrecision(3);
    ui->audioPlot->xAxis->setTicker(datetime_ticker_);
    ui->audioPlot->yAxis->setVisible(false);

    ui->playButton->setIcon(StockIcon("media-playback-start"));
    ui->playButton->setEnabled(false);
    ui->pauseButton->setIcon(StockIcon("media-playback-pause"));
    ui->pauseButton->setCheckable(true);
    ui->pauseButton->setVisible(false);
    ui->stopButton->setIcon(StockIcon("media-playback-stop"));
    ui->stopButton->setEnabled(false);
    ui->skipSilenceButton->setIcon(StockIcon("media-seek-forward"));
    ui->skipSilenceButton->setCheckable(true);
    ui->skipSilenceButton->setEnabled(false);

    read_btn_ = ui->buttonBox->addButton(ui->actionReadCapture->text(), QDialogButtonBox::ActionRole);
    read_btn_->setToolTip(ui->actionReadCapture->toolTip());
    read_btn_->setEnabled(false);
    connect(read_btn_, &QPushButton::pressed, this, &RtpPlayerDialog::on_actionReadCapture_triggered);

    inaudible_btn_ = new QToolButton();
    ui->buttonBox->addButton(inaudible_btn_, QDialogButtonBox::ActionRole);
    inaudible_btn_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    inaudible_btn_->setPopupMode(QToolButton::MenuButtonPopup);

    connect(ui->actionInaudibleButton, &QAction::triggered, this, &RtpPlayerDialog::on_actionSelectInaudible_triggered);
    inaudible_btn_->setDefaultAction(ui->actionInaudibleButton);
    // Overrides text striping of shortcut undercode in QAction
    inaudible_btn_->setText(ui->actionInaudibleButton->text());
    inaudible_btn_->setEnabled(false);
    inaudible_btn_->setMenu(ui->menuInaudible);

    analyze_btn_ = RtpAnalysisDialog::addAnalyzeButton(ui->buttonBox, this);

    prepare_btn_ = ui->buttonBox->addButton(ui->actionPrepareFilter->text(), QDialogButtonBox::ActionRole);
    prepare_btn_->setToolTip(ui->actionPrepareFilter->toolTip());
    connect(prepare_btn_, &QPushButton::pressed, this, &RtpPlayerDialog::on_actionPrepareFilter_triggered);

    export_btn_ = ui->buttonBox->addButton(ui->actionExportButton->text(), QDialogButtonBox::ActionRole);
    export_btn_->setToolTip(ui->actionExportButton->toolTip());
    export_btn_->setEnabled(false);
    export_btn_->setMenu(ui->menuExport);

    // Ordered, unique device names starting with the system default
    QMap<QString, bool> out_device_map; // true == default device
    out_device_map.insert(QAudioDeviceInfo::defaultOutputDevice().deviceName(), true);
    foreach (QAudioDeviceInfo out_device, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput)) {
        if (!out_device_map.contains(out_device.deviceName())) {
            out_device_map.insert(out_device.deviceName(), false);
        }
    }

    ui->outputDeviceComboBox->blockSignals(true);
    foreach (QString out_name, out_device_map.keys()) {
        ui->outputDeviceComboBox->addItem(out_name);
        if (out_device_map.value(out_name)) {
            ui->outputDeviceComboBox->setCurrentIndex(ui->outputDeviceComboBox->count() - 1);
        }
    }
    if (ui->outputDeviceComboBox->count() < 1) {
        ui->outputDeviceComboBox->setEnabled(false);
        ui->playButton->setEnabled(false);
        ui->pauseButton->setEnabled(false);
        ui->stopButton->setEnabled(false);
        ui->skipSilenceButton->setEnabled(false);
        ui->minSilenceSpinBox->setEnabled(false);
        ui->outputDeviceComboBox->addItem(tr("No devices available"));
        ui->outputAudioRate->setEnabled(false);
    } else {
        stereo_available_ = isStereoAvailable();
        fillAudioRateMenu();
    }
    ui->outputDeviceComboBox->blockSignals(false);

    ui->audioPlot->setMouseTracking(true);
    ui->audioPlot->setEnabled(true);
    ui->audioPlot->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );

    graph_ctx_menu_->addSeparator();
    list_ctx_menu_ = new QMenu(this);
    list_ctx_menu_->addAction(ui->actionPlay);
    graph_ctx_menu_->addAction(ui->actionPlay);
    list_ctx_menu_->addAction(ui->actionStop);
    graph_ctx_menu_->addAction(ui->actionStop);
    list_ctx_menu_->addMenu(ui->menuSelect);
    graph_ctx_menu_->addMenu(ui->menuSelect);
    list_ctx_menu_->addMenu(ui->menuAudioRouting);
    graph_ctx_menu_->addMenu(ui->menuAudioRouting);
    list_ctx_menu_->addAction(ui->actionRemoveStream);
    graph_ctx_menu_->addAction(ui->actionRemoveStream);
    list_ctx_menu_->addAction(ui->actionGoToSetupPacketTree);
    set_action_shortcuts_visible_in_context_menu(list_ctx_menu_->actions());

    connect(&cap_file_, &CaptureFile::captureEvent, this, &RtpPlayerDialog::captureEvent);
    connect(this, SIGNAL(updateFilter(QString, bool)),
            &parent, SLOT(filterPackets(QString, bool)));
    connect(this, SIGNAL(rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)));
#endif // QT_MULTIMEDIA_LIB
}

// _U_ is used when no QT_MULTIMEDIA_LIB is available
QToolButton *RtpPlayerDialog::addPlayerButton(QDialogButtonBox *button_box, QDialog *dialog _U_)
{
    if (!button_box) return NULL;

    QAction *ca;
    QToolButton *player_button = new QToolButton();
    button_box->addButton(player_button, QDialogButtonBox::ActionRole);
    player_button->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    player_button->setPopupMode(QToolButton::MenuButtonPopup);

    ca = new QAction(tr("&Play Streams"));
    ca->setToolTip(tr("Open RTP player dialog"));
    ca->setIcon(StockIcon("media-playback-start"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpPlayerReplace()));
    player_button->setDefaultAction(ca);
    // Overrides text striping of shortcut undercode in QAction
    player_button->setText(ca->text());

#if defined(QT_MULTIMEDIA_LIB)
    QMenu *button_menu = new QMenu(player_button);
    button_menu->setToolTipsVisible(true);
    ca = button_menu->addAction(tr("&Set playlist"));
    ca->setToolTip(tr("Replace existing playlist in RTP Player with new one"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpPlayerReplace()));
    ca = button_menu->addAction(tr("&Add to playlist"));
    ca->setToolTip(tr("Add new set to existing playlist in RTP Player"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpPlayerAdd()));
    ca = button_menu->addAction(tr("&Remove from playlist"));
    ca->setToolTip(tr("Remove selected streams from playlist in RTP Player"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpPlayerRemove()));
    player_button->setMenu(button_menu);
#else
    player_button->setEnabled(false);
    player_button->setText(tr("No Audio"));
#endif

    return player_button;
}

#ifdef QT_MULTIMEDIA_LIB
RtpPlayerDialog::~RtpPlayerDialog()
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (pinstance_ != nullptr) {
        cleanupMarkerStream();
        for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
            QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
            RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
            if (audio_stream)
                delete audio_stream;
        }
        delete ui;
        pinstance_ = nullptr;
    }
}

void RtpPlayerDialog::accept()
{
    if (!listener_removed_) {
        remove_tap_listener(this);
        listener_removed_ = true;
    }

    int row_count = ui->streamTreeWidget->topLevelItemCount();
    // Stop all streams before the dialogs are closed.
    for (int row = 0; row < row_count; row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        audio_stream->stopPlaying();
    }
    WiresharkDialog::accept();
}

void RtpPlayerDialog::reject()
{
    RtpPlayerDialog::accept();
}

void RtpPlayerDialog::retapPackets()
{
    if (!listener_removed_) {
        // Retap is running, nothing better we can do
        return;
    }
    lockUI();
    ui->hintLabel->setText("<i><small>" + tr("Decoding streams...") + "</i></small>");
    mainApp->processEvents();

    // Clear packets from existing streams before retap
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *row_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();

        row_stream->clearPackets();
    }

    // destroyCheck is protection againts destroying dialog during recap.
    // It stores dialog pointer in data() and if dialog destroyed, it
    // returns null
    QPointer<RtpPlayerDialog> destroyCheck=this;
    GString *error_string;

    listener_removed_ = false;
    error_string = register_tap_listener("rtp", this, NULL, 0, NULL, tapPacket, NULL, NULL);
    if (error_string) {
        report_failure("RTP Player - tap registration failed: %s", error_string->str);
        g_string_free(error_string, TRUE);
        unlockUI();
        return;
    }
    cap_file_.retapPackets();

    // Check if dialog exists still
    if (destroyCheck.data()) {
        if (!listener_removed_) {
            remove_tap_listener(this);
            listener_removed_ = true;
        }
        fillTappedColumns();
        rescanPackets(true);
    }
    unlockUI();
}

void RtpPlayerDialog::rescanPackets(bool rescale_axes)
{
    lockUI();
    // Show information for a user - it can last long time...
    playback_error_.clear();
    ui->hintLabel->setText("<i><small>" + tr("Decoding streams...") + "</i></small>");
    mainApp->processEvents();

    QAudioDeviceInfo cur_out_device = getCurrentDeviceInfo();
    int row_count = ui->streamTreeWidget->topLevelItemCount();

    // Reset stream values
    for (int row = 0; row < row_count; row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        audio_stream->setStereoRequired(stereo_available_);
        audio_stream->reset(first_stream_rel_start_time_);

        audio_stream->setJitterBufferSize((int) ui->jitterSpinBox->value());

        RtpAudioStream::TimingMode timing_mode = RtpAudioStream::JitterBuffer;
        switch (ui->timingComboBox->currentIndex()) {
        case RtpAudioStream::RtpTimestamp:
            timing_mode = RtpAudioStream::RtpTimestamp;
            break;
        case RtpAudioStream::Uninterrupted:
            timing_mode = RtpAudioStream::Uninterrupted;
            break;
        default:
            break;
        }
        audio_stream->setTimingMode(timing_mode);

        audio_stream->decode(cur_out_device);
    }

    for (int col = 0; col < ui->streamTreeWidget->columnCount() - 1; col++) {
        ui->streamTreeWidget->resizeColumnToContents(col);
    }

    createPlot(rescale_axes);

    updateWidgets();
    unlockUI();
}

void RtpPlayerDialog::createPlot(bool rescale_axes)
{
    bool legend_out_of_sequence = false;
    bool legend_jitter_dropped = false;
    bool legend_wrong_timestamps = false;
    bool legend_inserted_silences = false;
    bool relative_timestamps = !ui->todCheckBox->isChecked();
    int row_count = ui->streamTreeWidget->topLevelItemCount();
    gint16 total_max_sample_value = 1;

    ui->audioPlot->clearGraphs();

    if (relative_timestamps) {
        ui->audioPlot->xAxis->setTicker(number_ticker_);
    } else {
        ui->audioPlot->xAxis->setTicker(datetime_ticker_);
    }

    // Calculate common Y scale for graphs
    for (int row = 0; row < row_count; row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        gint16 max_sample_value = audio_stream->getMaxSampleValue();

        if (max_sample_value > total_max_sample_value) {
            total_max_sample_value = max_sample_value;
        }
    }

    // Clear existing graphs
    for (int row = 0; row < row_count; row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        int y_offset = row_count - row - 1;
        AudioRouting audio_routing = audio_stream->getAudioRouting();

        ti->setData(graph_audio_data_col_, Qt::UserRole, QVariant());
        ti->setData(graph_sequence_data_col_, Qt::UserRole, QVariant());
        ti->setData(graph_jitter_data_col_, Qt::UserRole, QVariant());
        ti->setData(graph_timestamp_data_col_, Qt::UserRole, QVariant());
        ti->setData(graph_silence_data_col_, Qt::UserRole, QVariant());

        // Set common scale
        audio_stream->setMaxSampleValue(total_max_sample_value);

        // Waveform
        RtpAudioGraph *audio_graph = new RtpAudioGraph(ui->audioPlot, audio_stream->color());
        audio_graph->setMuted(audio_routing.isMuted());
        audio_graph->setData(audio_stream->visualTimestamps(relative_timestamps), audio_stream->visualSamples(y_offset));
        ti->setData(graph_audio_data_col_, Qt::UserRole, QVariant::fromValue<RtpAudioGraph *>(audio_graph));
        //RTP_STREAM_DEBUG("Plotting %s, %d samples", ti->text(src_addr_col_).toUtf8().constData(), audio_graph->wave->data()->size());

        QString span_str;
        if (ui->todCheckBox->isChecked()) {
            QDateTime date_time1 = QDateTime::fromMSecsSinceEpoch((audio_stream->startRelTime() + first_stream_abs_start_time_ - audio_stream->startRelTime()) * 1000.0);
            QDateTime date_time2 = QDateTime::fromMSecsSinceEpoch((audio_stream->stopRelTime() + first_stream_abs_start_time_ - audio_stream->startRelTime()) * 1000.0);
            QString time_str1 = date_time1.toString("yyyy-MM-dd hh:mm:ss.zzz");
            QString time_str2 = date_time2.toString("yyyy-MM-dd hh:mm:ss.zzz");
            span_str = QString("%1 - %2 (%3)")
                .arg(time_str1)
                .arg(time_str2)
                .arg(QString::number(audio_stream->stopRelTime() - audio_stream->startRelTime(), 'f', prefs.gui_decimal_places1));
        } else {
            span_str = QString("%1 - %2 (%3)")
                .arg(QString::number(audio_stream->startRelTime(), 'f', prefs.gui_decimal_places1))
                .arg(QString::number(audio_stream->stopRelTime(), 'f', prefs.gui_decimal_places1))
                .arg(QString::number(audio_stream->stopRelTime() - audio_stream->startRelTime(), 'f', prefs.gui_decimal_places1));
        }
        ti->setText(time_span_col_, span_str);
        ti->setText(sample_rate_col_, QString::number(audio_stream->sampleRate()));
        ti->setText(play_rate_col_, QString::number(audio_stream->playRate()));
        ti->setText(payload_col_, audio_stream->payloadNames().join(", "));

        if (audio_stream->outOfSequence() > 0) {
            // Sequence numbers
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssSquare, tango_aluminium_6, Qt::white, mainApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->outOfSequenceTimestamps(relative_timestamps), audio_stream->outOfSequenceSamples(y_offset));
            ti->setData(graph_sequence_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (legend_out_of_sequence) {
                seq_graph->removeFromLegend();
            } else {
                seq_graph->setName(tr("Out of Sequence"));
                legend_out_of_sequence = true;
            }
        }

        if (audio_stream->jitterDropped() > 0) {
            // Jitter drops
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCircle, tango_scarlet_red_5, Qt::white, mainApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->jitterDroppedTimestamps(relative_timestamps), audio_stream->jitterDroppedSamples(y_offset));
            ti->setData(graph_jitter_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (legend_jitter_dropped) {
                seq_graph->removeFromLegend();
            } else {
                seq_graph->setName(tr("Jitter Drops"));
                legend_jitter_dropped = true;
            }
        }

        if (audio_stream->wrongTimestamps() > 0) {
            // Wrong timestamps
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDiamond, tango_sky_blue_5, Qt::white, mainApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->wrongTimestampTimestamps(relative_timestamps), audio_stream->wrongTimestampSamples(y_offset));
            ti->setData(graph_timestamp_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (legend_wrong_timestamps) {
                seq_graph->removeFromLegend();
            } else {
                seq_graph->setName(tr("Wrong Timestamps"));
                legend_wrong_timestamps = true;
            }
        }

        if (audio_stream->insertedSilences() > 0) {
            // Inserted silence
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssTriangle, tango_butter_5, Qt::white, mainApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->insertedSilenceTimestamps(relative_timestamps), audio_stream->insertedSilenceSamples(y_offset));
            ti->setData(graph_silence_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (legend_inserted_silences) {
                seq_graph->removeFromLegend();
            } else {
                seq_graph->setName(tr("Inserted Silence"));
                legend_inserted_silences = true;
            }
        }
    }
    ui->audioPlot->legend->setVisible(legend_out_of_sequence || legend_jitter_dropped || legend_wrong_timestamps || legend_inserted_silences);

    ui->audioPlot->replot();
    if (rescale_axes) resetXAxis();
}

void RtpPlayerDialog::fillTappedColumns()
{
    // true just for first stream
    bool is_first = true;

    // Get all rows, immutable list. Later changes in rows migth reorder them
    QList<QTreeWidgetItem *> items = ui->streamTreeWidget->findItems(
        QString("*"), Qt::MatchWrap | Qt::MatchWildcard | Qt::MatchRecursive);

    // Update rows by calculated values, it might reorder them in view...
    foreach(QTreeWidgetItem *ti, items) {
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (audio_stream) {
            rtpstream_info_t *rtpstream = audio_stream->getStreamInfo();

            // 0xFFFFFFFF mean no setup frame
            // first_packet_num == setup_frame_number happens, when
            // rtp_udp is active or Decode as was used
            if ((rtpstream->setup_frame_number == 0xFFFFFFFF) ||
                (rtpstream->rtp_stats.first_packet_num == rtpstream->setup_frame_number)
               ) {
                int packet = rtpstream->rtp_stats.first_packet_num;
                ti->setText(first_pkt_col_, QString("RTP %1").arg(packet));
                ti->setData(first_pkt_col_, Qt::UserRole, QVariant(packet));
            } else {
                int packet = rtpstream->setup_frame_number;
                ti->setText(first_pkt_col_, QString("SETUP %1").arg(rtpstream->setup_frame_number));
                ti->setData(first_pkt_col_, Qt::UserRole, QVariant(packet));
            }
            ti->setText(num_pkts_col_, QString::number(rtpstream->packet_count));
            updateStartStopTime(rtpstream, is_first);
            is_first = false;
        }
    }
    setMarkers();
}

void RtpPlayerDialog::addSingleRtpStream(rtpstream_id_t *id)
{
    bool found = false;

    AudioRouting audio_routing = AudioRouting(AUDIO_UNMUTED, channel_mono);

    if (!id) return;

    // Find the RTP streams associated with this conversation.
    // gtk/rtp_player.c:mark_rtp_stream_to_play does this differently.

    QList<RtpAudioStream *> streams = stream_hash_.values(rtpstream_id_to_hash(id));
    for (int i = 0; i < streams.size(); i++) {
        RtpAudioStream *row_stream = streams.at(i);
        if (row_stream->isMatch(id)) {
            found = true;
            break;
        }
    }


    if (found) {
       return;
    }

    try {
        int tli_count = ui->streamTreeWidget->topLevelItemCount();

        RtpAudioStream *audio_stream = new RtpAudioStream(this, id, stereo_available_);
        audio_stream->setColor(ColorUtils::graphColor(tli_count));

        QTreeWidgetItem *ti = new RtpPlayerTreeWidgetItem(ui->streamTreeWidget);
        stream_hash_.insert(rtpstream_id_to_hash(id), audio_stream);
        ti->setText(src_addr_col_, address_to_qstring(&(id->src_addr)));
        ti->setText(src_port_col_, QString::number(id->src_port));
        ti->setText(dst_addr_col_, address_to_qstring(&(id->dst_addr)));
        ti->setText(dst_port_col_, QString::number(id->dst_port));
        ti->setText(ssrc_col_, int_to_qstring(id->ssrc, 8, 16));

        // Calculated items are updated after every retapPackets()

        ti->setData(stream_data_col_, Qt::UserRole, QVariant::fromValue(audio_stream));
        if (stereo_available_) {
            if (tli_count%2) {
                audio_routing.setChannel(channel_stereo_right);
            } else {
                audio_routing.setChannel(channel_stereo_left);
            }
        } else {
            audio_routing.setChannel(channel_mono);
        }
        ti->setToolTip(channel_col_, QString(tr("Double click on cell to change audio routing")));
        formatAudioRouting(ti, audio_routing);
        audio_stream->setAudioRouting(audio_routing);

        for (int col = 0; col < ui->streamTreeWidget->columnCount(); col++) {
            QBrush fgBrush = ti->foreground(col);
            fgBrush.setColor(audio_stream->color());
            ti->setForeground(col, fgBrush);
        }

        connect(audio_stream, &RtpAudioStream::finishedPlaying, this, &RtpPlayerDialog::playFinished);
        connect(audio_stream, &RtpAudioStream::playbackError, this, &RtpPlayerDialog::setPlaybackError);
    } catch (...) {
        qWarning() << "Stream ignored, try to add fewer streams to playlist";
    }

    RTP_STREAM_DEBUG("adding stream %d to layout",
                     ui->streamTreeWidget->topLevelItemCount());
}

void RtpPlayerDialog::lockUI()
{
    if (0 == lock_ui_++) {
        if (playing_streams_.count() > 0) {
            on_stopButton_clicked();
        }
        setEnabled(false);
    }
}

void RtpPlayerDialog::unlockUI()
{
    if (--lock_ui_ == 0) {
        setEnabled(true);
    }
}

void RtpPlayerDialog::replaceRtpStreams(QVector<rtpstream_id_t *> stream_ids)
{
    std::unique_lock<std::mutex> lock(run_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
        lockUI();

        // Delete all existing rows
        if (last_ti_) {
            highlightItem(last_ti_, false);
            last_ti_ = NULL;
        }

        for (int row = ui->streamTreeWidget->topLevelItemCount() - 1; row >= 0; row--) {
            QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
            removeRow(ti);
        }

        // Add all new streams
        for (int i=0; i < stream_ids.size(); i++) {
            addSingleRtpStream(stream_ids[i]);
        }
        setMarkers();

        unlockUI();
#ifdef QT_MULTIMEDIA_LIB
        QTimer::singleShot(0, this, SLOT(retapPackets()));
#endif
    } else {
        ws_warning("replaceRtpStreams was called while other thread locked it. Current call is ignored, try it later.");
    }
}

void RtpPlayerDialog::addRtpStreams(QVector<rtpstream_id_t *> stream_ids)
{
    std::unique_lock<std::mutex> lock(run_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
        lockUI();

        int tli_count = ui->streamTreeWidget->topLevelItemCount();

        // Add new streams
        for (int i=0; i < stream_ids.size(); i++) {
            addSingleRtpStream(stream_ids[i]);
        }

        if (tli_count == 0) {
            setMarkers();
        }

        unlockUI();
#ifdef QT_MULTIMEDIA_LIB
        QTimer::singleShot(0, this, SLOT(retapPackets()));
#endif
    } else {
        ws_warning("addRtpStreams was called while other thread locked it. Current call is ignored, try it later.");
    }
}

void RtpPlayerDialog::removeRtpStreams(QVector<rtpstream_id_t *> stream_ids)
{
    std::unique_lock<std::mutex> lock(run_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
        lockUI();
        int tli_count = ui->streamTreeWidget->topLevelItemCount();

        for (int i=0; i < stream_ids.size(); i++) {
            for (int row = 0; row < tli_count; row++) {
                QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
                RtpAudioStream *row_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
                if (row_stream->isMatch(stream_ids[i])) {
                    removeRow(ti);
                    tli_count--;
                    break;
                }
            }
        }
        updateGraphs();

        updateWidgets();
        unlockUI();
    } else {
        ws_warning("removeRtpStreams was called while other thread locked it. Current call is ignored, try it later.");
    }
}

void RtpPlayerDialog::setMarkers()
{
    setStartPlayMarker(0);
    drawStartPlayMarker();
}

void RtpPlayerDialog::showEvent(QShowEvent *)
{
    QList<int> split_sizes = ui->splitter->sizes();
    int tot_size = split_sizes[0] + split_sizes[1];
    int plot_size = tot_size * 3 / 4;
    split_sizes.clear();
    split_sizes << plot_size << tot_size - plot_size;
    ui->splitter->setSizes(split_sizes);
}

bool RtpPlayerDialog::eventFilter(QObject *, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent &keyEvent = static_cast<QKeyEvent&>(*event);
        int pan_secs = keyEvent.modifiers() & Qt::ShiftModifier ? 1 : 10;

        switch(keyEvent.key()) {
            case Qt::Key_Minus:
            case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
            case Qt::Key_O:             // GTK+
            case Qt::Key_R:
                on_actionZoomOut_triggered();
                return true;
            case Qt::Key_Plus:
            case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
            case Qt::Key_I:             // GTK+
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+I
                    on_actionSelectInvert_triggered();
                    return true;
                } else {
                    // I
                    on_actionZoomIn_triggered();
                    return true;
                }
                break;
            case Qt::Key_Right:
            case Qt::Key_L:
                panXAxis(pan_secs);
                return true;
            case Qt::Key_Left:
            case Qt::Key_H:
                panXAxis(-1 * pan_secs);
                return true;
            case Qt::Key_0:
            case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
                on_actionReset_triggered();
                return true;
            case Qt::Key_G:
                if (keyEvent.modifiers() == Qt::ShiftModifier) {
                    // Goto SETUP frame, use correct call based on caller
                    QPoint pos1 = ui->audioPlot->mapFromGlobal(QCursor::pos());
                    QPoint pos2 = ui->streamTreeWidget->mapFromGlobal(QCursor::pos());
                    if (ui->audioPlot->rect().contains(pos1)) {
                        // audio plot, by mouse coords
                        on_actionGoToSetupPacketPlot_triggered();
                    } else if (ui->streamTreeWidget->rect().contains(pos2)) {
                        // packet tree, by cursor
                        on_actionGoToSetupPacketTree_triggered();
                    }
                    return true;
                } else {
                    on_actionGoToPacket_triggered();
                    return true;
                }
            case Qt::Key_A:
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+A
                    on_actionSelectAll_triggered();
                    return true;
                } else if (keyEvent.modifiers() == (Qt::ShiftModifier | Qt::ControlModifier)) {
                    // Ctrl+Shift+A
                    on_actionSelectNone_triggered();
                    return true;
                }
                break;
            case Qt::Key_M:
                if (keyEvent.modifiers() == Qt::ShiftModifier) {
                    on_actionAudioRoutingUnmute_triggered();
                    return true;
                } else if (keyEvent.modifiers() == Qt::ControlModifier) {
                    on_actionAudioRoutingMuteInvert_triggered();
                    return true;
                } else  {
                    on_actionAudioRoutingMute_triggered();
                    return true;
                }
            case Qt::Key_Delete:
                on_actionRemoveStream_triggered();
                return true;
            case Qt::Key_X:
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+X
                    on_actionRemoveStream_triggered();
                    return true;
                }
                break;
            case Qt::Key_Down:
            case Qt::Key_Up:
            case Qt::Key_PageUp:
            case Qt::Key_PageDown:
            case Qt::Key_Home:
            case Qt::Key_End:
                // Route keys to QTreeWidget
                ui->streamTreeWidget->setFocus();
                break;
            case Qt::Key_P:
                if (keyEvent.modifiers() == Qt::NoModifier) {
                    on_actionPlay_triggered();
                    return true;
                }
                break;
            case Qt::Key_S:
                on_actionStop_triggered();
                return true;
            case Qt::Key_N:
                if (keyEvent.modifiers() == Qt::ShiftModifier) {
                    // Shift+N
                    on_actionDeselectInaudible_triggered();
                    return true;
                } else {
                    on_actionSelectInaudible_triggered();
                    return true;
                }
                break;
        }
    }

    return false;
}

void RtpPlayerDialog::contextMenuEvent(QContextMenuEvent *event)
{
    list_ctx_menu_->popup(event->globalPos());
}

void RtpPlayerDialog::updateWidgets()
{
    bool enable_play = true;
    bool enable_pause = false;
    bool enable_stop = false;
    bool enable_timing = true;
    int count = ui->streamTreeWidget->topLevelItemCount();
    int selected = ui->streamTreeWidget->selectedItems().count();

    if (count < 1) {
        enable_play = false;
        ui->skipSilenceButton->setEnabled(false);
        ui->minSilenceSpinBox->setEnabled(false);
    } else {
        ui->skipSilenceButton->setEnabled(true);
        ui->minSilenceSpinBox->setEnabled(true);
    }

    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);

        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (audio_stream->outputState() != QAudio::IdleState) {
            enable_play = false;
            enable_pause = true;
            enable_stop = true;
            enable_timing = false;
        }
    }

    ui->actionAudioRoutingP->setVisible(!stereo_available_);
    ui->actionAudioRoutingL->setVisible(stereo_available_);
    ui->actionAudioRoutingLR->setVisible(stereo_available_);
    ui->actionAudioRoutingR->setVisible(stereo_available_);

    ui->playButton->setEnabled(enable_play);
    if (enable_play) {
        ui->playButton->setVisible(true);
        ui->pauseButton->setVisible(false);
    } else if (enable_pause) {
        ui->playButton->setVisible(false);
        ui->pauseButton->setVisible(true);
    }
    ui->outputDeviceComboBox->setEnabled(enable_play);
    ui->outputAudioRate->setEnabled(enable_play);
    ui->pauseButton->setEnabled(enable_pause);
    ui->stopButton->setEnabled(enable_stop);
    ui->actionStop->setEnabled(enable_stop);
    cur_play_pos_->setVisible(enable_stop);

    ui->jitterSpinBox->setEnabled(enable_timing);
    ui->timingComboBox->setEnabled(enable_timing);
    ui->todCheckBox->setEnabled(enable_timing);

    read_btn_->setEnabled(read_capture_enabled_);
    inaudible_btn_->setEnabled(count > 0);
    analyze_btn_->setEnabled(selected > 0);
    prepare_btn_->setEnabled(selected > 0);

    updateHintLabel();
    ui->audioPlot->replot();
}

void RtpPlayerDialog::handleItemHighlight(QTreeWidgetItem *ti, bool scroll)
{
    if (ti) {
        if (ti != last_ti_) {
            if (last_ti_) {
                highlightItem(last_ti_, false);
            }
            highlightItem(ti, true);

            if (scroll)
                ui->streamTreeWidget->scrollToItem(ti, QAbstractItemView::EnsureVisible);
            ui->audioPlot->replot();
            last_ti_ = ti;
        }
    } else {
        if (last_ti_) {
            highlightItem(last_ti_, false);
            ui->audioPlot->replot();
            last_ti_ = NULL;
        }
    }
}

void RtpPlayerDialog::highlightItem(QTreeWidgetItem *ti, bool highlight)
{
    QFont font;
    RtpAudioGraph *audio_graph;

    font.setBold(highlight);
    for(int i=0; i<ui->streamTreeWidget->columnCount(); i++) {
        ti->setFont(i, font);
    }

    audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<RtpAudioGraph*>();
    if (audio_graph) {
        audio_graph->setHighlight(highlight);
    }
}

void RtpPlayerDialog::itemEntered(QTreeWidgetItem *item, int column _U_)
{
    handleItemHighlight(item, false);
}

void RtpPlayerDialog::mouseMovePlot(QMouseEvent *event)
{
    updateHintLabel();

    QTreeWidgetItem *ti = findItemByCoords(event->pos());
    handleItemHighlight(ti, true);
}

void RtpPlayerDialog::graphClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::RightButton) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        graph_ctx_menu_->popup(event->globalPosition().toPoint());
#else
        graph_ctx_menu_->popup(event->globalPos());
#endif
    }
}

void RtpPlayerDialog::graphDoubleClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::LeftButton) {
        // Move start play line
        double ts = ui->audioPlot->xAxis->pixelToCoord(event->pos().x());

        setStartPlayMarker(ts);
        drawStartPlayMarker();

        ui->audioPlot->replot();
    }
}

void RtpPlayerDialog::plotClicked(QCPAbstractPlottable *plottable _U_, int dataIndex _U_, QMouseEvent *event)
{
    // Delivered plottable very often points to different element than a mouse
    // so we find right one by mouse coordinates
    QTreeWidgetItem *ti = findItemByCoords(event->pos());
    if (ti) {
        if (event->modifiers() == Qt::NoModifier) {
            ti->setSelected(true);
        } else if (event->modifiers() == Qt::ControlModifier) {
            ti->setSelected(!ti->isSelected());
        }
    }
}

QTreeWidgetItem *RtpPlayerDialog::findItemByCoords(QPoint point)
{
    QCPAbstractPlottable *plottable=ui->audioPlot->plottableAt(point);
    if (plottable) {
        return findItem(plottable);
    }

    return NULL;
}

QTreeWidgetItem *RtpPlayerDialog::findItem(QCPAbstractPlottable *plottable)
{
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<RtpAudioGraph*>();
        if (audio_graph && audio_graph->isMyPlottable(plottable)) {
            return ti;
        }
    }

    return NULL;
}

void RtpPlayerDialog::updateHintLabel()
{
    int packet_num = getHoveredPacket();
    QString hint = "<small><i>";
    double start_pos = getStartPlayMarker();
    int row_count = ui->streamTreeWidget->topLevelItemCount();
    int selected = ui->streamTreeWidget->selectedItems().count();
    int not_muted = 0;

    hint += tr("%1 streams").arg(row_count);

    if (row_count > 0) {
        if (selected > 0) {
            hint += tr(", %1 selected").arg(selected);
        }

        for (int row = 0; row < row_count; row++) {
            QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
            RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
            if (audio_stream && (!audio_stream->getAudioRouting().isMuted())) {
                not_muted++;
            }
        }

        hint += tr(", %1 not muted").arg(not_muted);
    }

    if (packet_num == 0) {
        hint += tr(", start: %1. Double click on graph to set start of playback.")
                .arg(getFormatedTime(start_pos));
    } else if (packet_num > 0) {
        hint += tr(", start: %1, cursor: %2. Press \"G\" to go to packet %3. Double click on graph to set start of playback.")
                .arg(getFormatedTime(start_pos))
                .arg(getFormatedHoveredTime())
                .arg(packet_num);
    }

    if (!playback_error_.isEmpty()) {
        hint += " <font color=\"red\">";
        hint += playback_error_;
        hint += " </font>";
    }

    hint += "</i></small>";
    ui->hintLabel->setText(hint);
}

void RtpPlayerDialog::resetXAxis()
{
    QCustomPlot *ap = ui->audioPlot;

    double pixel_pad = 10.0; // per side

    ap->rescaleAxes(true);

    double axis_pixels = ap->xAxis->axisRect()->width();
    ap->xAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, ap->xAxis->range().center());

    axis_pixels = ap->yAxis->axisRect()->height();
    ap->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, ap->yAxis->range().center());

    ap->replot();
}

void RtpPlayerDialog::updateGraphs()
{
    QCustomPlot *ap = ui->audioPlot;

    // Create new plots, just existing ones
    createPlot(false);

    // Rescale Y axis
    double pixel_pad = 10.0; // per side
    double axis_pixels = ap->yAxis->axisRect()->height();
    ap->yAxis->rescale(true);
    ap->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, ap->yAxis->range().center());

    ap->replot();
}

void RtpPlayerDialog::playFinished(RtpAudioStream *stream, QAudio::Error error)
{
    if ((error != QAudio::NoError) && (error != QAudio::UnderrunError)) {
        setPlaybackError(tr("Playback of stream %1 failed!")
            .arg(stream->getIDAsQString())
        );
    }
    playing_streams_.removeOne(stream);
    if (playing_streams_.isEmpty()) {
        marker_stream_->stop();
        updateWidgets();
    }
}

void RtpPlayerDialog::setPlayPosition(double secs)
{
    double cur_secs = cur_play_pos_->point1->key();

    if (ui->todCheckBox->isChecked()) {
        secs += first_stream_abs_start_time_;
    } else {
        secs += first_stream_rel_start_time_;
    }
    if (secs > cur_secs) {
        cur_play_pos_->point1->setCoords(secs, 0.0);
        cur_play_pos_->point2->setCoords(secs, 1.0);
        ui->audioPlot->replot();
    }
}

void RtpPlayerDialog::setPlaybackError(const QString playback_error)
{
    playback_error_ = playback_error;
    updateHintLabel();
}

tap_packet_status RtpPlayerDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr, tap_flags_t)
{
    RtpPlayerDialog *rtp_player_dialog = dynamic_cast<RtpPlayerDialog *>((RtpPlayerDialog*)tapinfo_ptr);
    if (!rtp_player_dialog) return TAP_PACKET_DONT_REDRAW;

    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)rtpinfo_ptr;
    if (!rtpinfo) return TAP_PACKET_DONT_REDRAW;

    /* ignore RTP Version != 2 */
    if (rtpinfo->info_version != 2)
        return TAP_PACKET_DONT_REDRAW;

    rtp_player_dialog->addPacket(pinfo, rtpinfo);

    return TAP_PACKET_DONT_REDRAW;
}

void RtpPlayerDialog::addPacket(packet_info *pinfo, const _rtp_info *rtpinfo)
{
    // Search stream in hash key, if there are multiple streams with same hash
    QList<RtpAudioStream *> streams = stream_hash_.values(pinfo_rtp_info_to_hash(pinfo, rtpinfo));
    for (int i = 0; i < streams.size(); i++) {
        RtpAudioStream *row_stream = streams.at(i);
        if (row_stream->isMatch(pinfo, rtpinfo)) {
            row_stream->addRtpPacket(pinfo, rtpinfo);
            break;
        }
    }

//    qDebug() << "=ap no match!" << address_to_qstring(&pinfo->src) << address_to_qstring(&pinfo->dst);
}

void RtpPlayerDialog::zoomXAxis(bool in)
{
    QCustomPlot *ap = ui->audioPlot;
    double h_factor = ap->axisRect()->rangeZoomFactor(Qt::Horizontal);

    if (!in) {
        h_factor = pow(h_factor, -1);
    }

    ap->xAxis->scaleRange(h_factor, ap->xAxis->range().center());
    ap->replot();
}

// XXX I tried using seconds but pixels make more sense at varying zoom
// levels.
void RtpPlayerDialog::panXAxis(int x_pixels)
{
    QCustomPlot *ap = ui->audioPlot;
    double h_pan;

    h_pan = ap->xAxis->range().size() * x_pixels / ap->xAxis->axisRect()->width();
    if (x_pixels) {
        ap->xAxis->moveRange(h_pan);
        ap->replot();
    }
}

void RtpPlayerDialog::on_playButton_clicked()
{
    double start_time;

    ui->hintLabel->setText("<i><small>" + tr("Preparing to play...") + "</i></small>");
    mainApp->processEvents();
    ui->pauseButton->setChecked(false);

    // Protect start time against move of marker during the play
    start_marker_time_play_ = start_marker_time_;
    silence_skipped_time_ = 0.0;
    cur_play_pos_->point1->setCoords(start_marker_time_play_, 0.0);
    cur_play_pos_->point2->setCoords(start_marker_time_play_, 1.0);
    cur_play_pos_->setVisible(true);
    playback_error_.clear();

    if (ui->todCheckBox->isChecked()) {
        start_time = start_marker_time_play_;
    } else {
        start_time = start_marker_time_play_ - first_stream_rel_start_time_;
    }

    QAudioDeviceInfo cur_out_device = getCurrentDeviceInfo();
    playing_streams_.clear();
    int row_count = ui->streamTreeWidget->topLevelItemCount();
    for (int row = 0; row < row_count; row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        // All streams starts at first_stream_rel_start_time_
        audio_stream->setStartPlayTime(start_time);
        if (audio_stream->prepareForPlay(cur_out_device)) {
            playing_streams_ << audio_stream;
        }
    }

    // Prepare silent stream for progress marker
    if (!marker_stream_) {
        marker_stream_ = getSilenceAudioOutput();
    } else {
        marker_stream_->stop();
    }

    // Start progress marker and then audio streams
    marker_stream_->start(new AudioSilenceGenerator());
    for( int i = 0; i<playing_streams_.count(); ++i ) {
        playing_streams_[i]->startPlaying();
    }

    updateWidgets();
}

QAudioDeviceInfo RtpPlayerDialog::getCurrentDeviceInfo()
{
    QAudioDeviceInfo cur_out_device = QAudioDeviceInfo::defaultOutputDevice();
    QString cur_out_name = currentOutputDeviceName();
    foreach (QAudioDeviceInfo out_device, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput)) {
        if (cur_out_name == out_device.deviceName()) {
            cur_out_device = out_device;
        }
    }

    return cur_out_device;
}

QAudioOutput *RtpPlayerDialog::getSilenceAudioOutput()
{
    QAudioOutput *o;
    QAudioDeviceInfo cur_out_device = getCurrentDeviceInfo();

    QAudioFormat format;
    if (marker_stream_requested_out_rate_ > 0) {
        format.setSampleRate(marker_stream_requested_out_rate_);
    } else {
        format.setSampleRate(8000);
    }
    format.setSampleSize(SAMPLE_BYTES * 8); // bits
    format.setSampleType(QAudioFormat::SignedInt);
    format.setChannelCount(1);
    format.setCodec("audio/pcm");
    if (!cur_out_device.isFormatSupported(format)) {
        format = cur_out_device.nearestFormat(format);
    }

    o = new QAudioOutput(cur_out_device, format, this);
    o->setNotifyInterval(100); // ~15 fps
    connect(o, SIGNAL(notify()), this, SLOT(outputNotify()));

    return o;
}

void RtpPlayerDialog::outputNotify()
{
    double new_current_pos = 0.0;
    double current_pos = 0.0;

    double secs = marker_stream_->processedUSecs() / 1000000.0;

    if (ui->skipSilenceButton->isChecked()) {
        // We should check whether we can skip some silence
        // We must calculate in time domain as every stream can use different
        // play rate
        double min_silence = playing_streams_[0]->getEndOfSilenceTime();
        for( int i = 1; i<playing_streams_.count(); ++i ) {
            qint64 cur_silence = playing_streams_[i]->getEndOfSilenceTime();
            if (cur_silence < min_silence) {
                min_silence = cur_silence;
            }
        }

        if (min_silence > 0.0) {
            double silence_duration;

            // Calculate silence duration we can skip
            new_current_pos = first_stream_rel_start_time_ + min_silence;
            if (ui->todCheckBox->isChecked()) {
                current_pos = secs + start_marker_time_play_ + first_stream_rel_start_time_;
            } else {
                current_pos = secs + start_marker_time_play_;
            }
            silence_duration = new_current_pos - current_pos;

            if (silence_duration >= ui->minSilenceSpinBox->value()) {
                // Skip silence gap and update cursor difference
                for( int i = 0; i<playing_streams_.count(); ++i ) {
                    // Convert silence from time domain to samples
                    qint64 skip_samples = playing_streams_[i]->convertTimeToSamples(min_silence);
                    playing_streams_[i]->seekPlaying(skip_samples);
                }
                silence_skipped_time_ = silence_duration;
            }
        }
    }

    // Calculate new cursor position
    if (ui->todCheckBox->isChecked()) {
        secs += start_marker_time_play_;
        secs += silence_skipped_time_;
    } else {
        secs += start_marker_time_play_;
        secs -= first_stream_rel_start_time_;
        secs += silence_skipped_time_;
    }
    setPlayPosition(secs);
}

void RtpPlayerDialog::on_pauseButton_clicked()
{
    for( int i = 0; i<playing_streams_.count(); ++i ) {
        playing_streams_[i]->pausePlaying();
    }
    if (ui->pauseButton->isChecked()) {
        marker_stream_->suspend();
    } else {
        marker_stream_->resume();
    }
    updateWidgets();
}

void RtpPlayerDialog::on_stopButton_clicked()
{
    // We need copy of list because items will be removed during stopPlaying()
    QList<RtpAudioStream *> ps=QList<RtpAudioStream *>(playing_streams_);
    for( int i = 0; i<ps.count(); ++i ) {
        ps[i]->stopPlaying();
    }
    marker_stream_->stop();
    cur_play_pos_->setVisible(false);
    updateWidgets();
}

void RtpPlayerDialog::on_actionReset_triggered()
{
    resetXAxis();
}

void RtpPlayerDialog::on_actionZoomIn_triggered()
{
    zoomXAxis(true);
}

void RtpPlayerDialog::on_actionZoomOut_triggered()
{
    zoomXAxis(false);
}

void RtpPlayerDialog::on_actionMoveLeft10_triggered()
{
    panXAxis(-10);
}

void RtpPlayerDialog::on_actionMoveRight10_triggered()
{
    panXAxis(10);
}

void RtpPlayerDialog::on_actionMoveLeft1_triggered()
{
    panXAxis(-1);
}

void RtpPlayerDialog::on_actionMoveRight1_triggered()
{
    panXAxis(1);
}

void RtpPlayerDialog::on_actionGoToPacket_triggered()
{
    int packet_num = getHoveredPacket();
    if (packet_num > 0) emit goToPacket(packet_num);
}

void RtpPlayerDialog::handleGoToSetupPacket(QTreeWidgetItem *ti)
{
    if (ti) {
        bool ok;

        int packet_num = ti->data(first_pkt_col_, Qt::UserRole).toInt(&ok);
        if (ok) {
            emit goToPacket(packet_num);
        }
    }
}

void RtpPlayerDialog::on_actionGoToSetupPacketPlot_triggered()
{
    QPoint pos = ui->audioPlot->mapFromGlobal(QCursor::pos());
    handleGoToSetupPacket(findItemByCoords(pos));
}

void RtpPlayerDialog::on_actionGoToSetupPacketTree_triggered()
{
    handleGoToSetupPacket(last_ti_);
}

// Make waveform graphs selectable and update the treewidget selection accordingly.
void RtpPlayerDialog::on_streamTreeWidget_itemSelectionChanged()
{
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<RtpAudioGraph*>();
        if (audio_graph) {
            audio_graph->setSelected(ti->isSelected());
        }
    }

    int selected = ui->streamTreeWidget->selectedItems().count();
    if (selected == 0) {
        analyze_btn_->setEnabled(false);
        prepare_btn_->setEnabled(false);
        export_btn_->setEnabled(false);
    } else if (selected == 1) {
        analyze_btn_->setEnabled(true);
        prepare_btn_->setEnabled(true);
        export_btn_->setEnabled(true);
        ui->actionSavePayload->setEnabled(true);
    } else {
        analyze_btn_->setEnabled(true);
        prepare_btn_->setEnabled(true);
        export_btn_->setEnabled(true);
        ui->actionSavePayload->setEnabled(false);
    }

    if (!block_redraw_) {
        ui->audioPlot->replot();
        updateHintLabel();
    }
}

// Change channel audio routing if double clicked channel column
void RtpPlayerDialog::on_streamTreeWidget_itemDoubleClicked(QTreeWidgetItem *item, const int column)
{
    if (column == channel_col_) {
        RtpAudioStream *audio_stream = item->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (!audio_stream)
            return;

        AudioRouting audio_routing = audio_stream->getAudioRouting();
        audio_routing = audio_routing.getNextChannel(stereo_available_);
        changeAudioRoutingOnItem(item, audio_routing);
    }
    updateHintLabel();
}

void RtpPlayerDialog::removeRow(QTreeWidgetItem *ti)
{
    if (last_ti_ && (last_ti_ == ti)) {
        highlightItem(last_ti_, false);
        last_ti_ = NULL;
    }
    RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
    if (audio_stream) {
        stream_hash_.remove(audio_stream->getHash(), audio_stream);
        ti->setData(stream_data_col_, Qt::UserRole, QVariant());
        delete audio_stream;
    }

    RtpAudioGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<RtpAudioGraph*>();
    if (audio_graph) {
        ti->setData(graph_audio_data_col_, Qt::UserRole, QVariant());
        audio_graph->remove(ui->audioPlot);
    }

    QCPGraph *graph;
    graph = ti->data(graph_sequence_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_sequence_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
    }

    graph = ti->data(graph_jitter_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_jitter_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
    }

    graph = ti->data(graph_timestamp_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_timestamp_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
    }

    graph = ti->data(graph_silence_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_silence_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
    }

    delete ti;
}

void RtpPlayerDialog::on_actionRemoveStream_triggered()
{
    lockUI();
    QList<QTreeWidgetItem *> items = ui->streamTreeWidget->selectedItems();

    block_redraw_ = true;
    for(int i = items.count() - 1; i>=0; i-- ) {
        removeRow(items[i]);
    }
    block_redraw_ = false;
    // TODO: Recalculate legend
    // - Graphs used for legend could be removed above and we must add new
    // - If no legend is required, it should be removed

    // Redraw existing waveforms and rescale Y axis
    updateGraphs();

    updateWidgets();
    unlockUI();
}

// If called with channel_any, just muted flag should be changed
void RtpPlayerDialog::changeAudioRoutingOnItem(QTreeWidgetItem *ti, AudioRouting new_audio_routing)
{
    if (!ti)
        return;

    RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
    if (!audio_stream)
        return;

    AudioRouting audio_routing = audio_stream->getAudioRouting();
    audio_routing.mergeAudioRouting(new_audio_routing);
    formatAudioRouting(ti, audio_routing);

    audio_stream->setAudioRouting(audio_routing);

    RtpAudioGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<RtpAudioGraph*>();
    if (audio_graph) {

        audio_graph->setSelected(ti->isSelected());
        audio_graph->setMuted(audio_routing.isMuted());
        if (!block_redraw_) {
            ui->audioPlot->replot();
        }
    }
}

// Find current item and apply change on it
void RtpPlayerDialog::changeAudioRouting(AudioRouting new_audio_routing)
{
    lockUI();
    QList<QTreeWidgetItem *> items = ui->streamTreeWidget->selectedItems();

    block_redraw_ = true;
    for(int i = 0; i<items.count(); i++ ) {

        QTreeWidgetItem *ti = items[i];
        changeAudioRoutingOnItem(ti, new_audio_routing);
    }
    block_redraw_ = false;
    ui->audioPlot->replot();
    updateHintLabel();
    unlockUI();
}

// Invert mute/unmute on item
void RtpPlayerDialog::invertAudioMutingOnItem(QTreeWidgetItem *ti)
{
    if (!ti)
        return;

    RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
    if (!audio_stream)
        return;

    AudioRouting audio_routing = audio_stream->getAudioRouting();
    // Invert muting
    if (audio_routing.isMuted()) {
        changeAudioRoutingOnItem(ti, AudioRouting(AUDIO_UNMUTED, channel_any));
    } else {
        changeAudioRoutingOnItem(ti, AudioRouting(AUDIO_MUTED, channel_any));
    }
}

void RtpPlayerDialog::on_actionAudioRoutingP_triggered()
{
    changeAudioRouting(AudioRouting(AUDIO_UNMUTED, channel_mono));
}

void RtpPlayerDialog::on_actionAudioRoutingL_triggered()
{
    changeAudioRouting(AudioRouting(AUDIO_UNMUTED, channel_stereo_left));
}

void RtpPlayerDialog::on_actionAudioRoutingLR_triggered()
{
    changeAudioRouting(AudioRouting(AUDIO_UNMUTED, channel_stereo_both));
}

void RtpPlayerDialog::on_actionAudioRoutingR_triggered()
{
    changeAudioRouting(AudioRouting(AUDIO_UNMUTED, channel_stereo_right));
}

void RtpPlayerDialog::on_actionAudioRoutingMute_triggered()
{
    changeAudioRouting(AudioRouting(AUDIO_MUTED, channel_any));
}

void RtpPlayerDialog::on_actionAudioRoutingUnmute_triggered()
{
    changeAudioRouting(AudioRouting(AUDIO_UNMUTED, channel_any));
}

void RtpPlayerDialog::on_actionAudioRoutingMuteInvert_triggered()
{
    lockUI();
    QList<QTreeWidgetItem *> items = ui->streamTreeWidget->selectedItems();

    block_redraw_ = true;
    for(int i = 0; i<items.count(); i++ ) {

        QTreeWidgetItem *ti = items[i];
        invertAudioMutingOnItem(ti);
    }
    block_redraw_ = false;
    ui->audioPlot->replot();
    updateHintLabel();
    unlockUI();
}

const QString RtpPlayerDialog::getFormatedTime(double f_time)
{
    QString time_str;

    if (ui->todCheckBox->isChecked()) {
        QDateTime date_time = QDateTime::fromMSecsSinceEpoch(f_time * 1000.0);
        time_str = date_time.toString("yyyy-MM-dd hh:mm:ss.zzz");
    } else {
        time_str = QString::number(f_time, 'f', 6);
        time_str += " s";
    }

    return time_str;
}

const QString RtpPlayerDialog::getFormatedHoveredTime()
{
    QPoint pos = ui->audioPlot->mapFromGlobal(QCursor::pos());
    QTreeWidgetItem *ti = findItemByCoords(pos);
    if (!ti) return tr("Unknown");

    double ts = ui->audioPlot->xAxis->pixelToCoord(pos.x());

    return getFormatedTime(ts);
}

int RtpPlayerDialog::getHoveredPacket()
{
    QPoint pos = ui->audioPlot->mapFromGlobal(QCursor::pos());
    QTreeWidgetItem *ti = findItemByCoords(pos);
    if (!ti) return 0;

    RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();

    double ts = ui->audioPlot->xAxis->pixelToCoord(pos.x());

    return audio_stream->nearestPacket(ts, !ui->todCheckBox->isChecked());
}

// Used by RtpAudioStreams to initialize QAudioOutput. We could alternatively
// pass the corresponding QAudioDeviceInfo directly.
QString RtpPlayerDialog::currentOutputDeviceName()
{
    return ui->outputDeviceComboBox->currentText();
}

void RtpPlayerDialog::fillAudioRateMenu()
{
    ui->outputAudioRate->blockSignals(true);
    ui->outputAudioRate->clear();
    ui->outputAudioRate->addItem(tr("Automatic"));
    foreach (int rate, getCurrentDeviceInfo().supportedSampleRates()) {
        ui->outputAudioRate->addItem(QString::number(rate));
    }
    ui->outputAudioRate->blockSignals(false);
}

void RtpPlayerDialog::cleanupMarkerStream()
{
    if (marker_stream_) {
        marker_stream_->stop();
        delete marker_stream_;
        marker_stream_ = NULL;
    }
}

void RtpPlayerDialog::on_outputDeviceComboBox_currentTextChanged(const QString &)
{
    lockUI();
    stereo_available_ = isStereoAvailable();
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (!audio_stream)
            continue;

        changeAudioRoutingOnItem(ti, audio_stream->getAudioRouting().convert(stereo_available_));
    }

    marker_stream_requested_out_rate_ = 0;
    cleanupMarkerStream();
    fillAudioRateMenu();
    rescanPackets();
    unlockUI();
}

void RtpPlayerDialog::on_outputAudioRate_currentTextChanged(const QString & rate_string)
{
    lockUI();
    // Any unconvertable string is converted to 0 => used as Automatic rate
    unsigned selected_rate = rate_string.toInt();

    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (!audio_stream)
            continue;

        audio_stream->setRequestedPlayRate(selected_rate);
    }
    marker_stream_requested_out_rate_ = selected_rate;
    cleanupMarkerStream();
    rescanPackets();
    unlockUI();
}

void RtpPlayerDialog::on_jitterSpinBox_valueChanged(double)
{
    rescanPackets();
}

void RtpPlayerDialog::on_timingComboBox_currentIndexChanged(int)
{
    rescanPackets();
}

void RtpPlayerDialog::on_todCheckBox_toggled(bool)
{
    QCPAxis *x_axis = ui->audioPlot->xAxis;
    double move;

    // Create plot with new tod settings
    createPlot();

    // Move view to same place as was shown before the change
    if (ui->todCheckBox->isChecked()) {
       // rel -> abs
       // based on abs time of first sample
       setStartPlayMarker(first_stream_abs_start_time_ + start_marker_time_ - first_stream_rel_start_time_);
       move = first_stream_abs_start_time_ - first_stream_rel_start_time_;
    } else {
       // abs -> rel
       // based on 0s
       setStartPlayMarker(first_stream_rel_start_time_ + start_marker_time_);
       move = - first_stream_abs_start_time_ + first_stream_rel_start_time_;
    }
    x_axis->moveRange(move);
    drawStartPlayMarker();
    ui->audioPlot->replot();
}

void RtpPlayerDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_TELEPHONY_RTP_PLAYER_DIALOG);
}

double RtpPlayerDialog::getStartPlayMarker()
{
    double start_pos;

    if (ui->todCheckBox->isChecked()) {
        start_pos = start_marker_time_ + first_stream_abs_start_time_;
    } else {
        start_pos = start_marker_time_;
    }

    return start_pos;
}

void RtpPlayerDialog::drawStartPlayMarker()
{
    double pos = getStartPlayMarker();

    start_marker_pos_->point1->setCoords(pos, 0.0);
    start_marker_pos_->point2->setCoords(pos, 1.0);

    updateHintLabel();
}

void RtpPlayerDialog::setStartPlayMarker(double new_time)
{
    if (ui->todCheckBox->isChecked()) {
        new_time = qBound(first_stream_abs_start_time_, new_time, first_stream_abs_start_time_ + streams_length_);
        // start_play_time is relative, we must calculate it
        start_marker_time_ = new_time - first_stream_abs_start_time_;
    } else {
        new_time = qBound(first_stream_rel_start_time_, new_time, first_stream_rel_start_time_ + streams_length_);
        start_marker_time_ = new_time;
    }
}

void RtpPlayerDialog::updateStartStopTime(rtpstream_info_t *rtpstream, bool is_first)
{
    // Calculate start time of first last packet of last stream
    double stream_rel_start_time = nstime_to_sec(&rtpstream->start_rel_time);
    double stream_abs_start_time = nstime_to_sec(&rtpstream->start_abs_time);
    double stream_rel_stop_time = nstime_to_sec(&rtpstream->stop_rel_time);

    if (is_first) {
        // Take start/stop time for first stream
        first_stream_rel_start_time_ = stream_rel_start_time;
        first_stream_abs_start_time_ = stream_abs_start_time;
        first_stream_rel_stop_time_ = stream_rel_stop_time;
    } else {
        // Calculate min/max for start/stop time for other streams
        first_stream_rel_start_time_ = qMin(first_stream_rel_start_time_, stream_rel_start_time);
        first_stream_abs_start_time_ = qMin(first_stream_abs_start_time_, stream_abs_start_time);
        first_stream_rel_stop_time_ = qMax(first_stream_rel_stop_time_, stream_rel_stop_time);
    }
    streams_length_ = first_stream_rel_stop_time_ - first_stream_rel_start_time_;
}

void RtpPlayerDialog::formatAudioRouting(QTreeWidgetItem *ti, AudioRouting audio_routing)
{
    ti->setText(channel_col_, tr(audio_routing.formatAudioRoutingToString()));
}

bool RtpPlayerDialog::isStereoAvailable()
{
    QAudioDeviceInfo cur_out_device = getCurrentDeviceInfo();
    foreach(int count, cur_out_device.supportedChannelCounts()) {
        if (count>1) {
            return true;
        }
    }

    return false;
}

void RtpPlayerDialog::invertSelection()
{
    block_redraw_ = true;
    ui->streamTreeWidget->blockSignals(true);
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        ti->setSelected(!ti->isSelected());
    }
    ui->streamTreeWidget->blockSignals(false);
    block_redraw_ = false;
    ui->audioPlot->replot();
    updateHintLabel();
}

void RtpPlayerDialog::on_actionSelectAll_triggered()
{
    ui->streamTreeWidget->selectAll();
    updateHintLabel();
}

void RtpPlayerDialog::on_actionSelectInvert_triggered()
{
    invertSelection();
    updateHintLabel();
}

void RtpPlayerDialog::on_actionSelectNone_triggered()
{
    ui->streamTreeWidget->clearSelection();
    updateHintLabel();
}

void RtpPlayerDialog::on_actionPlay_triggered()
{
    if (ui->playButton->isEnabled()) {
        ui->playButton->animateClick();
    } else if (ui->pauseButton->isEnabled()) {
        ui->pauseButton->animateClick();
    }
}

void RtpPlayerDialog::on_actionStop_triggered()
{
    if (ui->stopButton->isEnabled()) {
        ui->stopButton->animateClick();
    }
}

qint64 RtpPlayerDialog::saveAudioHeaderAU(QFile *save_file, int channels, unsigned audio_rate)
{
    uint8_t pd[4];
    int64_t nchars;

    /* https://pubs.opengroup.org/external/auformat.html */
    /* First we write the .au header.  All values in the header are
     * 4-byte big-endian values, so we use pntoh32() to copy them
     * to a 4-byte buffer, in big-endian order, and then write out
     * the buffer. */

    /* the magic word 0x2e736e64 == .snd */
    phton32(pd, 0x2e736e64);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* header offset == 24 bytes */
    phton32(pd, 24);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* total length; it is permitted to set this to 0xffffffff */
    phton32(pd, 0xffffffff);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* encoding format == 16-bit linear PCM */
    phton32(pd, 3);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* sample rate [Hz] */
    phton32(pd, audio_rate);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* channels */
    phton32(pd, channels);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    return save_file->pos();
}

qint64 RtpPlayerDialog::saveAudioHeaderWAV(QFile *save_file, int channels, unsigned audio_rate, qint64 samples)
{
    uint8_t pd[4];
    int64_t nchars;
    gint32  subchunk2Size;
    gint32  data32;
    gint16  data16;

    subchunk2Size = sizeof(SAMPLE) * channels * (gint32)samples;

    /* http://soundfile.sapp.org/doc/WaveFormat/ */

    /* RIFF header, ChunkID 0x52494646 == RIFF */
    phton32(pd, 0x52494646);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* RIFF header, ChunkSize */
    data32 = 36 + subchunk2Size;
    nchars = save_file->write((const char *)&data32, 4);
    if (nchars != 4) {
        return -1;
    }

    /* RIFF header, Format 0x57415645 == WAVE */
    phton32(pd, 0x57415645);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* WAVE fmt header, Subchunk1ID 0x666d7420 == 'fmt ' */
    phton32(pd, 0x666d7420);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* WAVE fmt header, Subchunk1Size */
    data32 = 16;
    nchars = save_file->write((const char *)&data32, 4);
    if (nchars != 4) {
        return -1;
    }

    /* WAVE fmt header, AudioFormat 1 == PCM */
    data16 = 1;
    nchars = save_file->write((const char *)&data16, 2);
    if (nchars != 2) {
        return -1;
    }

    /* WAVE fmt header, NumChannels */
    data16 = channels;
    nchars = save_file->write((const char *)&data16, 2);
    if (nchars != 2) {
        return -1;
    }

    /* WAVE fmt header, SampleRate */
    data32 = audio_rate;
    nchars = save_file->write((const char *)&data32, 4);
    if (nchars != 4) {
        return -1;
    }

    /* WAVE fmt header, ByteRate */
    data32 = audio_rate * channels * sizeof(SAMPLE);
    nchars = save_file->write((const char *)&data32, 4);
    if (nchars != 4) {
        return -1;
    }

    /* WAVE fmt header, BlockAlign */
    data16 = channels * (gint16)sizeof(SAMPLE);
    nchars = save_file->write((const char *)&data16, 2);
    if (nchars != 2) {
        return -1;
    }

    /* WAVE fmt header, BitsPerSample */
    data16 = (gint16)sizeof(SAMPLE) * 8;
    nchars = save_file->write((const char *)&data16, 2);
    if (nchars != 2) {
        return -1;
    }

    /* WAVE data header, Subchunk2ID 0x64617461 == 'data' */
    phton32(pd, 0x64617461);
    nchars = save_file->write((const char *)pd, 4);
    if (nchars != 4) {
        return -1;
    }

    /* WAVE data header, Subchunk2Size */
    data32 = subchunk2Size;
    nchars = save_file->write((const char *)&data32, 4);
    if (nchars != 4) {
        return -1;
    }

    /* Now we are ready for saving data */

    return save_file->pos();
}

bool RtpPlayerDialog::writeAudioSilenceSamples(QFile *out_file, qint64 samples, int stream_count)
{
    uint8_t pd[2];

    phton16(pd, 0x0000);
    for(int s=0; s < stream_count; s++) {
        for(qint64 i=0; i < samples; i++) {
            if (sizeof(SAMPLE) != out_file->write((char *)&pd, sizeof(SAMPLE))) {
                return false;
            }
        }
    }

    return true;
}

bool RtpPlayerDialog::writeAudioStreamsSamples(QFile *out_file, QVector<RtpAudioStream *> streams, bool swap_bytes)
{
    SAMPLE sample;
    uint8_t pd[2];

    // Did we read something in last cycle?
    bool read = true;

    while (read) {
        read = false;
        // Loop over all streams, read one sample from each, write to output
        foreach(RtpAudioStream *audio_stream, streams) {
            if (sizeof(sample) == audio_stream->readSample(&sample)) {
                if (swap_bytes) {
                    // same as phton16(), but more clear in compare
                    // to else branch
                    pd[0] = (guint8)(sample >> 8);
                    pd[1] = (guint8)(sample >> 0);
                } else {
                    // just copy
                    pd[1] = (guint8)(sample >> 8);
                    pd[0] = (guint8)(sample >> 0);
                }
                read = true;
            } else {
                // for 0x0000 doesn't matter on order
                phton16(pd, 0x0000);
            }
            if (sizeof(sample) != out_file->write((char *)&pd, sizeof(sample))) {
                return false;
            }
        }
    }

    return true;
}

save_audio_t RtpPlayerDialog::selectFileAudioFormatAndName(QString *file_path)
{
    QString ext_filter = "";
    QString ext_filter_wav = tr("WAV (*.wav)");
    QString ext_filter_au = tr("Sun Audio (*.au)");
    ext_filter.append(ext_filter_wav);
    ext_filter.append(";;");
    ext_filter.append(ext_filter_au);

    QString sel_filter;
    *file_path = WiresharkFileDialog::getSaveFileName(
                this, tr("Save audio"), mainApp->lastOpenDir().absoluteFilePath(""),
                ext_filter, &sel_filter);

    if (file_path->isEmpty()) return save_audio_none;

    save_audio_t save_format = save_audio_none;
    if (0 == QString::compare(sel_filter, ext_filter_au)) {
        save_format = save_audio_au;
    } else if (0 == QString::compare(sel_filter, ext_filter_wav)) {
        save_format = save_audio_wav;
    }

    return save_format;
}

save_payload_t RtpPlayerDialog::selectFilePayloadFormatAndName(QString *file_path)
{
    QString ext_filter = "";
    QString ext_filter_raw = tr("Raw (*.raw)");
    ext_filter.append(ext_filter_raw);

    QString sel_filter;
    *file_path = WiresharkFileDialog::getSaveFileName(
                this, tr("Save payload"), mainApp->lastOpenDir().absoluteFilePath(""),
                ext_filter, &sel_filter);

    if (file_path->isEmpty()) return save_payload_none;

    save_payload_t save_format = save_payload_none;
    if (0 == QString::compare(sel_filter, ext_filter_raw)) {
        save_format = save_payload_data;
    }

    return save_format;
}

QVector<rtpstream_id_t *>RtpPlayerDialog::getSelectedRtpStreamIDs()
{
    QList<QTreeWidgetItem *> items = ui->streamTreeWidget->selectedItems();
    QVector<rtpstream_id_t *> ids;

    if (items.count() > 0) {
        foreach(QTreeWidgetItem *ti, items) {
            RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
            if (audio_stream) {
                ids << audio_stream->getID();
            }
        }
    }

    return ids;
}

QVector<RtpAudioStream *>RtpPlayerDialog::getSelectedAudibleNonmutedAudioStreams()
{
    QList<QTreeWidgetItem *> items = ui->streamTreeWidget->selectedItems();
    QVector<RtpAudioStream *> streams;

    if (items.count() > 0) {
        foreach(QTreeWidgetItem *ti, items) {
            RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
            // Ignore muted streams and streams with no audio
            if (audio_stream &&
                !audio_stream->getAudioRouting().isMuted() &&
                (audio_stream->sampleRate()>0)
               ) {
                streams << audio_stream;
            }
        }
    }

    return streams;
}

void RtpPlayerDialog::saveAudio(save_mode_t save_mode)
{
    qint64 minSilenceSamples;
    qint64 startSample;
    qint64 lead_silence_samples;
    qint64 maxSample;
    QString path;
    QVector<RtpAudioStream *>streams;

    streams = getSelectedAudibleNonmutedAudioStreams();
    if (streams.count() < 1) {
        QMessageBox::warning(this, tr("Warning"), tr("No stream selected or none of selected streams provide audio"));
        return;
    }

    unsigned save_audio_rate = streams[0]->playRate();
    // Check whether all streams use same audio rate
    foreach(RtpAudioStream *audio_stream, streams) {
        if (save_audio_rate != audio_stream->playRate()) {
            QMessageBox::warning(this, tr("Error"), tr("All selected streams must use same play rate. Manual set of Output Audio Rate might help."));
            return;
        }
    }

    save_audio_t format = selectFileAudioFormatAndName(&path);
    if (format == save_audio_none) return;

    // Use start silence and length of first stream
    minSilenceSamples = streams[0]->getLeadSilenceSamples();
    maxSample = streams[0]->getTotalSamples();
    // Find shortest start silence and longest stream
    foreach(RtpAudioStream *audio_stream, streams) {
        if (minSilenceSamples > audio_stream->getLeadSilenceSamples()) {
            minSilenceSamples = audio_stream->getLeadSilenceSamples();
        }
        if (maxSample < audio_stream->getTotalSamples()) {
            maxSample = audio_stream->getTotalSamples();
        }
    }

    switch (save_mode) {
        case save_mode_from_cursor:
            if (ui->todCheckBox->isChecked()) {
                startSample = start_marker_time_ * save_audio_rate;
            } else {
                startSample = (start_marker_time_ - first_stream_rel_start_time_) * save_audio_rate;
            }
            lead_silence_samples = 0;
            break;
        case save_mode_sync_stream:
            // Skip start of first stream, no lead silence
            startSample = minSilenceSamples;
            lead_silence_samples = 0;
            break;
        case save_mode_sync_file:
        default:
            // Full first stream, lead silence
            startSample = 0;
            lead_silence_samples = first_stream_rel_start_time_ * save_audio_rate;
            break;
    }

    QVector<RtpAudioStream *>temp = QVector<RtpAudioStream *>(streams);

    // Remove streams shorter than startSample and
    // seek to correct start for longer ones
    foreach(RtpAudioStream *audio_stream, temp) {
        if (startSample > audio_stream->getTotalSamples()) {
            streams.removeAll(audio_stream);
        } else {
            audio_stream->seekSample(startSample);
        }
    }

    if (streams.count() < 1) {
        QMessageBox::warning(this, tr("Warning"), tr("No streams are suitable for save"));
        return;
    }

    QFile file(path);
    file.open(QIODevice::WriteOnly);

    if (!file.isOpen() || (file.error() != QFile::NoError)) {
        QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
    } else {
        switch (format) {
            case save_audio_au:
                if (-1 == saveAudioHeaderAU(&file, streams.count(), save_audio_rate)) {
                   QMessageBox::warning(this, tr("Error"), tr("Can't write header of AU file"));
                   return;
                }
                if (lead_silence_samples > 0) {
                    if (!writeAudioSilenceSamples(&file, lead_silence_samples, streams.count())) {
                        QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
                    }
                }
                if (!writeAudioStreamsSamples(&file, streams, true)) {
                    QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
                }
                break;
            case save_audio_wav:
                if (-1 == saveAudioHeaderWAV(&file, streams.count(), save_audio_rate, (maxSample - startSample) + lead_silence_samples)) {
                   QMessageBox::warning(this, tr("Error"), tr("Can't write header of WAV file"));
                   return;
                }
                if (lead_silence_samples > 0) {
                    if (!writeAudioSilenceSamples(&file, lead_silence_samples, streams.count())) {
                        QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
                    }
                }
                if (!writeAudioStreamsSamples(&file, streams, false)) {
                    QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
                }
                break;
            case save_audio_none:
                break;
        }
    }

    file.close();
}

void RtpPlayerDialog::savePayload()
{
    QString path;
    QList<QTreeWidgetItem *> items;
    RtpAudioStream *audio_stream = NULL;

    items = ui->streamTreeWidget->selectedItems();
    foreach(QTreeWidgetItem *ti, items) {
        audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (audio_stream)
           break;
    }
    if (items.count() != 1 || !audio_stream) {
        QMessageBox::warning(this, tr("Warning"), tr("Payload save works with just one audio stream."));
        return;
    }

    save_payload_t format = selectFilePayloadFormatAndName(&path);
    if (format == save_payload_none) return;

    QFile file(path);
    file.open(QIODevice::WriteOnly);

    if (!file.isOpen() || (file.error() != QFile::NoError)) {
        QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
    } else if (!audio_stream->savePayload(&file)) {
        QMessageBox::warning(this, tr("Warning"), tr("Save failed!"));
    }

    file.close();
}

void RtpPlayerDialog::on_actionSaveAudioFromCursor_triggered()
{
    saveAudio(save_mode_from_cursor);
}

void RtpPlayerDialog::on_actionSaveAudioSyncStream_triggered()
{
    saveAudio(save_mode_sync_stream);
}

void RtpPlayerDialog::on_actionSaveAudioSyncFile_triggered()
{
    saveAudio(save_mode_sync_file);
}

void RtpPlayerDialog::on_actionSavePayload_triggered()
{
    savePayload();
}

void RtpPlayerDialog::selectInaudible(bool select)
{
    block_redraw_ = true;
    ui->streamTreeWidget->blockSignals(true);
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        // Streams with no audio
        if (audio_stream && (audio_stream->sampleRate()==0)) {
            ti->setSelected(select);
        }
    }
    ui->streamTreeWidget->blockSignals(false);
    block_redraw_ = false;
    ui->audioPlot->replot();
    updateHintLabel();
}

void RtpPlayerDialog::on_actionSelectInaudible_triggered()
{
    selectInaudible(true);
}

void RtpPlayerDialog::on_actionDeselectInaudible_triggered()
{
    selectInaudible(false);
}

void RtpPlayerDialog::on_actionPrepareFilter_triggered()
{
    QVector<rtpstream_id_t *> ids = getSelectedRtpStreamIDs();
    QString filter = make_filter_based_on_rtpstream_id(ids);
    if (filter.length() > 0) {
        emit updateFilter(filter);
    }
}

void RtpPlayerDialog::rtpAnalysisReplace()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpAnalysisDialogReplaceRtpStreams(getSelectedRtpStreamIDs());
}

void RtpPlayerDialog::rtpAnalysisAdd()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpAnalysisDialogAddRtpStreams(getSelectedRtpStreamIDs());
}

void RtpPlayerDialog::rtpAnalysisRemove()
{
    if (ui->streamTreeWidget->selectedItems().count() < 1) return;

    emit rtpAnalysisDialogRemoveRtpStreams(getSelectedRtpStreamIDs());
}

void RtpPlayerDialog::on_actionReadCapture_triggered()
{
#ifdef QT_MULTIMEDIA_LIB
    QTimer::singleShot(0, this, SLOT(retapPackets()));
#endif
}

// _U_ is used for case w have no LIBPCAP
void RtpPlayerDialog::captureEvent(CaptureEvent e _U_)
{
#ifdef HAVE_LIBPCAP
    bool new_read_capture_enabled = false;
    bool found = false;

    if ((e.captureContext() & CaptureEvent::Capture) &&
        (e.eventType() == CaptureEvent::Prepared)
       ) {
        new_read_capture_enabled = true;
        found = true;
    } else if ((e.captureContext() & CaptureEvent::Capture) &&
               (e.eventType() == CaptureEvent::Finished)
              ) {
        new_read_capture_enabled = false;
        found = true;
    }

    if (found) {
        bool retap = false;
        if (read_capture_enabled_ && !new_read_capture_enabled) {
            // Capturing ended, automatically refresh data
            retap = true;
        }
        read_capture_enabled_ = new_read_capture_enabled;
        updateWidgets();
        if (retap) {
            QTimer::singleShot(0, this, SLOT(retapPackets()));
        }
    }
#endif
}

#endif // QT_MULTIMEDIA_LIB
