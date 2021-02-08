/* rtp_player_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/rtp_media.h>
#include "rtp_player_dialog.h"
#include <ui_rtp_player_dialog.h>

#ifdef QT_MULTIMEDIA_LIB

#include <epan/dissectors/packet-rtp.h>

#include <wsutil/report_message.h>
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_audio_stream.h"
#include <ui/qt/utils/tango_colors.h>

#include <QAudio>
#include <QAudioDeviceInfo>
#include <QFrame>
#include <QMenu>
#include <QVBoxLayout>

#include <QAudioFormat>
#include <QAudioOutput>
#include <ui/qt/utils/rtp_audio_silence_generator.h>

#endif // QT_MULTIMEDIA_LIB

#include <QPushButton>

#include <ui/qt/utils/stock_icon.h>
#include "wireshark_application.h"

// To do:
// - Fully implement shorcuts (drag, go to packet, etc.)
// - Figure out selection and highlighting.
// - Make streams checkable.
// - Add silence, drop & jitter indicators to the graph.
// - How to handle multiple channels?
// - Threaded decoding?
// - Play MP3s. As per Zawinski's Law we already read emails.
// - RTP audio streams are currently keyed on src addr + src port + dst addr
//   + dst port + ssrc. This means that we can have multiple rtp_stream_info
//   structs per RtpAudioStream. Should we make them 1:1 instead?

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

// XXX It looks like we duplicate some functionality here and in the RTP
// analysis code, which has its own routines for writing audio data to a
// file.

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
    payload_col_,

    stream_data_col_ = src_addr_col_, // RtpAudioStream
    graph_audio_data_col_ = src_port_col_, // QCPGraph (wave)
    graph_sequence_data_col_ = dst_addr_col_, // QCPGraph (sequence)
    graph_jitter_data_col_ = dst_port_col_, // QCPGraph (jitter)
    graph_timestamp_data_col_ = ssrc_col_, // QCPGraph (timestamp)
    graph_silence_data_col_ = first_pkt_col_, // QCPGraph (silence)
};


#ifdef QT_MULTIMEDIA_LIB
static const double wf_graph_normal_width_ = 0.5;
#endif

RtpPlayerDialog::RtpPlayerDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf)
#ifdef QT_MULTIMEDIA_LIB
    , ui(new Ui::RtpPlayerDialog)
    , first_stream_rel_start_time_(0.0)
    , first_stream_abs_start_time_(0.0)
    , first_stream_rel_stop_time_(0.0)
    , streams_length_(0.0)
    , start_marker_time_(0.0)
#endif // QT_MULTIMEDIA_LIB
    , number_ticker_(new QCPAxisTicker)
    , datetime_ticker_(new QCPAxisTickerDateTime)
    , stereo_available_(false)
    , marker_stream_(0)
    , listener_removed_(false)
{
    ui->setupUi(this);
    setWindowTitle(wsApp->windowTitleString(tr("RTP Player")));
    loadGeometry(parent.width(), parent.height());

#ifdef QT_MULTIMEDIA_LIB
    ui->splitter->setStretchFactor(0, 3);
    ui->splitter->setStretchFactor(1, 1);

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
    graph_ctx_menu_->addSeparator();
    graph_ctx_menu_->addAction(ui->actionDragZoom);
    graph_ctx_menu_->addAction(ui->actionToggleTimeOrigin);
//    graph_ctx_menu_->addAction(ui->actionCrosshairs);
    set_action_shortcuts_visible_in_context_menu(graph_ctx_menu_->actions());

    connect(ui->audioPlot, SIGNAL(mouseMove(QMouseEvent*)),
            this, SLOT(updateHintLabel()));
    connect(ui->audioPlot, SIGNAL(mousePress(QMouseEvent*)),
            this, SLOT(graphClicked(QMouseEvent*)));
    connect(ui->audioPlot, SIGNAL(mouseDoubleClick(QMouseEvent*)),
            this, SLOT(graphDoubleClicked(QMouseEvent*)));
    connect(ui->audioPlot, SIGNAL(plottableClick(QCPAbstractPlottable*,int,QMouseEvent*)),
            this, SLOT(plotClicked(QCPAbstractPlottable*,int,QMouseEvent*)));

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

    // Ordered, unique device names starting with the system default
    QMap<QString, bool> out_device_map; // true == default device
    out_device_map.insert(QAudioDeviceInfo::defaultOutputDevice().deviceName(), true);
    foreach (QAudioDeviceInfo out_device, QAudioDeviceInfo::availableDevices(QAudio::AudioOutput)) {
        if (!out_device_map.contains(out_device.deviceName())) {
            out_device_map.insert(out_device.deviceName(), false);
        }
    }

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
        ui->outputDeviceComboBox->addItem(tr("No devices available"));
    } else {
        stereo_available_ = isStereoAvailable();
    }

    ui->audioPlot->setMouseTracking(true);
    ui->audioPlot->setEnabled(true);
    ui->audioPlot->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );
    ui->audioPlot->setFocus();

    graph_ctx_menu_->addSeparator();
    list_ctx_menu_ = new QMenu(this);
    QMenu *audio_routing_menu1 = list_ctx_menu_->addMenu(tr("Audio Routing"));
    QMenu *audio_routing_menu2 = graph_ctx_menu_->addMenu(tr("Audio Routing"));
    // All AudioRouting actions are in menu, some of them are disabled later
    audio_routing_menu1->addAction(ui->actionAudioRoutingM);
    audio_routing_menu2->addAction(ui->actionAudioRoutingM);
    audio_routing_menu1->addAction(ui->actionAudioRoutingP);
    audio_routing_menu2->addAction(ui->actionAudioRoutingP);
    audio_routing_menu1->addAction(ui->actionAudioRoutingL);
    audio_routing_menu2->addAction(ui->actionAudioRoutingL);
    audio_routing_menu1->addAction(ui->actionAudioRoutingLR);
    audio_routing_menu2->addAction(ui->actionAudioRoutingLR);
    audio_routing_menu1->addAction(ui->actionAudioRoutingR);
    audio_routing_menu2->addAction(ui->actionAudioRoutingR);
    audio_routing_menu1->addAction(ui->actionAudioRoutingI);
    audio_routing_menu2->addAction(ui->actionAudioRoutingI);
    list_ctx_menu_->addAction(ui->actionRemoveStream);
    graph_ctx_menu_->addAction(ui->actionRemoveStream);
    set_action_shortcuts_visible_in_context_menu(list_ctx_menu_->actions());

    QTimer::singleShot(0, this, SLOT(retapPackets()));
#endif // QT_MULTIMEDIA_LIB
}

QPushButton *RtpPlayerDialog::addPlayerButton(QDialogButtonBox *button_box)
{
    if (!button_box) return NULL;

    QPushButton *player_button;
    player_button = button_box->addButton(tr("Play Streams"), QDialogButtonBox::ApplyRole);
    player_button->setIcon(StockIcon("media-playback-start"));
    return player_button;
}

#ifdef QT_MULTIMEDIA_LIB
RtpPlayerDialog::~RtpPlayerDialog()
{
    if (marker_stream_) {
        marker_stream_->stop();
        delete marker_stream_;
    }
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (audio_stream)
            delete audio_stream;
    }
    delete ui;
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
    ui->hintLabel->setText("<i><small>" + tr("Decoding streams...") + "</i></small>");
    wsApp->processEvents();

    // destroyCheck is protection againts destroying dialog during recap.
    // It stores dialog pointer in data() and if dialog destroyed, it
    // returns null
    QPointer<RtpPlayerDialog> destroyCheck=this;
    GString *error_string;

    error_string = register_tap_listener("rtp", this, NULL, 0, NULL, tapPacket, NULL, NULL);
    if (error_string) {
        report_failure("RTP Player - tap registration failed: %s", error_string->str);
        g_string_free(error_string, TRUE);
        return;
    }
    cap_file_.retapPackets();

    // Check if dialog exists still
    if (destroyCheck.data()) {
        if (!listener_removed_) {
            remove_tap_listener(this);
            listener_removed_ = true;
        }
        rescanPackets(true);
    }
}

void RtpPlayerDialog::rescanPackets(bool rescale_axes)
{
    // Show information for a user - it can last long time...
    ui->hintLabel->setText("<i><small>" + tr("Decoding streams...") + "</i></small>");
    wsApp->processEvents();

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
}

void RtpPlayerDialog::createPlot(bool rescale_axes)
{
    bool show_legend = false;
    bool relative_timestamps = !ui->todCheckBox->isChecked();
    int row_count = ui->streamTreeWidget->topLevelItemCount();

    ui->audioPlot->clearGraphs();

    if (relative_timestamps) {
        ui->audioPlot->xAxis->setTicker(number_ticker_);
    } else {
        ui->audioPlot->xAxis->setTicker(datetime_ticker_);
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

        // Waveform
        QCPGraph *audio_graph = ui->audioPlot->addGraph();
        QPen wf_pen(audio_stream->color());
        wf_pen.setWidthF(wf_graph_normal_width_);
        if (audio_routing.isMuted()) {
            // Indicate that audio will not be hearable
            wf_pen.setStyle(Qt::DotLine);
        }
        audio_graph->setPen(wf_pen);
        audio_graph->setSelectable(QCP::stNone);
        audio_graph->setData(audio_stream->visualTimestamps(relative_timestamps), audio_stream->visualSamples(y_offset));
        audio_graph->removeFromLegend();
        ti->setData(graph_audio_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(audio_graph));
        RTP_STREAM_DEBUG("Plotting %s, %d samples", ti->text(src_addr_col_).toUtf8().constData(), audio_graph->data()->size());

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
        ti->setText(payload_col_, audio_stream->payloadNames().join(", "));

        if (audio_stream->outOfSequence() > 0) {
            // Sequence numbers
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssSquare, tango_aluminium_6, Qt::white, wsApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->outOfSequenceTimestamps(relative_timestamps), audio_stream->outOfSequenceSamples(y_offset));
            ti->setData(graph_sequence_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (row < 1) {
                seq_graph->setName(tr("Out of Sequence"));
                show_legend = true;
            } else {
                seq_graph->removeFromLegend();
            }
        }

        if (audio_stream->jitterDropped() > 0) {
            // Jitter drops
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCircle, tango_scarlet_red_5, Qt::white, wsApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->jitterDroppedTimestamps(relative_timestamps), audio_stream->jitterDroppedSamples(y_offset));
            ti->setData(graph_jitter_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (row < 1) {
                seq_graph->setName(tr("Jitter Drops"));
                show_legend = true;
            } else {
                seq_graph->removeFromLegend();
            }
        }

        if (audio_stream->wrongTimestamps() > 0) {
            // Wrong timestamps
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDiamond, tango_sky_blue_5, Qt::white, wsApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->wrongTimestampTimestamps(relative_timestamps), audio_stream->wrongTimestampSamples(y_offset));
            ti->setData(graph_timestamp_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (row < 1) {
                seq_graph->setName(tr("Wrong Timestamps"));
                show_legend = true;
            } else {
                seq_graph->removeFromLegend();
            }
        }

        if (audio_stream->insertedSilences() > 0) {
            // Inserted silence
            QCPGraph *seq_graph = ui->audioPlot->addGraph();
            seq_graph->setLineStyle(QCPGraph::lsNone);
            seq_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssTriangle, tango_butter_5, Qt::white, wsApp->font().pointSize())); // Arbitrary
            seq_graph->setSelectable(QCP::stNone);
            seq_graph->setData(audio_stream->insertedSilenceTimestamps(relative_timestamps), audio_stream->insertedSilenceSamples(y_offset));
            ti->setData(graph_silence_data_col_, Qt::UserRole, QVariant::fromValue<QCPGraph *>(seq_graph));
            if (row < 1) {
                seq_graph->setName(tr("Inserted Silence"));
                show_legend = true;
            } else {
                seq_graph->removeFromLegend();
            }
        }
    }
    ui->audioPlot->legend->setVisible(show_legend);

    ui->audioPlot->replot();
    if (rescale_axes) resetXAxis();
}

void RtpPlayerDialog::addRtpStream(rtpstream_info_t *rtpstream)
{
    AudioRouting audio_routing = AudioRouting(AUDIO_UNMUTED, channel_mono);

    if (!rtpstream) return;

    // Find the RTP streams associated with this conversation.
    // gtk/rtp_player.c:mark_rtp_stream_to_play does this differently.

    RtpAudioStream *audio_stream = NULL;
    int tli_count = ui->streamTreeWidget->topLevelItemCount();
    for (int row = 0; row < tli_count; row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *row_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (row_stream->isMatch(rtpstream)) {
            audio_stream = row_stream;
            break;
        }
    }

    if (!audio_stream) {
        audio_stream = new RtpAudioStream(this, rtpstream, stereo_available_);
        audio_stream->setColor(ColorUtils::graphColor(tli_count));

        QTreeWidgetItem *ti = new QTreeWidgetItem(ui->streamTreeWidget);
        ti->setText(src_addr_col_, address_to_qstring(&rtpstream->id.src_addr));
        ti->setText(src_port_col_, QString::number(rtpstream->id.src_port));
        ti->setText(dst_addr_col_, address_to_qstring(&rtpstream->id.dst_addr));
        ti->setText(dst_port_col_, QString::number(rtpstream->id.dst_port));
        ti->setText(ssrc_col_, int_to_qstring(rtpstream->id.ssrc, 8, 16));
        ti->setText(first_pkt_col_, QString::number(rtpstream->setup_frame_number));
        ti->setText(num_pkts_col_, QString::number(rtpstream->packet_count));

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
        ti->setToolTip(channel_col_, QString(tr("Double click to change audio routing")));
        formatAudioRouting(ti, audio_routing);
        audio_stream->setAudioRouting(audio_routing);

        for (int col = 0; col < ui->streamTreeWidget->columnCount(); col++) {
            QBrush fgBrush = ti->foreground(col);
            fgBrush.setColor(audio_stream->color());
            ti->setForeground(col, fgBrush);
        }

        connect(audio_stream, SIGNAL(finishedPlaying(RtpAudioStream *)), this, SLOT(playFinished(RtpAudioStream *)));
        connect(audio_stream, SIGNAL(playbackError(QString)), this, SLOT(setPlaybackError(QString)));
    }

    // Update start/stop time nevertheless stream is new or already seen
    // because voip_calls_dialog.cpp splits same stream to multiple pieces
    updateStartStopTime(rtpstream, tli_count);

    RTP_STREAM_DEBUG("adding stream %d to layout, %u packets, start %u",
                     ui->streamTreeWidget->topLevelItemCount(),
                     rtpstream->packet_count,
                     rtpstream->start_fd ? rtpstream->start_fd->num : 0);
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

void RtpPlayerDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_secs = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
    case Qt::Key_O:             // GTK+
    case Qt::Key_R:
        on_actionZoomOut_triggered();
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
    case Qt::Key_I:             // GTK+
        on_actionZoomIn_triggered();
        break;

    case Qt::Key_Right:
    case Qt::Key_L:
        panXAxis(pan_secs);
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        panXAxis(-1 * pan_secs);
        break;

    case Qt::Key_Space:
//        toggleTracerStyle();
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_Home:
        on_actionReset_triggered();
        break;

    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        break;
    case Qt::Key_T:
//        on_actionToggleTimeOrigin_triggered();
        break;
    case Qt::Key_Z:
//        on_actionDragZoom_triggered();
        break;
    }

    QDialog::keyPressEvent(event);
}

void RtpPlayerDialog::contextMenuEvent(QContextMenuEvent *event)
{
    QTreeWidgetItem *ti = ui->streamTreeWidget->currentItem();
    if (!ti)
        return;

    list_ctx_menu_->exec(event->globalPos());
}

void RtpPlayerDialog::updateWidgets()
{
    bool enable_play = true;
    bool enable_pause = false;
    bool enable_stop = false;
    bool enable_timing = true;

    if (ui->streamTreeWidget->topLevelItemCount() < 1)
        enable_play = false;

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
    ui->pauseButton->setEnabled(enable_pause);
    ui->stopButton->setEnabled(enable_stop);
    cur_play_pos_->setVisible(enable_stop);

    ui->jitterSpinBox->setEnabled(enable_timing);
    ui->timingComboBox->setEnabled(enable_timing);
    ui->todCheckBox->setEnabled(enable_timing);

    updateHintLabel();
    ui->audioPlot->replot();
}

void RtpPlayerDialog::graphClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::RightButton) {
        graph_ctx_menu_->exec(event->globalPos());
    }
    ui->audioPlot->setFocus();
}

void RtpPlayerDialog::graphDoubleClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::LeftButton) {
        // Move start play line
        double ts = ui->audioPlot->xAxis->pixelToCoord(ui->audioPlot->mapFromGlobal(QCursor::pos()).x());

        setStartPlayMarker(ts);
        drawStartPlayMarker();

        ui->audioPlot->replot();
    }
    ui->audioPlot->setFocus();
}

void RtpPlayerDialog::plotClicked(QCPAbstractPlottable *plottable, int dataIndex _U_, QMouseEvent *event _U_)
{
    ui->streamTreeWidget->clearSelection();
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        QCPGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<QCPGraph*>();
        if (plottable == audio_graph) {
            ui->streamTreeWidget->setCurrentItem(ti);
        }
    }
}

void RtpPlayerDialog::updateHintLabel()
{
    int packet_num = getHoveredPacket();
    QString hint = "<small><i>";
    double start_pos = getStartPlayMarker();

    if (packet_num == 0) {
        hint += tr("Start: %1. Double click to set start of playback.")
                .arg(getFormatedTime(start_pos));
    } else if (packet_num > 0) {
        hint += tr("Start: %1, cursor: %2. Press \"G\" to go to packet %3. Double click to set start of playback.")
                .arg(getFormatedTime(start_pos))
                .arg(getFormatedHoveredTime())
                .arg(packet_num);
    } else if (!playback_error_.isEmpty()) {
        hint += playback_error_;
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

void RtpPlayerDialog::playFinished(RtpAudioStream *stream)
{
    playing_streams_.removeOne(stream);
    if (playing_streams_.isEmpty()) {
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

tap_packet_status RtpPlayerDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr)
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
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *row_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();

        if (row_stream->isMatch(pinfo, rtpinfo)) {
            row_stream->addRtpPacket(pinfo, rtpinfo);
            return;
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
    wsApp->processEvents();
    ui->pauseButton->setChecked(false);

    // Protect start time against move of marker during the play
    start_marker_time_play_ = start_marker_time_;
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
    format.setSampleRate(8000);
    format.setSampleSize(SAMPLE_BYTES * 8); // bits
    format.setSampleType(QAudioFormat::SignedInt);
    if (stereo_available_) {
        format.setChannelCount(2);
    } else {
        format.setChannelCount(1);
    }
    format.setCodec("audio/pcm");

    o = new QAudioOutput(cur_out_device, format, this);
    o->setNotifyInterval(100); // ~15 fps
    connect(o, SIGNAL(notify()), this, SLOT(outputNotify()));

    return o;
}

void RtpPlayerDialog::outputNotify()
{
    double secs = marker_stream_->processedUSecs() / 1000000.0;
    if (ui->todCheckBox->isChecked()) {
        secs += start_marker_time_play_;
    } else {
        secs += start_marker_time_play_;
        secs -= first_stream_rel_start_time_;
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

// Make waveform graphs selectable and update the treewidget selection accordingly.
void RtpPlayerDialog::on_streamTreeWidget_itemSelectionChanged()
{
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        QCPGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<QCPGraph*>();
        if (audio_graph) {
            audio_graph->setSelection(ti->isSelected() ? QCPDataSelection(QCPDataRange()) : QCPDataSelection());
            QPen p = audio_graph->pen();
            if (ti->isSelected()) {
                p.setWidthF(wf_graph_normal_width_*2);
            } else {
                p.setWidthF(wf_graph_normal_width_);
            }
            audio_graph->setPen(p);
        }
    }
    ui->audioPlot->replot();
    ui->audioPlot->setFocus();
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
}

void RtpPlayerDialog::on_actionRemoveStream_triggered()
{
    QTreeWidgetItem *ti = ui->streamTreeWidget->currentItem();
    if (!ti)
        return;

    RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
    if (audio_stream) {
        ti->setData(stream_data_col_, Qt::UserRole, QVariant());
        delete audio_stream;
    }

    QCPGraph *graph;
    graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_audio_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
        ui->audioPlot->replot();
    }

    graph = ti->data(graph_sequence_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_sequence_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
        ui->audioPlot->replot();
    }

    graph = ti->data(graph_jitter_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_jitter_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
        ui->audioPlot->replot();
    }

    graph = ti->data(graph_timestamp_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_timestamp_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
        ui->audioPlot->replot();
    }

    graph = ti->data(graph_silence_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (graph) {
        ti->setData(graph_silence_data_col_, Qt::UserRole, QVariant());
        ui->audioPlot->removeGraph(graph);
        ui->audioPlot->replot();
    }

    delete ti;

    updateWidgets();
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

    QCPGraph *audio_graph = ti->data(graph_audio_data_col_, Qt::UserRole).value<QCPGraph*>();
    if (audio_graph) {

        audio_graph->setSelection(ti->isSelected() ? QCPDataSelection(QCPDataRange()) : QCPDataSelection());
        QPen p = audio_graph->pen();
        if (audio_routing.isMuted()) {
            // Indicate that audio will not be hearable
            p.setStyle(Qt::DotLine);
        } else {
            p.setStyle(Qt::SolidLine);
        }
        audio_graph->setPen(p);
        ui->audioPlot->replot();
    }
}

// Find current item and apply change on it
void RtpPlayerDialog::changeAudioRouting(AudioRouting new_audio_routing)
{
    QTreeWidgetItem *ti = ui->streamTreeWidget->currentItem();
    changeAudioRoutingOnItem(ti, new_audio_routing);
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

void RtpPlayerDialog::on_actionAudioRoutingM_triggered()
{
    QTreeWidgetItem *ti = ui->streamTreeWidget->currentItem();
    invertAudioMutingOnItem(ti);
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

void RtpPlayerDialog::on_actionAudioRoutingI_triggered()
{
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        invertAudioMutingOnItem(ti);
    }
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
    QTreeWidgetItem *ti = ui->streamTreeWidget->currentItem();
    if (!ti) return tr("Unknown");

    double ts = ui->audioPlot->xAxis->pixelToCoord(ui->audioPlot->mapFromGlobal(QCursor::pos()).x());

    return getFormatedTime(ts);
}

int RtpPlayerDialog::getHoveredPacket()
{
    QTreeWidgetItem *ti = ui->streamTreeWidget->currentItem();
    if (!ti) return 0;

    RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();

    double ts = ui->audioPlot->xAxis->pixelToCoord(ui->audioPlot->mapFromGlobal(QCursor::pos()).x());

    return audio_stream->nearestPacket(ts, !ui->todCheckBox->isChecked());
}

// Used by RtpAudioStreams to initialize QAudioOutput. We could alternatively
// pass the corresponding QAudioDeviceInfo directly.
QString RtpPlayerDialog::currentOutputDeviceName()
{
    return ui->outputDeviceComboBox->currentText();
}

void RtpPlayerDialog::on_outputDeviceComboBox_currentIndexChanged(const QString &)
{
    stereo_available_ = isStereoAvailable();
    for (int row = 0; row < ui->streamTreeWidget->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = ui->streamTreeWidget->topLevelItem(row);
        RtpAudioStream *audio_stream = ti->data(stream_data_col_, Qt::UserRole).value<RtpAudioStream*>();
        if (!audio_stream)
            continue;

        changeAudioRoutingOnItem(ti, audio_stream->getAudioRouting().convert(stereo_available_));
    }
    rescanPackets();
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
    wsApp->helpTopicAction(HELP_TELEPHONY_RTP_PLAYER_DIALOG);
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

void RtpPlayerDialog::updateStartStopTime(rtpstream_info_t *rtpstream, int tli_count)
{
    // Calculate start time of first stream and end time of last stream
    double stream_rel_start_time = nstime_to_sec(&rtpstream->start_rel_time);
    double stream_abs_start_time = nstime_to_sec(&rtpstream->start_abs_time);
    double stream_rel_stop_time = nstime_to_sec(&rtpstream->stop_rel_time);

    if (tli_count == 0) {
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

#if 0
// This also serves as a title in RtpAudioFrame.
static const QString stream_key_tmpl_ = "%1:%2 " UTF8_RIGHTWARDS_ARROW " %3:%4 0x%5";
const QString RtpPlayerDialog::streamKey(const rtpstream_info_t *rtpstream)
{
    const QString stream_key = QString(stream_key_tmpl_)
            .arg(address_to_display_qstring(&rtpstream->src_addr))
            .arg(rtpstream->src_port)
            .arg(address_to_display_qstring(&rtpstream->dst_addr))
            .arg(rtpstream->dst_port)
            .arg(rtpstream->ssrc, 0, 16);
    return stream_key;
}

const QString RtpPlayerDialog::streamKey(const packet_info *pinfo, const struct _rtp_info *rtpinfo)
{
    const QString stream_key = QString(stream_key_tmpl_)
            .arg(address_to_display_qstring(&pinfo->src))
            .arg(pinfo->srcport)
            .arg(address_to_display_qstring(&pinfo->dst))
            .arg(pinfo->destport)
            .arg(rtpinfo->info_sync_src, 0, 16);
    return stream_key;
}
#endif

#endif // QT_MULTIMEDIA_LIB

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
