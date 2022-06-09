/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_PLAYER_DIALOG_H
#define RTP_PLAYER_DIALOG_H

#include "config.h"

#include <glib.h>
#include <mutex>

#include "ui/rtp_stream.h"

#include "wireshark_dialog.h"
#include "rtp_audio_stream.h"

#include <QWidget>
#include <QMap>
#include <QMultiHash>
#include <QTreeWidgetItem>
#include <QMetaType>
#include <ui/qt/widgets/qcustomplot.h>

#ifdef QT_MULTIMEDIA_LIB
#include <QAudioDeviceInfo>
#endif

namespace Ui {
class RtpPlayerDialog;
}

class QCPItemStraightLine;
class QDialogButtonBox;
class QMenu;
class RtpAudioStream;
class QCPAxisTicker;
class QCPAxisTickerDateTime;

typedef enum {
    save_audio_none,
    save_audio_au,
    save_audio_wav
} save_audio_t;

typedef enum {
    save_payload_none,
    save_payload_data
} save_payload_t;

typedef enum {
    save_mode_from_cursor,
    save_mode_sync_stream,
    save_mode_sync_file
} save_mode_t;

// Singleton by https://refactoring.guru/design-patterns/singleton/cpp/example#example-1
class RtpPlayerDialog : public WiresharkDialog
{
    Q_OBJECT
#ifdef QT_MULTIMEDIA_LIB
    Q_PROPERTY(QString currentOutputDeviceName READ currentOutputDeviceName)
#endif

public:
    /**
     * Returns singleton
     */
    static RtpPlayerDialog *openRtpPlayerDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list, bool capture_running);

    /**
     * Should not be clonnable and assignable
     */
    RtpPlayerDialog(RtpPlayerDialog &other) = delete;
    void operator=(const RtpPlayerDialog &) = delete;

    /**
     * @brief Common routine to add a "Play call" button to a QDialogButtonBox.
     * @param button_box Caller's QDialogButtonBox.
     * @return The new "Play call" button.
     */
    static QToolButton *addPlayerButton(QDialogButtonBox *button_box, QDialog *dialog);

#ifdef QT_MULTIMEDIA_LIB
    void accept();
    void reject();

    void setMarkers();

    /** Replace/Add/Remove an RTP streams to play.
     * Requires array of rtpstream_info_t.
     * Each item must have filled items: src_addr, src_port, dest_addr,
     *  dest_port, ssrc, packet_count, setup_frame_number, and start_rel_time.
     *
     * @param stream_ids struct with rtpstream info
     */
    void replaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void addRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void removeRtpStreams(QVector<rtpstream_id_t *> stream_ids);

signals:
    // Tells the packet list to redraw. An alternative might be to add a
    // cf_packet_marked callback to file.[ch] but that's synchronous and
    // might incur too much overhead.
    void packetsMarked();
    void updateFilter(QString filter, bool force = false);
    void goToPacket(int packet_num);
    void rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_infos);
    void rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_infos);
    void rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_infos);

public slots:
    void rtpAnalysisReplace();
    void rtpAnalysisAdd();
    void rtpAnalysisRemove();

#endif
protected:
    explicit RtpPlayerDialog(QWidget &parent, CaptureFile &cf, bool capture_running);
#ifdef QT_MULTIMEDIA_LIB
    ~RtpPlayerDialog();

    virtual void showEvent(QShowEvent *);
    void contextMenuEvent(QContextMenuEvent *event);
    bool eventFilter(QObject *obj, QEvent *event);

private slots:
    /** Retap the capture file, reading RTP packets that match the
     * streams added using ::addRtpStream.
     */
    void retapPackets();
    void captureEvent(CaptureEvent e);
    /** Clear, decode, and redraw each stream.
     */
    void rescanPackets(bool rescale_axes = false);
    void createPlot(bool rescale_axes = false);
    void updateWidgets();
    void itemEntered(QTreeWidgetItem *item, int column);
    void mouseMovePlot(QMouseEvent *event);
    void graphClicked(QMouseEvent *event);
    void graphDoubleClicked(QMouseEvent *event);
    void plotClicked(QCPAbstractPlottable *plottable, int dataIndex, QMouseEvent *event);
    void updateHintLabel();
    void resetXAxis();
    void updateGraphs();
    void playFinished(RtpAudioStream *stream, QAudio::Error error);

    void setPlayPosition(double secs);
    void setPlaybackError(const QString playback_error);
    void changeAudioRoutingOnItem(QTreeWidgetItem *ti, AudioRouting new_audio_routing);
    void changeAudioRouting(AudioRouting new_audio_routing);
    void invertAudioMutingOnItem(QTreeWidgetItem *ti);
    void on_playButton_clicked();
    void on_pauseButton_clicked();
    void on_stopButton_clicked();
    void on_actionReset_triggered();
    void on_actionZoomIn_triggered();
    void on_actionZoomOut_triggered();
    void on_actionMoveLeft10_triggered();
    void on_actionMoveRight10_triggered();
    void on_actionMoveLeft1_triggered();
    void on_actionMoveRight1_triggered();
    void on_actionGoToPacket_triggered();
    void on_actionGoToSetupPacketPlot_triggered();
    void on_actionGoToSetupPacketTree_triggered();
    void on_actionRemoveStream_triggered();
    void on_actionAudioRoutingP_triggered();
    void on_actionAudioRoutingL_triggered();
    void on_actionAudioRoutingLR_triggered();
    void on_actionAudioRoutingR_triggered();
    void on_actionAudioRoutingMute_triggered();
    void on_actionAudioRoutingUnmute_triggered();
    void on_actionAudioRoutingMuteInvert_triggered();
    void on_streamTreeWidget_itemSelectionChanged();
    void on_streamTreeWidget_itemDoubleClicked(QTreeWidgetItem *item, const int column);
    void on_outputDeviceComboBox_currentIndexChanged(const QString &);
    void on_outputAudioRate_currentIndexChanged(const QString &);
    void on_jitterSpinBox_valueChanged(double);
    void on_timingComboBox_currentIndexChanged(int);
    void on_todCheckBox_toggled(bool checked);
    void on_buttonBox_helpRequested();
    void on_actionSelectAll_triggered();
    void on_actionSelectInvert_triggered();
    void on_actionSelectNone_triggered();
    void outputNotify();
    void on_actionPlay_triggered();
    void on_actionStop_triggered();
    void on_actionSaveAudioFromCursor_triggered();
    void on_actionSaveAudioSyncStream_triggered();
    void on_actionSaveAudioSyncFile_triggered();
    void on_actionSavePayload_triggered();
    void on_actionSelectInaudible_triggered();
    void on_actionDeselectInaudible_triggered();
    void on_actionPrepareFilter_triggered();
    void on_actionReadCapture_triggered();

#endif
private:
    static RtpPlayerDialog *pinstance_;
    static std::mutex init_mutex_;
    static std::mutex run_mutex_;

#ifdef QT_MULTIMEDIA_LIB
    Ui::RtpPlayerDialog *ui;
    QMenu *graph_ctx_menu_;
    QMenu *list_ctx_menu_;
    double first_stream_rel_start_time_;  // Relative start time of first stream
    double first_stream_abs_start_time_;  // Absolute start time of first stream
    double first_stream_rel_stop_time_;  // Relative end time of first stream (ued for streams_length_ calculation
    double streams_length_;  // Difference between start of first stream and end of last stream
    double start_marker_time_;    // Always relative time to start of the capture
    double start_marker_time_play_;    // Copy when play started
    QCPItemStraightLine *cur_play_pos_;
    QCPItemStraightLine *start_marker_pos_;
    QString playback_error_;
    QSharedPointer<QCPAxisTicker> number_ticker_;
    QSharedPointer<QCPAxisTickerDateTime> datetime_ticker_;
    bool stereo_available_;
    QList<RtpAudioStream *> playing_streams_;
    QAudioOutput *marker_stream_;
    quint32 marker_stream_requested_out_rate_;
    QTreeWidgetItem *last_ti_;
    bool listener_removed_;
    QPushButton *read_btn_;
    QToolButton *inaudible_btn_;
    QToolButton *analyze_btn_;
    QPushButton *prepare_btn_;
    QPushButton *export_btn_;
    QMultiHash<guint, RtpAudioStream *> stream_hash_;
    bool block_redraw_;
    int lock_ui_;
    bool read_capture_enabled_;
    double silence_skipped_time_;

//    const QString streamKey(const rtpstream_info_t *rtpstream);
//    const QString streamKey(const packet_info *pinfo, const struct _rtp_info *rtpinfo);

    // Tap callbacks
//    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr, tap_flags_t flags);
    static void tapDraw(void *tapinfo_ptr);

    void addPacket(packet_info *pinfo, const struct _rtp_info *rtpinfo);
    void zoomXAxis(bool in);
    void panXAxis(int x_pixels);
    const QString getFormatedTime(double f_time);
    const QString getFormatedHoveredTime();
    int getHoveredPacket();
    QString currentOutputDeviceName();
    double getStartPlayMarker();
    void drawStartPlayMarker();
    void setStartPlayMarker(double new_time);
    void updateStartStopTime(rtpstream_info_t *rtpstream, bool is_first);
    void formatAudioRouting(QTreeWidgetItem *ti, AudioRouting audio_routing);
    bool isStereoAvailable();
    QAudioOutput *getSilenceAudioOutput();
    QAudioDeviceInfo getCurrentDeviceInfo();
    QTreeWidgetItem *findItemByCoords(QPoint point);
    QTreeWidgetItem *findItem(QCPAbstractPlottable *plottable);
    void handleItemHighlight(QTreeWidgetItem *ti, bool scroll);
    void highlightItem(QTreeWidgetItem *ti, bool highlight);
    void invertSelection();
    void handleGoToSetupPacket(QTreeWidgetItem *ti);
    void addSingleRtpStream(rtpstream_id_t *id);
    void removeRow(QTreeWidgetItem *ti);
    void fillAudioRateMenu();
    void cleanupMarkerStream();

    qint64 saveAudioHeaderAU(QFile *save_file, int channels, unsigned audio_rate);
    qint64 saveAudioHeaderWAV(QFile *save_file, int channels, unsigned audio_rate, qint64 samples);
    bool writeAudioSilenceSamples(QFile *out_file, qint64 samples, int stream_count);
    bool writeAudioStreamsSamples(QFile *out_file, QVector<RtpAudioStream *> streams, bool swap_bytes);
    save_audio_t selectFileAudioFormatAndName(QString *file_path);
    save_payload_t selectFilePayloadFormatAndName(QString *file_path);
    QVector<RtpAudioStream *>getSelectedAudibleNonmutedAudioStreams();
    void saveAudio(save_mode_t save_mode);
    void savePayload();
    void lockUI();
    void unlockUI();
    void selectInaudible(bool select);
    QVector<rtpstream_id_t *>getSelectedRtpStreamIDs();
    void fillTappedColumns();

#else // QT_MULTIMEDIA_LIB
private:
    Ui::RtpPlayerDialog *ui;
#endif // QT_MULTIMEDIA_LIB
};

#endif // RTP_PLAYER_DIALOG_H
