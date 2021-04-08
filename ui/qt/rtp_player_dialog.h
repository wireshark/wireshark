/* rtp_player_dialog.h
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

#include "ui/rtp_stream.h"

#include "wireshark_dialog.h"
#include "rtp_audio_stream.h"

#include <QMap>
#include <QTreeWidgetItem>
#include <QMetaType>
#include <ui/qt/widgets/qcustomplot.h>
#include <QAudioDeviceInfo>

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

class RtpPlayerDialog : public WiresharkDialog
{
    Q_OBJECT
#ifdef QT_MULTIMEDIA_LIB
    Q_PROPERTY(QString currentOutputDeviceName READ currentOutputDeviceName)
#endif

public:
    explicit RtpPlayerDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Common routine to add a "Play call" button to a QDialogButtonBox.
     * @param button_box Caller's QDialogButtonBox.
     * @return The new "Play call" button.
     */
    static QPushButton *addPlayerButton(QDialogButtonBox *button_box, QDialog *dialog);

#ifdef QT_MULTIMEDIA_LIB
    ~RtpPlayerDialog();

    void accept();
    void reject();

    void setMarkers();

    /** Replace/Add/Remove an RTP streams to play.
     * Requires array of rtpstream_info_t.
     * Each item must have filled items: src_addr, src_port, dest_addr,
     *  dest_port, ssrc, packet_count, setup_frame_number, and start_rel_time.
     *
     * @param rtpstream struct with rtpstream info
     */
    void replaceRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void addRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void removeRtpStreams(QVector<rtpstream_info_t *> stream_infos);

signals:
    void goToPacket(int packet_num);

protected:
    virtual void showEvent(QShowEvent *);
    void contextMenuEvent(QContextMenuEvent *event);
    bool eventFilter(QObject *obj, QEvent *event);

private slots:
    /** Retap the capture file, reading RTP packets that match the
     * streams added using ::addRtpStream.
     */
    void retapPackets();
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
    void playFinished(RtpAudioStream *stream);

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
    void on_actionSaveAudioSyncStream_triggered();
    void on_actionSaveAudioSyncFile_triggered();
    void on_actionSavePayload_triggered();

private:
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
    QPushButton *export_btn_;

//    const QString streamKey(const rtpstream_info_t *rtpstream);
//    const QString streamKey(const packet_info *pinfo, const struct _rtp_info *rtpinfo);

    // Tap callbacks
//    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr);
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
    void updateStartStopTime(rtpstream_info_t *rtpstream, int tli_count);
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
    void addSingleRtpStream(rtpstream_info_t *rtpstream);
    void removeRow(QTreeWidgetItem *ti);
    void fillAudioRateMenu();
    void cleanupMarkerStream();

    qint64 saveAudioHeaderAU(QFile *save_file, int channels, unsigned audio_rate);
    qint64 saveAudioHeaderWAV(QFile *save_file, int channels, unsigned audio_rate, qint64 samples);
    bool writeAudioStreamsSamples(QFile *out_file, QVector<RtpAudioStream *> streams, bool swap_bytes);
    save_audio_t selectFileAudioFormatAndName(QString *file_path);
    save_payload_t selectFilePayloadFormatAndName(QString *file_path);
    QVector<RtpAudioStream *>getSelectedAudibleAudioStreams();
    void saveAudio(bool sync_to_stream);
    void savePayload();

#else // QT_MULTIMEDIA_LIB
private:
    Ui::RtpPlayerDialog *ui;
#endif // QT_MULTIMEDIA_LIB
};

#endif // RTP_PLAYER_DIALOG_H
