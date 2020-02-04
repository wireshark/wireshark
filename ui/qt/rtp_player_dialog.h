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

#include <QMap>
#include <QTreeWidgetItem>

namespace Ui {
class RtpPlayerDialog;
}

typedef enum {
    channel_none,         // Mute
    channel_mono,         // Play
    channel_stereo_left,  // L
    channel_stereo_right, // R
    channel_stereo_both   // L+R
} channel_mode_t;

class QCPItemStraightLine;
class QDialogButtonBox;
class QMenu;
class RtpAudioStream;
class QCPAxisTicker;
class QCPAxisTickerDateTime;

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
    // XXX We might want to move this to qt_ui_utils.
    static QPushButton *addPlayerButton(QDialogButtonBox *button_box);

#ifdef QT_MULTIMEDIA_LIB
    ~RtpPlayerDialog();

    void accept();
    void reject();

    /** Add an RTP stream to play.
     * MUST be called before show().
     * Requires src_addr, src_port, dest_addr, dest_port, ssrc, packet_count,
     * setup_frame_number, and start_rel_time.
     *
     * @param rtpstream struct with rtpstream info
     */
    void addRtpStream(rtpstream_info_t *rtpstream);
    void setMarkers();

public slots:

signals:
    void goToPacket(int packet_num);

protected:
    virtual void showEvent(QShowEvent *);
    virtual void keyPressEvent(QKeyEvent *event);

private slots:
    /** Retap the capture file, adding RTP packets that match the
     * streams added using ::addRtpStream.
     */
    void retapPackets();
    /** Clear, decode, and redraw each stream.
     */
    void rescanPackets(bool rescale_axes = false);
    void updateWidgets();
    void graphClicked(QMouseEvent *event);
    void graphDoubleClicked(QMouseEvent *event);
    void updateHintLabel();
    void resetXAxis();

    void setPlayPosition(double secs);
    void setPlaybackError(const QString playback_error) {
        playback_error_ = playback_error;
        updateHintLabel();
    }
    void on_playButton_clicked();
    void on_stopButton_clicked();
    void on_actionReset_triggered();
    void on_actionZoomIn_triggered();
    void on_actionZoomOut_triggered();
    void on_actionMoveLeft10_triggered();
    void on_actionMoveRight10_triggered();
    void on_actionMoveLeft1_triggered();
    void on_actionMoveRight1_triggered();
    void on_actionGoToPacket_triggered();
    void on_streamTreeWidget_itemSelectionChanged();
    void on_streamTreeWidget_itemDoubleClicked(QTreeWidgetItem *item, const int column);
    void on_outputDeviceComboBox_currentIndexChanged(const QString &);
    void on_jitterSpinBox_valueChanged(double);
    void on_timingComboBox_currentIndexChanged(int);
    void on_todCheckBox_toggled(bool checked);
    void on_buttonBox_helpRequested();

private:
    Ui::RtpPlayerDialog *ui;
    QMenu *ctx_menu_;
    double first_stream_rel_start_time_;  // Relative start time of first stream
    double first_stream_abs_start_time_;  // Absolute start time of first stream
    double first_stream_rel_stop_time_;  // Relative end time of first stream (ued for streams_length_ calculation
    double streams_length_;  // Difference between start of first stream and end of last stream
    double start_marker_time_;    // Always relative time to start of the capture
    QCPItemStraightLine *cur_play_pos_;
    QCPItemStraightLine *start_marker_pos_;
    QString playback_error_;
    QSharedPointer<QCPAxisTicker> number_ticker_;
    QSharedPointer<QCPAxisTickerDateTime> datetime_ticker_;
    bool stereo_available_;

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
    void setChannelMode(QTreeWidgetItem *ti, channel_mode_t channel_mode);
    channel_mode_t changeChannelMode(channel_mode_t channel_mode);
    bool isStereoAvailable();

#else // QT_MULTIMEDIA_LIB
private:
    Ui::RtpPlayerDialog *ui;
#endif // QT_MULTIMEDIA_LIB
};

#endif // RTP_PLAYER_DIALOG_H

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
