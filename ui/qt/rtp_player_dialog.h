/* rtp_player_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef RTP_PLAYER_DIALOG_H
#define RTP_PLAYER_DIALOG_H

#include "config.h"

#include <glib.h>

#include "ui/rtp_stream.h"

#include "wireshark_dialog.h"

#include <QMap>

namespace Ui {
class RtpPlayerDialog;
}

struct _rtp_stream_info;

class QCPItemStraightLine;
class QDialogButtonBox;
class QMenu;
class RtpAudioStream;

class RtpPlayerDialog : public WiresharkDialog
{
    Q_OBJECT

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
     * MUST be called before exec().
     * Requires src_addr, src_port, dest_addr, dest_port, ssrc, packet_count,
     * setup_frame_number, and start_rel_time.
     *
     * @param rtp_stream struct with rtp_stream info
     */
    void addRtpStream(struct _rtp_stream_info *rtp_stream);

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
    void mouseMoved(QMouseEvent *);
    void resetXAxis();

    void setPlayPosition(double secs);
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
    void on_jitterSpinBox_valueChanged(double);
    void on_timingComboBox_currentIndexChanged(int);
    void on_todCheckBox_toggled(bool checked);
    void on_buttonBox_helpRequested();

private:
    Ui::RtpPlayerDialog *ui;
    QMenu *ctx_menu_;
    double start_rel_time_;
    QCPItemStraightLine *cur_play_pos_;

//    const QString streamKey(const struct _rtp_stream_info *rtp_stream);
//    const QString streamKey(const packet_info *pinfo, const struct _rtp_info *rtpinfo);

    // Tap callbacks
//    static void tapReset(void *tapinfo_ptr);
    static gboolean tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr);
    static void tapDraw(void *tapinfo_ptr);

    void addPacket(packet_info *pinfo, const struct _rtp_info *rtpinfo);
    void zoomXAxis(bool in);
    void panXAxis(int x_pixels);
    double getLowestTimestamp();
    const QString getHoveredTime();
    int getHoveredPacket();

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
