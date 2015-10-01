/* rtp_stream_dialog.h
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

#ifndef RTP_STREAM_DIALOG_H
#define RTP_STREAM_DIALOG_H

#include "wireshark_dialog.h"

#include "ui/rtp_stream.h"

#include <QAbstractButton>
#include <QMenu>

namespace Ui {
class RtpStreamDialog;
}

class RtpStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit RtpStreamDialog(QWidget &parent, CaptureFile &cf);
    ~RtpStreamDialog();

signals:
    // Tells the packet list to redraw. An alternative might be to add a
    // cf_packet_marked callback to file.[ch] but that's synchronous and
    // might incur too much overhead.
    void packetsMarked();
    void updateFilter(QString filter, bool force = false);
    void goToPacket(int packet_num);

protected:
    bool eventFilter(QObject *obj, QEvent *event);

private:
    Ui::RtpStreamDialog *ui;
    rtpstream_tapinfo_t tapinfo_;
    QPushButton *find_reverse_button_;
    QPushButton *prepare_button_;
    QPushButton *export_button_;
    QPushButton *copy_button_;
    QPushButton *analyze_button_;
    QMenu ctx_menu_;
    bool need_redraw_;

    static void tapReset(rtpstream_tapinfo_t *tapinfo);
    static void tapDraw(rtpstream_tapinfo_t *tapinfo);
    static void tapMarkPacket(rtpstream_tapinfo_t *tapinfo, frame_data *fd);

    void updateStreams();
    void updateWidgets();

    QList<QVariant> streamRowData(int row) const;


private slots:
    void captureFileClosing();
    void showStreamMenu(QPoint pos);
    void on_actionCopyAsCsv_triggered();
    void on_actionCopyAsYaml_triggered();
    void on_actionFindReverse_triggered();
    void on_actionGoToSetup_triggered();
    void on_actionMarkPackets_triggered();
    void on_actionPrepareFilter_triggered();
    void on_actionSelectNone_triggered();
    void on_streamTreeWidget_itemSelectionChanged();
    void on_buttonBox_helpRequested();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_actionExportAsRtpDump_triggered();
    void on_actionAnalyze_triggered();
};

#endif // RTP_STREAM_DIALOG_H

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
