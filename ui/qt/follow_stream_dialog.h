/* follow_stream_dialog.h
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

#ifndef FOLLOW_STREAM_DIALOG_H
#define FOLLOW_STREAM_DIALOG_H

#include "config.h"

#include <glib.h>

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "file.h"

#include "ui/follow.h"

#include <QDialog>
#include <QFile>
#include <QMap>
#include <QPushButton>

extern "C" {
WS_DLL_PUBLIC FILE *data_out_file;
}

// Shouldn't these be member variables?
typedef struct {
    show_stream_t   show_stream;
    show_type_t     show_type;
    gboolean        is_ipv6;
    GList           *payload;
    guint           bytes_written[2]; /* Index with FROM_CLIENT or FROM_SERVER for readability. */
    guint           client_port;
    address         client_ip;
} follow_info_t;

namespace Ui {
class FollowStreamDialog;
}

class FollowStreamDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FollowStreamDialog(QWidget *parent = 0, follow_type_t type = FOLLOW_TCP, capture_file *cf = NULL);
    ~FollowStreamDialog();

    bool follow(QString previous_filter = QString(), bool use_tcp_index = false);

public slots:
    void setCaptureFile(capture_file *cf);

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);

private slots:
    void on_cbCharset_currentIndexChanged(int index);
    void on_cbDirections_currentIndexChanged(int index);
    void on_bFind_clicked();
    void on_leFind_returnPressed();

    void helpButton();
    void filterOut();
    void findText(bool go_back = true);
    void saveAs();
    void printStream();
    void fillHintLabel(int text_pos);
    void goToPacketForTextPos(int text_pos);

    void on_streamNumberSpinBox_valueChanged(int stream_num);

    void on_buttonBox_rejected();

signals:
    void updateFilter(QString &filter, bool force);
    void goToPacket(int packet_num);

private:
    void removeStreamControls();
    void resetStream(void);
    frs_return_t
    follow_show(char *buffer, size_t nchars, gboolean is_from_server,
                guint32 packet_num, guint32 *global_pos);

    frs_return_t follow_read_stream();
    frs_return_t follow_read_tcp_stream();
    frs_return_t follow_read_udp_stream();
    frs_return_t follow_read_ssl_stream();

    void follow_stream();

    void add_text(QString text, gboolean is_from_server, guint32 packet_num);

    Ui::FollowStreamDialog  *ui;

    capture_file            *cap_file_;
    QPushButton             *b_filter_out_;
    QPushButton             *b_find_;
    QPushButton             *b_print_;
    QPushButton             *b_save_;

    follow_type_t           follow_type_;
    follow_info_t           follow_info_;
    QString                 data_out_filename_;
    QString                 filter_out_filter_;
    int                     client_buffer_count_;
    int                     server_buffer_count_;
    int                     client_packet_count_;
    int                     server_packet_count_;
    guint32                 last_packet_;
    gboolean                last_from_server_;
    int                     turns_;
    QMap<int,guint32>       text_pos_to_packet_;

    bool                    save_as_;
    QFile                   file_;
};

#endif // FOLLOW_STREAM_DIALOG_H

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
