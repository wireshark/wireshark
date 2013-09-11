/* follow_stream_dialog.h
 *
 * $Id$
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

#include <QDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QPrinter>
#include <QPrintDialog>
#include <QInputDialog>

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "qt_ui_utils.h"

#include <epan/follow.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/charsets.h>
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include <epan/ipproto.h>
#include <epan/charsets.h>
#include <epan/plugins.h>
#include <epan/tap.h>

#include "../file.h"
#include "ui/alert_box.h"
#include "ui/follow.h"
#include "ui/simple_dialog.h"
#include "ui/utf8_entities.h"
#include "wsutil/tempfile.h"
#include <wsutil/file_util.h>
#include "ws_symbol_export.h"


#include "globals.h"
#include "file.h"

#include "version_info.h"


#include <QtGui>

extern "C" {
WS_DLL_PUBLIC FILE *data_out_file;
}

typedef struct {
    follow_type_t   follow_type;
    show_stream_t   show_stream;
    show_type_t     show_type;
    char            *data_out_filename;
    gboolean        is_ipv6;
    char            *filter_out_filter;
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
    explicit FollowStreamDialog(QWidget *parent = 0);
    ~FollowStreamDialog();

    bool Follow(QString previous_filter_, follow_type_t type);

    frs_return_t
    follow_show(char *buffer, size_t nchars, gboolean is_from_server,
            guint32 *global_pos, guint32 *server_packet_count,
            guint32 *client_packet_count);

    frs_return_t
    follow_read_stream();

    frs_return_t
    follow_read_tcp_stream();

    frs_return_t
    follow_read_udp_stream();

    frs_return_t
    follow_read_ssl_stream();

    void
    follow_stream();

    void add_text(char *buffer, size_t nchars, gboolean is_from_server);

private slots:
    void on_cbCharset_currentIndexChanged(int index);
    void on_cbDirections_currentIndexChanged(int index);
    void HelpButton();
    void FilterOut();
    void FindText();
    void SaveAs();
    void Print();
//    void on_bNext_clicked();
//    void on_bPrevious_clicked();

signals:
    void updateFilter(QString &filter, bool force);

private:
    Ui::FollowStreamDialog  *ui;

    QPushButton             *bFilterOut;
    QPushButton             *bFind;
    QPushButton             *bPrint;
    QPushButton             *bSave;

    follow_info_t           *follow_info;

    bool                    save_as;
    QFile                   file;
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
