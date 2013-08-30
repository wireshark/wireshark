/* tcp_stream_dialog.h
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

#ifndef TCP_STREAM_DIALOG_H
#define TCP_STREAM_DIALOG_H

#include "config.h"

#include <glib.h>

#include <file.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/tap-tcp-stream.h"

#include <qcustomplot.h>
#include <QDialog>

namespace Ui {
class TCPStreamDialog;
}

class TCPStreamDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TCPStreamDialog(QWidget *parent = 0, capture_file *cf = NULL, tcp_graph_type graph_type = GRAPH_TSEQ_STEVENS);
    ~TCPStreamDialog();

signals:
    void goToPacket(int packet_num);

protected:
    void keyPressEvent(QKeyEvent *event);

private:
    Ui::TCPStreamDialog *ui;
    capture_file *cap_file_;
    QMap<double, struct segment *> segment_map_;
    struct tcp_graph graph_;
    QRectF data_range_;
    QCPItemTracer *tracer_;
    guint32 packet_num_;


    bool compareHeaders(struct segment *seg);
    void toggleTracerStyle(bool force_default = false);

private slots:
    void graphClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
};

#endif // TCP_STREAM_DIALOG_H

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
