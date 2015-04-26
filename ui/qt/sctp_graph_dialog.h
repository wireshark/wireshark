/* sctp_graph_dialog.h
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

#ifndef SCTP_GRAPH_DIALOG_H
#define SCTP_GRAPH_DIALOG_H

#include <config.h>
#include <glib.h>

#include <QDialog>

namespace Ui {
class SCTPGraphDialog;
}

class QCPAbstractPlottable;
class QCustomPlot;

struct _capture_file;
struct _sctp_assoc_info;

struct chunk_header {
    guint8  type;
    guint8  flags;
    guint16 length;
};

struct data_chunk_header {
    guint8  type;
    guint8  flags;
    guint16 length;
    guint32 tsn;
    guint16 sid;
    guint16 ssn;
    guint32 ppi;
};

struct gaps {
    guint16 start;
    guint16 end;
};

struct sack_chunk_header {
    guint8  type;
    guint8  flags;
    guint16 length;
    guint32 cum_tsn_ack;
    guint32 a_rwnd;
    guint16 nr_of_gaps;
    guint16 nr_of_dups;
    struct gaps gaps[1];
};

struct nr_sack_chunk_header {
    guint8  type;
    guint8  flags;
    guint16 length;
    guint32 cum_tsn_ack;
    guint32 a_rwnd;
    guint16 nr_of_gaps;
    guint16 nr_of_nr_gaps;
    guint16 nr_of_dups;
    guint16 reserved;
    struct gaps gaps[1];
};


class SCTPGraphDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPGraphDialog(QWidget *parent = 0, struct _sctp_assoc_info *assoc = NULL, struct _capture_file *cf = NULL, int dir = 0);
    ~SCTPGraphDialog();
    static void save_graph(QDialog *dlg, QCustomPlot *plot);

public slots:
    void setCaptureFile(struct _capture_file *cf) { cap_file_ = cf; }

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_4_clicked();

    void graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event);

    void on_saveButton_clicked();

private:
    Ui::SCTPGraphDialog *ui;
    struct _sctp_assoc_info *selected_assoc;
    struct _capture_file *cap_file_;
    int frame_num;
    int direction;
    QVector<double> xt, yt, xs, ys, xg, yg, xd, yd, xn, yn;
    QVector<guint32> ft, fs, fg, fd, fn;
    QVector<QString> typeStrings;
    bool gIsSackChunkPresent;
    bool gIsNRSackChunkPresent;

    void drawGraph(int which);
    void drawTSNGraph();
    void drawSACKGraph();
    void drawNRSACKGraph();
};

#endif // SCTP_GRAPH_DIALOG_H

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
