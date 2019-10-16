/* sctp_graph_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_GRAPH_DIALOG_H
#define SCTP_GRAPH_DIALOG_H

#include <config.h>
#include <glib.h>

#include "cfile.h"

#include <QDialog>

namespace Ui {
class SCTPGraphDialog;
}

class QCPAbstractPlottable;
class QCustomPlot;

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
    explicit SCTPGraphDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL,
            capture_file *cf = NULL, int dir = 0);
    ~SCTPGraphDialog();
    static void save_graph(QDialog *dlg, QCustomPlot *plot);

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_4_clicked();

    void graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event);

    void on_saveButton_clicked();

    void on_relativeTsn_stateChanged(int arg1);

private:
    Ui::SCTPGraphDialog *ui;
    guint16 selected_assoc_id;
    capture_file *cap_file_;
    int frame_num;
    int direction;
    QVector<double> xt, yt, xs, ys, xg, yg, xd, yd, xn, yn;
    QVector<guint32> ft, fs, fg, fd, fn;
    QVector<QString> typeStrings;
    bool relative;
    int type;

    void drawGraph(const _sctp_assoc_info* selected_assoc = NULL);
    void drawTSNGraph(const _sctp_assoc_info* selected_assoc);
    void drawSACKGraph(const _sctp_assoc_info* selected_assoc);
    void drawNRSACKGraph(const _sctp_assoc_info* selected_assoc);
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
