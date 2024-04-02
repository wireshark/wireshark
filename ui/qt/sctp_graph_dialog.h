/** @file
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

#include "cfile.h"

#include <QDialog>

namespace Ui {
class SCTPGraphDialog;
}

class QCPAbstractPlottable;
class QCustomPlot;

struct _sctp_assoc_info;

struct chunk_header {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

struct data_chunk_header {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t tsn;
    uint16_t sid;
    uint16_t ssn;
    uint32_t ppi;
};

struct gaps {
    uint16_t start;
    uint16_t end;
};

struct sack_chunk_header {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t cum_tsn_ack;
    uint32_t a_rwnd;
    uint16_t nr_of_gaps;
    uint16_t nr_of_dups;
    struct gaps gaps[1];
};

struct nr_sack_chunk_header {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint32_t cum_tsn_ack;
    uint32_t a_rwnd;
    uint16_t nr_of_gaps;
    uint16_t nr_of_nr_gaps;
    uint16_t nr_of_dups;
    uint16_t reserved;
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

    void graphClicked(QCPAbstractPlottable* plottable, int, QMouseEvent* event);

    void on_saveButton_clicked();

    void on_relativeTsn_stateChanged(int arg1);

private:
    Ui::SCTPGraphDialog *ui;
    uint16_t selected_assoc_id;
    capture_file *cap_file_;
    int frame_num;
    int direction;
    QVector<double> xt, yt, xs, ys, xg, yg, xd, yd, xn, yn;
    QVector<uint32_t> ft, fs, fg, fd, fn;
    QVector<QString> typeStrings;
    bool relative;
    int type;

    void drawGraph(const _sctp_assoc_info* selected_assoc = NULL);
    void drawTSNGraph(const _sctp_assoc_info* selected_assoc);
    void drawSACKGraph(const _sctp_assoc_info* selected_assoc);
    void drawNRSACKGraph(const _sctp_assoc_info* selected_assoc);
};

#endif // SCTP_GRAPH_DIALOG_H
