/* sctp_graph_arwn_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SCTP_GRAPH_ARWND_DIALOG_H
#define SCTP_GRAPH_ARWND_DIALOG_H

#include <config.h>
#include <glib.h>

#include "cfile.h"

#include <QDialog>

namespace Ui {
class SCTPGraphArwndDialog;
}

class QCPAbstractPlottable;

struct _sctp_assoc_info;

class SCTPGraphArwndDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCTPGraphArwndDialog(QWidget *parent = 0, const _sctp_assoc_info *assoc = NULL,
            capture_file *cf = NULL, int dir = 0);
    ~SCTPGraphArwndDialog();

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

private slots:
    void on_pushButton_4_clicked();

    void graphClicked(QCPAbstractPlottable* plottable, QMouseEvent* event);

    void on_saveButton_clicked();

private:
    Ui::SCTPGraphArwndDialog *ui;
    guint16 selected_assoc_id;
    capture_file *cap_file_;
    int frame_num;
    int direction;
    guint32 startArwnd;
    QVector<double> xa, ya;
    QVector<guint32> fa;
 //   QVector<QString> typeStrings;

    void drawGraph(const _sctp_assoc_info *selected_assoc);
    void drawArwndGraph(const _sctp_assoc_info *selected_assoc);
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
