/* print_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PRINT_DIALOG_H
#define PRINT_DIALOG_H

#include <config.h>

#include <glib.h>

#include "file.h"

#include <QDialog>
#include <QPrinter>
#include <QPrintPreviewWidget>
#include <QPushButton>

namespace Ui {
    class PrintDialog;
}

class PrintDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PrintDialog(QWidget *parent = 0, capture_file *cf = NULL, QString selRange = QString());
    ~PrintDialog();

    gboolean printHeader();
    gboolean printLine(int indent, const char *line);

protected:
    virtual void keyPressEvent(QKeyEvent *event) override;

private:
    Ui::PrintDialog *pd_ui_;

    QPrinter printer_;
    QPrinter *cur_printer_;
    QPainter *cur_painter_;
    QPrintPreviewWidget *preview_;
    QPushButton *print_bt_;
    QFont header_font_;
    QFont packet_font_;
public:
    capture_file *cap_file_;
private:
    print_args_t print_args_;
    print_stream_ops_t stream_ops_;
    print_stream_t stream_;
    int page_pos_;
    bool in_preview_;

    void printPackets(QPrinter *printer = NULL, bool in_preview = false);

private slots:
    void paintPreview(QPrinter *printer);
    void checkValidity();
    void on_buttonBox_helpRequested();
    void on_buttonBox_clicked(QAbstractButton *button);
};


#endif // PRINT_DIALOG_H

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
