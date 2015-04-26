/* print_dialog.h
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
    explicit PrintDialog(QWidget *parent = 0, capture_file *cf = NULL);
    ~PrintDialog();
    gboolean printHeader();
    gboolean printLine(int indent, const char *line);

protected:
    void keyPressEvent(QKeyEvent *event);

private:
    void printPackets(QPrinter *printer = NULL, bool in_preview = false);

    Ui::PrintDialog *pd_ui_;

    QPrinter printer_;
    QPrinter *cur_printer_;
    QPainter *cur_painter_;
    QPrintPreviewWidget *preview_;
    QPushButton *print_bt_;
    QFont header_font_;
    QFont packet_font_;
    capture_file *cap_file_;
    print_args_t print_args_;
    print_stream_ops_t stream_ops_;
    print_stream_t stream_;
    int page_pos_;
    bool in_preview_;

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
