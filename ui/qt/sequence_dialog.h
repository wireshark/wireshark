/* sequence_dialog.h
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

#ifndef SEQUENCE_DIALOG_H
#define SEQUENCE_DIALOG_H

#include "config.h"

#include <glib.h>

#include "cfile.h"

#include "epan/packet.h"

#include "sequence_diagram.h"

#include <QDialog>

namespace Ui {
class SequenceDialog;
}

class SequenceDialog : public QDialog
{
    Q_OBJECT
    
public:
    enum SequenceType { any, tcp, voip };

    explicit SequenceDialog(QWidget *parent = 0, capture_file *cf = NULL, SequenceType type = any);
    ~SequenceDialog();
    
signals:
    void goToPacket(int packet_num);

public slots:
    void setCaptureFile(capture_file *cf);

protected:
    void showEvent(QShowEvent *event);
    void resizeEvent(QResizeEvent *event);

private slots:
    void on_resetButton_clicked();

private:
    Ui::SequenceDialog *ui;
    SequenceDiagram *seq_diagram_;
    capture_file *cap_file_;
    seq_analysis_info_t seq_analysis_;
    double one_em_;

    void fillDiagram();
    void resetAxes(bool keep_lower = false);

};

#endif // SEQUENCE_DIALOG_H
