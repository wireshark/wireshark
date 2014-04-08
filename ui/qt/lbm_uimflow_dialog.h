/* lbm_uimflow_dialog.h
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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

#ifndef LBM_UIMFLOW_DIALOG_H
#define LBM_UIMFLOW_DIALOG_H

#include "config.h"

#include <glib.h>

#include "cfile.h"

#include "epan/packet.h"

#include "sequence_diagram.h"

#include <QDialog>
#include <QMenu>

namespace Ui
{
    class LBMUIMFlowDialog;
}

class LBMUIMFlowDialog : public QDialog
{
        Q_OBJECT

    public:
        explicit LBMUIMFlowDialog(QWidget * parent = 0, capture_file * cfile = NULL);
        ~LBMUIMFlowDialog(void);

    signals:
        void goToPacket(int packet_number);

    public slots:
        void setCaptureFile(capture_file * CaptureFile);

    protected:
        void showEvent(QShowEvent * event);
        void resizeEvent(QResizeEvent * event);
        void keyPressEvent(QKeyEvent * event);
        void mouseReleaseEvent(QMouseEvent * event);

    private slots:
        void hScrollBarChanged(int value);
        void vScrollBarChanged(int value);
        void xAxisChanged(QCPRange range);
        void yAxisChanged(QCPRange range);
        void diagramClicked(QMouseEvent * event);
        void mouseMoved(QMouseEvent * event);
        void mouseReleased(QMouseEvent * event);

        void on_buttonBox_accepted(void);
        void on_resetButton_clicked(void);
        void on_actionGoToPacket_triggered(void);
        void on_showComboBox_currentIndexChanged(int index);
        void on_actionReset_triggered(void);
        void on_actionMoveRight10_triggered(void);
        void on_actionMoveLeft10_triggered(void);
        void on_actionMoveUp10_triggered(void);
        void on_actionMoveDown10_triggered(void);
        void on_actionMoveRight1_triggered(void);
        void on_actionMoveLeft1_triggered(void);
        void on_actionMoveUp1_triggered(void);
        void on_actionMoveDown1_triggered(void);

    private:
        Ui::LBMUIMFlowDialog * m_ui;
        SequenceDiagram * m_sequence_diagram;
        capture_file * m_capture_file;
        seq_analysis_info_t m_sequence_analysis;
        int m_num_items;
        guint32 m_packet_num;
        double m_one_em;
        int m_node_label_width;
        QMenu m_context_menu;

        void fillDiagram(void);
        void panAxes(int x_pixels, int y_pixels);
        void resetAxes(bool keep_lower = false);
};

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
