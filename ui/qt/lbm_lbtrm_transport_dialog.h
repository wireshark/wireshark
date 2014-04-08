/* lbm_lbtrm_transport_dialog.h
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

#ifndef LBM_LBTRM_TRANSPORT_DIALOG_H
#define LBM_LBTRM_TRANSPORT_DIALOG_H

#include "config.h"

#include <glib.h>

#include "cfile.h"
#include <epan/packet_info.h>
#include <QDialog>
#include <QTreeWidgetItem>

namespace Ui
{
    class LBMLBTRMTransportDialog;
}

class LBMLBTRMTransportDialogInfo;
class LBMLBTRMSourceTransportEntry;
class LBMLBTRMReceiverTransportEntry;

class LBMLBTRMTransportDialog : public QDialog
{
        Q_OBJECT

    public:
        explicit LBMLBTRMTransportDialog(QWidget * parent = 0, capture_file * cfile = NULL);
        Ui::LBMLBTRMTransportDialog * getUI(void)
        {
            return (m_ui);
        }
    public slots:
        void setCaptureFile(capture_file * cfile);

    signals:
        void goToPacket(int PacketNum);

    private:
        Ui::LBMLBTRMTransportDialog * m_ui;
        LBMLBTRMTransportDialogInfo * m_dialog_info;
        capture_file * m_capture_file;
        LBMLBTRMSourceTransportEntry * m_current_source_transport;
        LBMLBTRMReceiverTransportEntry * m_current_receiver_transport;
        QMenu * m_source_context_menu;
        QHeaderView * m_source_header;

        virtual ~LBMLBTRMTransportDialog(void);
        void resetSources(void);
        void resetReceivers(void);
        void resetSourcesDetail(void);
        void resetReceiversDetail(void);
        void fillTree(void);
        static void resetTap(void * tap_data);
        static gboolean tapPacket(void * tap_data, packet_info * pinfo, epan_dissect_t * edt, const void * stream_info);
        static void drawTreeItems(void * tap_data);
        void loadSourceDataDetails(LBMLBTRMSourceTransportEntry * transport);
        void loadSourceRXDataDetails(LBMLBTRMSourceTransportEntry * transport);
        void loadSourceNCFDetails(LBMLBTRMSourceTransportEntry * transport);
        void loadSourceSMDetails(LBMLBTRMSourceTransportEntry * transport);
        void loadSourceRSTDetails(LBMLBTRMSourceTransportEntry * transport);
        void loadReceiverNAKDetails(LBMLBTRMReceiverTransportEntry * transport);

    private slots:
        void closeDialog(void);
        void on_applyFilterButton_clicked(void);

        void sourcesDetailCurrentChanged(int Index);
        void sourcesItemClicked(QTreeWidgetItem * item, int column);
        void receiversItemClicked(QTreeWidgetItem * item, int column);
        void sourcesDetailItemDoubleClicked(QTreeWidgetItem * item, int column);
        void receiversDetailItemDoubleClicked(QTreeWidgetItem * item, int column);
        void actionSourceDataFrames_triggered(bool checked);
        void actionSourceDataBytes_triggered(bool checked);
        void actionSourceDataFramesBytes_triggered(bool checked);
        void actionSourceDataRate_triggered(bool checked);
        void actionSourceRXDataFrames_triggered(bool checked);
        void actionSourceRXDataBytes_triggered(bool checked);
        void actionSourceRXDataFramesBytes_triggered(bool checked);
        void actionSourceRXDataRate_triggered(bool checked);
        void actionSourceNCFFrames_triggered(bool checked);
        void actionSourceNCFCount_triggered(bool checked);
        void actionSourceNCFBytes_triggered(bool checked);
        void actionSourceNCFFramesBytes_triggered(bool checked);
        void actionSourceNCFCountBytes_triggered(bool checked);
        void actionSourceNCFFramesCount_triggered(bool checked);
        void actionSourceNCFFramesCountBytes_triggered(bool checked);
        void actionSourceNCFRate_triggered(bool checked);
        void actionSourceSMFrames_triggered(bool checked);
        void actionSourceSMBytes_triggered(bool checked);
        void actionSourceSMFramesBytes_triggered(bool checked);
        void actionSourceSMRate_triggered(bool checked);
        void actionSourceAutoResizeColumns_triggered(void);
        void custom_source_context_menuRequested(const QPoint & pos);
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
