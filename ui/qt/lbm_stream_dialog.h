/* lbm_stream_dialog.h
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

#ifndef LBM_STREAM_DIALOG_H
#define LBM_STREAM_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"
#include <epan/packet_info.h>
#include <QDialog>

namespace Ui
{
    class LBMStreamDialog;
}

class LBMStreamDialogInfo;

class LBMStreamDialog : public QDialog
{
        Q_OBJECT

    public:
        explicit LBMStreamDialog(QWidget * parent = 0, capture_file * cfile = NULL);
        ~LBMStreamDialog(void);
        Ui::LBMStreamDialog * getUI(void)
        {
            return (m_ui);
        }

    public slots:
        void setCaptureFile(capture_file * cfile);

    private:
        Ui::LBMStreamDialog * m_ui;
        LBMStreamDialogInfo * m_dialog_info;
        capture_file * m_capture_file;

        void fillTree(void);
        static void resetTap(void * tap_data);
        static gboolean tapPacket(void * tap_data, packet_info * pinfo, epan_dissect_t * edt, const void * stream_info);
        static void drawTreeItems(void * tap_data);

    private slots:
        void closeDialog(void);
        void on_applyFilterButton_clicked(void);
};

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
