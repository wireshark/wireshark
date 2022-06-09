/** @file
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LBM_STREAM_DIALOG_H
#define LBM_STREAM_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"
#include <epan/packet_info.h>
#include <epan/tap.h>
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
        static tap_packet_status tapPacket(void * tap_data, packet_info * pinfo, epan_dissect_t * edt, const void * stream_info, tap_flags_t flags);
        static void drawTreeItems(void * tap_data);

    private slots:
        void closeDialog(void);
        void on_applyFilterButton_clicked(void);
};

#endif
