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

#include <epan/cfile.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <QDialog>

namespace Ui
{
    class LBMStreamDialog;
}

class LBMStreamDialogInfo;

/**
 * @brief Dialog for analyzing LBM stream statistics and details.
 */
class LBMStreamDialog : public QDialog
{
        Q_OBJECT

    public:
        /**
         * @brief Constructs a new LBMStreamDialog.
         * @param parent The parent widget, defaults to 0.
         * @param cfile The capture file, defaults to NULL.
         */
        explicit LBMStreamDialog(QWidget * parent = 0, capture_file * cfile = NULL);

        /**
         * @brief Destroys the LBMStreamDialog.
         */
        ~LBMStreamDialog(void);

        /**
         * @brief Retrieves the UI object.
         * @return Pointer to the UI object.
         */
        Ui::LBMStreamDialog * getUI(void)
        {
            return (m_ui);
        }

    public slots:
        /**
         * @brief Sets the capture file.
         * @param cfile The capture file to set.
         */
        void setCaptureFile(capture_file * cfile);

    private:
        /** Pointer to the UI object. */
        Ui::LBMStreamDialog * m_ui;

        /** Pointer to the dialog information. */
        LBMStreamDialogInfo * m_dialog_info;

        /** Pointer to the capture file. */
        capture_file * m_capture_file;

        /**
         * @brief Fills the tree with stream data.
         */
        void fillTree(void);

        /**
         * @brief Callback to reset the tap data.
         * @param tap_data Pointer to the tap data.
         */
        static void resetTap(void * tap_data);

        /**
         * @brief Callback to process a tapped packet.
         * @param tap_data Pointer to the tap data.
         * @param pinfo Pointer to the packet info structure.
         * @param edt Pointer to the epan dissection structure.
         * @param stream_info Pointer to the stream information.
         * @param flags Tap flags.
         * @return The tap packet status.
         */
        static tap_packet_status tapPacket(void * tap_data, packet_info * pinfo, epan_dissect_t * edt, const void * stream_info, tap_flags_t flags);

        /**
         * @brief Callback to draw the tree items.
         * @param tap_data Pointer to the tap data.
         */
        static void drawTreeItems(void * tap_data);

    private slots:
        /**
         * @brief Slot triggered when the apply filter button is clicked.
         */
        void on_applyFilterButton_clicked(void);
};

#endif
