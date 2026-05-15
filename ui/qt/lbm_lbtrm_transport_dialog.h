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

#ifndef LBM_LBTRM_TRANSPORT_DIALOG_H
#define LBM_LBTRM_TRANSPORT_DIALOG_H

#include <config.h>

#include <epan/cfile.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <QDialog>

class QHeaderView;
class QMenu;
class QTreeWidgetItem;

namespace Ui
{
    class LBMLBTRMTransportDialog;
}

class LBMLBTRMTransportDialogInfo;
class LBMLBTRMSourceTransportEntry;
class LBMLBTRMReceiverTransportEntry;

/**
 * @brief Dialog for analyzing LBM LBTRM transport statistics and details.
 */
class LBMLBTRMTransportDialog : public QDialog
{
        Q_OBJECT

    public:
        /**
         * @brief Constructs a new LBMLBTRMTransportDialog.
         * @param parent The parent widget, defaults to 0.
         * @param cfile The capture file, defaults to NULL.
         */
        explicit LBMLBTRMTransportDialog(QWidget * parent = 0, capture_file * cfile = NULL);

        /**
         * @brief Retrieves the UI object.
         * @return Pointer to the UI object.
         */
        Ui::LBMLBTRMTransportDialog * getUI(void)
        {
            return (m_ui);
        }

    public slots:
        /**
         * @brief Sets the capture file.
         * @param cfile The capture file to set.
         */
        void setCaptureFile(capture_file * cfile);

    signals:
        /**
         * @brief Signal emitted to navigate to a specific packet.
         * @param PacketNum The packet number to navigate to.
         */
        void goToPacket(int PacketNum);

    private:
        /** Pointer to the UI object. */
        Ui::LBMLBTRMTransportDialog * m_ui;

        /** Pointer to the dialog information. */
        LBMLBTRMTransportDialogInfo * m_dialog_info;

        /** Pointer to the capture file. */
        capture_file * m_capture_file;

        /** Pointer to the current source transport entry. */
        LBMLBTRMSourceTransportEntry * m_current_source_transport;

        /** Pointer to the current receiver transport entry. */
        LBMLBTRMReceiverTransportEntry * m_current_receiver_transport;

        /** Pointer to the source context menu. */
        QMenu * m_source_context_menu;

        /** Pointer to the source tree header view. */
        QHeaderView * m_source_header;

        /**
         * @brief Destroys the LBMLBTRMTransportDialog.
         */
        virtual ~LBMLBTRMTransportDialog(void);

        /**
         * @brief Resets the sources tree.
         */
        void resetSources(void);

        /**
         * @brief Resets the receivers tree.
         */
        void resetReceivers(void);

        /**
         * @brief Resets the sources detail view.
         */
        void resetSourcesDetail(void);

        /**
         * @brief Resets the receivers detail view.
         */
        void resetReceiversDetail(void);

        /**
         * @brief Fills the tree with transport data.
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

        /**
         * @brief Loads details for source data.
         * @param transport Pointer to the source transport entry.
         */
        void loadSourceDataDetails(LBMLBTRMSourceTransportEntry * transport);

        /**
         * @brief Loads details for source RX data.
         * @param transport Pointer to the source transport entry.
         */
        void loadSourceRXDataDetails(LBMLBTRMSourceTransportEntry * transport);

        /**
         * @brief Loads details for source NCF data.
         * @param transport Pointer to the source transport entry.
         */
        void loadSourceNCFDetails(LBMLBTRMSourceTransportEntry * transport);

        /**
         * @brief Loads details for source SM data.
         * @param transport Pointer to the source transport entry.
         */
        void loadSourceSMDetails(LBMLBTRMSourceTransportEntry * transport);

        /**
         * @brief Loads details for source RST data.
         * @param transport Pointer to the source transport entry.
         */
        void loadSourceRSTDetails(LBMLBTRMSourceTransportEntry * transport);

        /**
         * @brief Loads details for receiver NAK data.
         * @param transport Pointer to the receiver transport entry.
         */
        void loadReceiverNAKDetails(LBMLBTRMReceiverTransportEntry * transport);

    private slots:
        /**
         * @brief Slot triggered when the apply filter button is clicked.
         */
        void on_applyFilterButton_clicked(void);

        /**
         * @brief Slot triggered when the current source detail index changes.
         * @param Index The new index.
         */
        void sourcesDetailCurrentChanged(int Index);

        /**
         * @brief Slot triggered when a source item is clicked.
         * @param item The clicked tree widget item.
         * @param column The clicked column index.
         */
        void sourcesItemClicked(QTreeWidgetItem * item, int column);

        /**
         * @brief Slot triggered when a receiver item is clicked.
         * @param item The clicked tree widget item.
         * @param column The clicked column index.
         */
        void receiversItemClicked(QTreeWidgetItem * item, int column);

        /**
         * @brief Slot triggered when a source detail item is double-clicked.
         * @param item The double-clicked tree widget item.
         * @param column The double-clicked column index.
         */
        void sourcesDetailItemDoubleClicked(QTreeWidgetItem * item, int column);

        /**
         * @brief Slot triggered when a receiver detail item is double-clicked.
         * @param item The double-clicked tree widget item.
         * @param column The double-clicked column index.
         */
        void receiversDetailItemDoubleClicked(QTreeWidgetItem * item, int column);

        /**
         * @brief Slot triggered when the source data frames action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceDataFrames_triggered(bool checked);

        /**
         * @brief Slot triggered when the source data bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceDataBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source data frames/bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceDataFramesBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source data rate action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceDataRate_triggered(bool checked);

        /**
         * @brief Slot triggered when the source RX data frames action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceRXDataFrames_triggered(bool checked);

        /**
         * @brief Slot triggered when the source RX data bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceRXDataBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source RX data frames/bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceRXDataFramesBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source RX data rate action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceRXDataRate_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF frames action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFFrames_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF count action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFCount_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF frames/bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFFramesBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF count/bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFCountBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF frames/count action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFFramesCount_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF frames/count/bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFFramesCountBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source NCF rate action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceNCFRate_triggered(bool checked);

        /**
         * @brief Slot triggered when the source SM frames action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceSMFrames_triggered(bool checked);

        /**
         * @brief Slot triggered when the source SM bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceSMBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source SM frames/bytes action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceSMFramesBytes_triggered(bool checked);

        /**
         * @brief Slot triggered when the source SM rate action is triggered.
         * @param checked True if checked, false otherwise.
         */
        void actionSourceSMRate_triggered(bool checked);

        /**
         * @brief Slot triggered to automatically resize source columns.
         */
        void actionSourceAutoResizeColumns_triggered(void);

        /**
         * @brief Slot triggered when the custom source context menu is requested.
         * @param pos The position of the request.
         */
        void custom_source_context_menuRequested(const QPoint & pos);
};

#endif
