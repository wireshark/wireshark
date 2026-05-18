/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WLANSTATISTICSDIALOG_H
#define WLANSTATISTICSDIALOG_H

#include "tap_parameter_dialog.h"
#include <ui/qt/models/percent_bar_delegate.h>

class QElapsedTimer;

/**
 * @brief Dialog for displaying and filtering WLAN network statistics,
 *        including per-network and per-station packet counts, retry rates,
 *        and other 802.11 metrics captured from a live or saved capture file.
 */
class WlanStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the WLAN Statistics dialog and registers the tap listener.
     * @param parent  Parent widget reference.
     * @param cf      Capture file whose packets are analysed.
     * @param filter  Optional display filter string applied to the tap; @c nullptr for no filter.
     */
    WlanStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);

    /**
     * @brief Destroys the dialog and deregisters the tap listener.
     */
    ~WlanStatisticsDialog();

protected:
    /**
     * @brief Called when the associated capture file is being closed; stops
     *        the tap and disables any actions that require live data.
     */
    void captureFileClosing();

private:
    int               packet_count_;       /**< Total number of packets processed by the tap. */
    int               cur_network_;        /**< Index of the network currently being populated. */
    PercentBarDelegate *packets_delegate_; /**< Delegate that renders packet-count cells as percent bars. */
    PercentBarDelegate *retry_delegate_;   /**< Delegate that renders retry-rate cells as percent bars. */
    QElapsedTimer     *add_station_timer_; /**< Timer used to throttle incremental station-row insertion. */
    QString            displayFilter_;     /**< Display filter string applied when the dialog was opened. */

    /**
     * @brief Tap callback invoked when the tap is reset (e.g. on retap); clears
     *        all accumulated statistics in the dialog pointed to by @p ws_dlg_ptr.
     * @param ws_dlg_ptr Opaque pointer to the WlanStatisticsDialog instance.
     */
    static void tapReset(void *ws_dlg_ptr);

    /**
     * @brief Tap callback invoked for each matching packet; extracts 802.11
     *        header data and accumulates per-network and per-station statistics.
     * @param ws_dlg_ptr    Opaque pointer to the WlanStatisticsDialog instance.
     * @param pinfo         Packet metadata (unused directly; provided by tap framework).
     * @param edt           Dissection tree for the packet (unused directly).
     * @param wlan_hdr_ptr  Pointer to the decoded WLAN tap header structure.
     * @param flags         Tap flags for this packet.
     * @return TAP_PACKET_REDRAW if the display should be redrawn, TAP_PACKET_DONT_REDRAW otherwise.
     */
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *pinfo,
                                       struct epan_dissect *edt,
                                       const void *wlan_hdr_ptr, tap_flags_t flags);

    /**
     * @brief Tap callback invoked after all packets have been processed; triggers
     *        a final UI refresh on the dialog pointed to by @p ws_dlg_ptr.
     * @param ws_dlg_ptr Opaque pointer to the WlanStatisticsDialog instance.
     */
    static void tapDraw(void *ws_dlg_ptr);

    /**
     * @brief Returns the current display filter expression for use by the tap framework.
     * @return Display filter string, or an empty string if none is set.
     */
    virtual const QString filterExpression() ;

    /**
     * @brief Serialises one tree item's visible column data into a list of
     *        QVariant values for CSV/clipboard export.
     * @param it Tree widget item to serialise.
     * @return Ordered list of column values for the given item.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *it) const;

private slots:
    /**
     * @brief Clears and rebuilds the entire network/station tree from accumulated
     *        tap data; connected to the retap completion signal.
     */
    virtual void fillTree();

    /**
     * @brief Incrementally inserts buffered station rows under their parent network
     *        item; called periodically via @c add_station_timer_ to keep the UI
     *        responsive during large captures.
     */
    void addStationTreeItems();

    /**
     * @brief Refreshes the column header labels to reflect the current sort column
     *        and sort order.
     */
    void updateHeaderLabels();

    /**
     * @brief Responds to an external filter change by re-running the tap with the
     *        updated filter expression.
     * @param filter The new display filter string.
     */
    void filterUpdated(QString filter);
};

#endif // WLANSTATISTICSDIALOG_H
