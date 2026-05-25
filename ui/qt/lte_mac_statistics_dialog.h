/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LTE_MAC_STATISTICS_DIALOG_H__
#define __LTE_MAC_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

#include <QLabel>
#include <QCheckBox>

#include <ui/qt/models/percent_bar_delegate.h>

/**
 * @brief Structure for holding common 3GPP MAC statistics.
 */
typedef struct mac_3gpp_common_stats {
    /** Total number of frames. */
    uint32_t all_frames;

    /** Number of MIB (Master Information Block) frames. */
    uint32_t mib_frames;

    /** Number of SIB (System Information Block) frames. */
    uint32_t sib_frames;

    /** Total bytes in SIB frames. */
    uint32_t sib_bytes;

    /** Number of PCH (Paging Channel) frames. */
    uint32_t pch_frames;

    /** Total bytes in PCH frames. */
    uint32_t pch_bytes;

    /** Number of Paging IDs found in PCH frames. */
    uint32_t pch_paging_ids;

    /** Number of RAR (Random Access Response) frames. */
    uint32_t rar_frames;

    /** Number of RAR entries. */
    uint32_t rar_entries;

    /** Maximum number of Uplink UEs in a single TTI. */
    uint16_t max_ul_ues_in_tti;

    /** Maximum number of Downlink UEs in a single TTI. */
    uint16_t max_dl_ues_in_tti;
} mac_3gpp_common_stats;


/**
 * @brief Dialog for displaying LTE MAC statistics.
 */
class LteMacStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new LteMacStatisticsDialog.
     * @param parent The parent widget.
     * @param cf The capture file associated with the dialog.
     * @param filter The display filter to apply.
     */
    LteMacStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);

    /**
     * @brief Destroys the LteMacStatisticsDialog.
     */
    ~LteMacStatisticsDialog();

protected:
    /**
     * @brief Handles the event when the capture file is closing.
     */
    void captureFileClosing() override;

private:
    /** Label to display the common statistics summary. */
    QLabel *commonStatsLabel_;

    /** Checkbox to toggle the display of Scheduling Request (SR) filters. */
    QCheckBox *showSRFilterCheckBox_;

    /** Checkbox to toggle the display of RACH filters. */
    QCheckBox *showRACHFilterCheckBox_;

    /** Delegate for rendering the uplink percentage bar. */
    PercentBarDelegate *ul_delegate_;

    /** Delegate for rendering the downlink percentage bar. */
    PercentBarDelegate *dl_delegate_;

    /** The active display filter string. */
    QString   displayFilter_;

    /**
     * @brief Callback to reset the tap data.
     * @param ws_dlg_ptr Pointer to the dialog instance.
     */
    static void tapReset(void *ws_dlg_ptr);

    /**
     * @brief Callback to process a tapped packet.
     * @param ws_dlg_ptr Pointer to the dialog instance.
     * @param pinfo Pointer to the packet info structure.
     * @param edt Pointer to the epan dissection structure.
     * @param mac_3gpp_tap_info_ptr Pointer to the 3GPP MAC tap information.
     * @param flags Tap flags.
     * @return The tap packet status.
     */
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *pinfo, struct epan_dissect *edt, const void *mac_3gpp_tap_info_ptr, tap_flags_t flags);

    /**
     * @brief Callback to draw the tap results.
     * @param ws_dlg_ptr Pointer to the dialog instance.
     */
    static void tapDraw(void *ws_dlg_ptr);

    /**
     * @brief Gets the current filter expression.
     * @return The filter expression as a string.
     */
    virtual const QString filterExpression() override;

    /** Structure holding the common statistics. */
    mac_3gpp_common_stats commonStats_;

    /** Flag indicating whether the common stats are current (not yet drawn). */
    bool commonStatsCurrent_;

    /**
     * @brief Updates the common statistics with new tap info.
     * @param mlt_info Pointer to the MAC LTE tap info to apply.
     */
    void updateCommonStats(const struct mac_3gpp_tap_info *mlt_info);

    /**
     * @brief Draws the common statistics to the UI.
     */
    void drawCommonStats();

    /**
     * @brief Clears the common statistics data.
     */
    void clearCommonStats();

    /**
     * @brief Gets the total frame count.
     * @return The number of frames.
     */
    unsigned  getFrameCount();

    /**
     * @brief Retrieves the data associated with a tree item.
     * @param item The tree widget item to inspect.
     * @return A list of variants containing the item's data.
     */
    QList<QVariant> treeItemData(QTreeWidgetItem *item) const override;

private slots:
    /**
     * @brief Fills the tree with MAC statistics data.
     */
    virtual void fillTree() override;

    /**
     * @brief Updates the labels in the header.
     */
    void updateHeaderLabels();

    /**
     * @brief Slot triggered when the filter is updated.
     * @param filter The new filter string.
     */
    void filterUpdated(QString filter);
};

#endif // __LTE_MAC_STATISTICS_DIALOG_H__
