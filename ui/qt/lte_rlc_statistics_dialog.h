/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LTE_RLC_STATISTICS_DIALOG_H__
#define __LTE_RLC_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

#include <epan/dissectors/packet-rlc-lte.h>
#include <epan/dissectors/packet-rlc-3gpp-common.h>


#include <QCheckBox>

/**
 * @brief Dialog for displaying LTE RLC statistics.
 */
class LteRlcStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new LteRlcStatisticsDialog.
     * @param parent The parent widget.
     * @param cf The capture file associated with the dialog.
     * @param filter The display filter to apply.
     */
    LteRlcStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter);

    /**
     * @brief Destroys the LteRlcStatisticsDialog.
     */
    ~LteRlcStatisticsDialog();

    /**
     * @brief Retrieves the current frame count.
     * @return The number of packets processed.
     */
    unsigned getFrameCount() { return packet_count_; }

    /**
     * @brief Increments the frame count.
     */
    void     incFrameCount() { ++packet_count_; }

protected:
    /**
     * @brief Handles the event when the capture file is closing.
     */
    void captureFileClosing() override;

signals:
    /**
     * @brief Signal emitted to launch an RLC graph.
     * @param channelKnown True if the channel is already known.
     * @param version The RAT version.
     * @param ueid The User Equipment identifier.
     * @param rlcMode The RLC mode (e.g., AM, UM).
     * @param channelType The type of the channel.
     * @param channelId The identifier for the channel.
     * @param direction The direction of the channel (uplink/downlink).
     */
    void launchRLCGraph(bool channelKnown,
                        uint8_t version,
                        uint16_t ueid,
                        uint8_t rlcMode,
                        uint16_t channelType, uint16_t channelId,
                        uint8_t direction);

private:
    /** Checkbox for using RLC frames from MAC. */
    QCheckBox *useRLCFramesFromMacCheckBox_;

    /** Checkbox for showing Scheduling Request (SR) filters. */
    QCheckBox *showSRFilterCheckBox_;

    /** Checkbox for showing RACH filters. */
    QCheckBox *showRACHFilterCheckBox_;

    /** Button to launch the uplink graph. */
    QPushButton *launchULGraph_;

    /** Button to launch the downlink graph. */
    QPushButton *launchDLGraph_;

    /** The active display filter string. */
    QString     displayFilter_;

    /** Reference to the capture file. */
    CaptureFile &cf_;

    /** Counter for the number of packets processed. */
    int packet_count_;

    /**
     * @brief Callback to reset the tap data.
     * @param ws_dlg_ptr Pointer to the dialog instance.
     */
    static void tapReset(void *ws_dlg_ptr);

    /**
     * @brief Callback to process a tapped packet.
     * @param ws_dlg_ptr Pointer to the dialog instance.
     * @param rlc_lte_tap_info_ptr Pointer to the LTE RLC tap information.
     * @param flags Tap flags.
     * @return The tap packet status.
     */
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *, struct epan_dissect *, const void *rlc_lte_tap_info_ptr, tap_flags_t flags);

    /**
     * @brief Callback to draw the tap results.
     * @param ws_dlg_ptr Pointer to the dialog instance.
     */
    static void tapDraw(void *ws_dlg_ptr);

    /**
     * @brief Updates the labels in the header.
     */
    void updateHeaderLabels();

    /**
     * @brief Gets the current filter expression.
     * @return The filter expression as a string.
     */
    virtual const QString filterExpression() override;

    /**
     * @brief Retrieves the data associated with a tree item.
     * @param item The tree widget item to inspect.
     * @return A list of variants containing the item's data.
     */
    QList<QVariant> treeItemData(QTreeWidgetItem *item) const override;

private slots:
    /**
     * @brief Fills the tree with RLC statistics data.
     */
    virtual void fillTree() override;

    /**
     * @brief Slot triggered when the tree item selection changes.
     */
    void updateItemSelectionChanged();

    /**
     * @brief Slot triggered when the use RLC frames from MAC checkbox is toggled.
     * @param state True if checked, false otherwise.
     */
    void useRLCFramesFromMacCheckBoxToggled(bool state);

    /**
     * @brief Slot triggered when the launch UL graph button is clicked.
     */
    void launchULGraphButtonClicked();

    /**
     * @brief Slot triggered when the launch DL graph button is clicked.
     */
    void launchDLGraphButtonClicked();

    /**
     * @brief Slot triggered when the filter is updated.
     * @param filter The new filter string.
     */
    void filterUpdated(QString filter);
};

#endif // __LTE_RLC_STATISTICS_DIALOG_H__
