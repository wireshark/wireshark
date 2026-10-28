/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MKA_CA_DIALOG_H
#define MKA_CA_DIALOG_H

#include "tap_parameter_dialog.h"

class QPushButton;

struct mka_ca_stat_s;

/**
 * @brief Statistics dialog for MKA Connectivity Associations.
 *
 * Shows, per CA (identified by a known CKN/CAK), the detected peers, each
 * peer's live/potential peer lists, SAK Use parameters and last-heard time,
 * the key server history, and the key-formation timings for key server
 * startup, rekey, key server change and new-peer key distribution.
 */
class MkaCaDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new MkaCaDialog.
     * @param parent The parent widget.
     * @param cf The capture file associated with the dialog.
     * @param filter Optional display filter, defaults to NULL.
     */
    MkaCaDialog(QWidget &parent, CaptureFile &cf, const char *filter = NULL);

    /**
     * @brief Destroys the MkaCaDialog.
     */
    ~MkaCaDialog();

    /**
     * @brief Factory used by the TapParameterDialog registry.
     */
    static TapParameterDialog *createMkaCaDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

protected:
    /**
     * @brief Handles the event when the capture file is closing.
     */
    void captureFileClosing() override;

private:
    /** Shared MKA CA analysis engine state. */
    struct mka_ca_stat_s *stat_;

    /** Whether a tap listener is currently registered on stat_. */
    bool tap_registered_;

    /** Auto-refresh toggle button in the dialog button box. */
    QPushButton *auto_refresh_button_;

    /** Dialog-local base font (before zoom scaling) for the tree. */
    QFont base_font_;

    /** Applies base_font_ scaled by the current zoom factor to the tree. */
    void applyFont();

    /**
     * @brief Tap reset callback.
     * @param tapdata Pointer to this dialog.
     */
    static void tapReset(void *tapdata);

    /**
     * @brief Tap per-packet callback.
     */
    static tap_packet_status tapPacket(void *tapdata, struct _packet_info *pinfo, struct epan_dissect *edt, const void *data, tap_flags_t flags);

    /**
     * @brief Tap draw callback; redraws the tree from accumulated data.
     * @param tapdata Pointer to this dialog.
     */
    static void tapDraw(void *tapdata);

    /**
     * @brief Registers the tap listener for this dialog.
     * @return An error string on failure, otherwise NULL.
     */
    GString *registerTap();

    /**
     * @brief Removes the tap listener if one is currently registered.
     */
    void removeTap();

    /**
     * @brief Rescans the capture, rebuilding the analysis state.
     */
    void rescan();

    /**
     * @brief Rebuilds the tree from the current analysis state.
     */
    void drawTree();

    /**
     * @brief Retrieves the data associated with a tree item for copy/export.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const override;

    /**
     * @brief Display filter for the currently selected item, for the find /
     *        filter / colorize context menu.
     */
    virtual const QString filterExpression() override;

private slots:
    /**
     * @brief Fills the tree with the current analysis results.
     */
    virtual void fillTree() override;

    /**
     * @brief Navigates to the frame associated with a double-clicked item.
     * @param item The activated tree item.
     */
    void itemDoubleClicked(QTreeWidgetItem *item, int column);
    /**
     * @brief Auto-expands a formation's 'Peers' folder when the formation is
     *        expanded.
     * @param item The expanded tree item.
     */
    void itemExpanded(QTreeWidgetItem *item);
    /**
     * @brief Handles capture file events; re-registers the tap and refreshes
     *        when a new capture file finishes loading.
     * @param e The capture event.
     */
    void mkaCaptureEvent(CaptureEvent e);

    /**
     * @brief Opens a font chooser and applies the selection to the tree.
     */
    void chooseFont();
};

#endif // MKA_CA_DIALOG_H
