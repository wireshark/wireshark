/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISTRIBUTIONDIALOG_H
#define DISTRIBUTIONDIALOG_H

#include "tap_parameter_dialog.h"

#include <ui/qt/widgets/syntax_line_edit.h>

/*
 * Defines a Variable for building any distribution
 */
struct Variable {

    /* hf abbrev of this variable */
    QString name;

    /* type as returned by hfi_supports_distribution() */
    int     type;

    /* All hf indices for this hf */
    QList<int> hf_indices;
};

/**
 * @brief Dialog for displaying distribution statistics,
 *        with an occurence count, percentages, and an Entropy indicator.
 */
class DistributionDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Distribution Statistics dialog and registers the tap listener.
     * @param parent  Parent widget reference.
     * @param cf      Capture file whose packets are analysed.
     * @param filter  Optional display filter string applied to the tap; @c nullptr for no filter.
     */
    DistributionDialog(QWidget &parent, CaptureFile &cf, const QString &filter);

    /**
     * @brief Destroys the dialog and deregisters the tap listener.
     */
    ~DistributionDialog();

protected:
    /**
     * @brief Called when the associated capture file is being closed; stops
     *        the tap and disables any actions that require live data.
     */
    void captureFileClosing() override;

    /**
     * @brief Inherit refresh of the enabled/disabled state of UI widgets based on current
     *        capture and filter state, then ensure we are dealing with an appropriate Field.
     */
    void updateWidgets() override;


private:
    int               packet_count_;       /**< Total number of packets processed by the tap (matching the filter). */
    int               observations_;       /**< Total number of observations for a distribution ( >= packet_count_ ). */
    QString           displayFilter_;      /**< Display filter string applied when the dialog was opened. */
    bool              tap_registered_;     /**< true if a tap listener is currently registered. */
    int               hf_index_;
    bool              needsQuotes_;
    int               field_type_;
    wmem_allocator_t  *allocator;
    wmem_map_t        *fvalues_map_;

    bool retap_running_ = false;

    /* variables and String for managing the input filter */
    QList<Variable> pending_variables_;
    QString         pending_text_;
    QList<Variable> variables_;

    /**
     * @brief Tap callback invoked when the tap is reset (e.g. on retap); clears
     *        all accumulated statistics in the dialog pointed to by @p ws_dlg_ptr.
     * @param ws_dlg_ptr Opaque pointer to the DistributionDialog instance.
     */
    static void tapReset(void *ws_dlg_ptr);

    /**
     * @brief Tap callback invoked for each matching packet; extracts 802.11
     *        header data and accumulates per-network and per-station statistics.
     * @param ws_dlg_ptr    Opaque pointer to the DistributionDialog instance.
     * @param pinfo         Packet metadata (unused directly; provided by tap framework).
     * @param edt           Dissection tree for the packet (unused directly).
     * @param dist_hdr_ptr  Pointer to a header structure, not used yet.
     * @param flags         Tap flags for this packet.
     * @return TAP_PACKET_REDRAW if the display should be redrawn, TAP_PACKET_DONT_REDRAW otherwise.
     */
    static tap_packet_status tapPacket(void *ws_dlg_ptr, struct _packet_info *pinfo,
                                       struct epan_dissect *edt,
                                       const void *dist_hdr_ptr, tap_flags_t flags);

    /**
     * @brief Tap callback invoked after all packets have been processed; triggers
     *        a final UI refresh on the dialog pointed to by @p ws_dlg_ptr.
     * @param ws_dlg_ptr Opaque pointer to the DistributionDialog instance.
     */
    static void tapDraw(void *ws_dlg_ptr);

    /**
     * @brief Remove all elements from the storage map related to the tap.
     */
    static void tapRemoveAll(void *ws_dlg_ptr);

    /**
     * @brief Insert a key in the distribution map.
     */
    static void insertOccurence(void*, void*, void*);

    /**
     * @brief Set enclosing quotes to the display filter when necessary.
     */
    void setFilterQuotes(int);

    /**
     * @brief Set an aggregate type corresponding to the filter.
     */
    void setFieldType(int);

    /**
     * @brief Returns the current display filter expression for use by the tap framework.
     * @return Display filter string, or an empty string if none is set.
     */
    const QString filterExpression() override;

    /**
     * @brief Serialises one tree item's visible column data into a list of
     *        QVariant values for CSV/clipboard export.
     * @param it Tree widget item to serialise.
     * @return Ordered list of column values for the given item.
     */
    QList<QVariant> treeItemData(QTreeWidgetItem *it) const override;

    /**
     * @brief Parses text and returns true if it can be splitted in valid tokens.
     * @param text       The text to be parsed and splitted
     * @param variables  A list of tokens to be returned
     * @return boolean (true if it can be splitted, false otherwise)
     */
    bool parseFields(const QString &text, QList<Variable> &variables) const;

    /**
     * @brief Checks the input text syntax and returns its state
     * @param text         The text to be checked
     * @return State value (Empty/Valid/Invalid)
     */
    SyntaxLineEdit::SyntaxState checkInput(const QString &text);

private slots:
    /**
     * @brief Clears and rebuilds the entire network/station tree from accumulated
     *        tap data; connected to the retap completion signal.
     */
    void fillTree() override;

    /**
     * @brief Refreshes the window subtitle to reflect the current sort column.
     */
    void updateLabels();

    /**
     * @brief Responds to an external filter change by re-running the tap with the
     *        updated filter expression.
     * @param filter The new display filter string.
     */
    void filterUpdated(QString filter);

    /**
     * @brief Runs some logic when the display filter is changed.
     * @param filter The new display filter string.
     */
    void onFilterTextChanged(const QString &filter);
};

#endif // DISTRIBUTIONDIALOG_H
