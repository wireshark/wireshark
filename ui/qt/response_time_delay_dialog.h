/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RESPONSE_TIME_DELAY_DIALOG_H__
#define __RESPONSE_TIME_DELAY_DIALOG_H__

#include "tap_parameter_dialog.h"

struct _rtd_stat_table;

/**
 * @brief Dialog for calculating and displaying response time delays.
 */
class ResponseTimeDelayDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ResponseTimeDelayDialog.
     * @param parent The parent widget.
     * @param cf The capture file associated with the dialog.
     * @param rtd Pointer to the registered RTD structure.
     * @param filter The display filter to apply.
     * @param help_topic The help topic identifier, defaults to 0.
     */
    ResponseTimeDelayDialog(QWidget &parent, CaptureFile &cf, struct register_rtd *rtd, const QString filter, int help_topic = 0);

    /**
     * @brief Factory method to create an RTD dialog from a configuration string.
     * @param parent The parent widget.
     * @param cfg_str The configuration string defining the RTD parameters.
     * @param filter The display filter to apply.
     * @param cf The capture file.
     * @return Pointer to the created TapParameterDialog instance.
     */
    static TapParameterDialog *createRtdDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

protected:
    /**
     * @brief Add a response time delay table.
     *
     * @param rtd_table The table to add.
     */
    // gtk:service_response_table.h:init_srt_table
    void addRtdTable(const struct _rtd_stat_table *rtd_table);

private:
    /** Pointer to the registered RTD structure. */
    struct register_rtd *rtd_;

    /**
     * @brief Callback to reset the RTD tap data.
     * @param rtdd_ptr Pointer to the dialog instance.
     */
    static void tapReset(void *rtdd_ptr);

    /**
     * @brief Callback to draw the RTD tap results.
     * @param rtdd_ptr Pointer to the dialog instance.
     */
    static void tapDraw(void *rtdd_ptr);

    /**
     * @brief Retrieves the data associated with a tree item.
     * @param ti The tree widget item to process.
     * @return A list of variants containing the data for the item.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const override;

private slots:
    /**
     * @brief Fills the tree view with response time delay statistics.
     */
    virtual void fillTree() override;
};

/** Register function to register dissectors that support RTD for Qt.
 *
 * @param key is unused
 * @param value register_rtd_t* representing dissector RTD table
 * @param userdata is unused
 */
bool register_response_time_delay_tables(const void *key, void *value, void *userdata);

#endif // __RESPONSE_TIME_DELAY_DIALOG_H__
