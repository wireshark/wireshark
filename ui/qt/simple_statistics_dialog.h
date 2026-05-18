/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SIMPLE_STATISTICS_DIALOG_H__
#define __SIMPLE_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

struct _stat_data_t;

/**
 * @brief TapParameterDialog specialisation that displays a generic
 *        tap-driven statistics table whose columns and rows are defined
 *        entirely by a _stat_tap_table_ui descriptor.
 */
class SimpleStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a SimpleStatisticsDialog and registers the tap listener.
     * @param parent     Parent widget reference.
     * @param cf         Capture file to attach the tap to.
     * @param stu        Descriptor defining the table's columns, tap name, and callbacks.
     * @param filter     Initial display-filter string applied to the tap.
     * @param help_topic Optional help topic ID; 0 disables the Help button.
     */
    SimpleStatisticsDialog(QWidget &parent, CaptureFile &cf,
                           struct _stat_tap_table_ui *stu,
                           const QString filter,
                           int help_topic = 0);

    /**
     * @brief Factory function conforming to the TapParameterDialog creation signature.
     *
     * Instantiates a SimpleStatisticsDialog from the registered tap configuration
     * string, suitable for use with TapParameterDialog::registerDialog().
     *
     * @param parent  Parent widget reference.
     * @param cfg_str Configuration string identifying the registered tap.
     * @param filter  Initial display-filter string.
     * @param cf      Capture file to attach the tap to.
     * @return Pointer to the newly created TapParameterDialog instance.
     */
    static TapParameterDialog *createSimpleStatisticsDialog(QWidget &parent,
                                                             const QString cfg_str,
                                                             const QString filter,
                                                             CaptureFile &cf);

protected:
    /**
     * @brief Adds tree widget rows for any table entries present in @p stat_data
     *        that do not yet have a corresponding row in the tree widget.
     *
     * Analogous to init_srt_table() in the GTK service-response-time UI.
     *
     * @param stat_data Tap statistics data containing the current table state.
     */
    void addMissingRows(struct _stat_data_t *stat_data);

private:
    struct _stat_tap_table_ui *stu_; /**< Descriptor defining columns, tap name, and draw/reset callbacks. */

    /**
     * @brief Tap reset callback; clears accumulated statistics and resets all rows.
     * @param sd_ptr Pointer to the SimpleStatisticsDialog instance (cast from void *).
     */
    static void tapReset(void *sd_ptr);

    /**
     * @brief Tap draw callback; updates the tree widget rows with the latest statistics.
     * @param sd_ptr Pointer to the SimpleStatisticsDialog instance (cast from void *).
     */
    static void tapDraw(void *sd_ptr);

    /**
     * @brief Returns the exportable column data for a tree widget item.
     *
     * Called by the base-class export machinery for each SimpleStatisticsTreeWidgetItem.
     *
     * @param item Tree widget item to extract data from.
     * @return List of QVariant values, one per column, in column order.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *item) const;

    /**
     * @brief Destroys the dialog, deregisters the tap listener, and frees resources.
     */
    ~SimpleStatisticsDialog();

private slots:
    /**
     * @brief Rebuilds the tree widget from the current tap data.
     *
     * Called after the tap has been (re-)run, e.g. when the filter changes or
     * a new capture file is loaded.
     */
    virtual void fillTree();
};

/**
 * @brief Register function to register dissectors that support a "simple" statistics table.
 *
 * @param key is tap string
 * @param value stat_tap_table_ui* representing dissector stat table
 */
bool register_simple_stat_tables(const void *key, void *value, void*);

#endif // __SIMPLE_STATISTICS_DIALOG_H__
