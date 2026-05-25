/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SERVICE_RESPONSE_TIME_DIALOG_H__
#define __SERVICE_RESPONSE_TIME_DIALOG_H__

#include "tap_parameter_dialog.h"
#include <epan/srt_table.h>

struct register_srt;
struct _srt_stat_table;

class QTreeWidgetItem;

/**
 * @brief Base dialog for displaying Service Response Time (SRT) statistics.
 */
class ServiceResponseTimeDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ServiceResponseTimeDialog object.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param srt Pointer to the registered SRT structure.
     * @param filter The display filter to apply.
     * @param help_topic The help topic ID associated with this dialog.
     */
    ServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, const QString filter, int help_topic = 0);

    /**
     * @brief Destroys the ServiceResponseTimeDialog object.
     */
    ~ServiceResponseTimeDialog();

    /**
     * @brief Factory method to create an SRT dialog.
     * @param parent The parent widget.
     * @param cfg_str The configuration string.
     * @param filter The display filter.
     * @param cf The capture file.
     * @return A pointer to the created TapParameterDialog.
     */
    static TapParameterDialog *createSrtDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

public slots:
    /**
     * @brief Slot called when the retap of packets finishes.
     */
    void endRetapPackets() override;

protected:
    /** @brief Pointer to the registered SRT data structure. */
    struct register_srt *srt_;

    /** Add a service response time table.
     *
     * In the GTK+ UI "tables" are separate, tabbed widgets. In the Qt UI they are
     * separate groups of QTreeWidgetItems.
     *
     * @param srt_table The table to add.
     */
    // gtk:service_response_table.h:init_srt_table
    void addSrtTable(const struct _srt_stat_table *srt_table);

    /**
     * @brief Virtual method for derived classes to provide specific parameter data.
     */
    virtual void provideParameterData() {}

protected slots:
    /**
     * @brief Fills the tree widget with the collected SRT statistics.
     */
    void fillTree() override;

private:
    // Callbacks for register_tap_listener
    /**
     * @brief Callback to reset the collected tap data.
     * @param srtd_ptr Pointer to the dialog instance.
     */
    static void tapReset(void *srtd_ptr);

    /**
     * @brief Callback to draw/update the UI with the collected tap data.
     * @param srtd_ptr Pointer to the dialog instance.
     */
    static void tapDraw(void *srtd_ptr);

    /**
     * @brief Formats the data for a single tree item row.
     * @param ti The tree widget item.
     * @return A list of QVariant representing the column data.
     */
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const override;

    /**
     * @brief Retrieves the filter expression constructed for the selected tree items.
     * @return The filter string.
     */
    virtual const QString filterExpression() override;

    /** @brief The internal SRT data state. */
    srt_data_t srt_data_;

private slots:
    /**
     * @brief Handles changes in the tree widget selection to update UI state.
     */
    void statsTreeWidgetItemChanged();
};

/** Register function to register dissectors that support SRT.
 *
 * @param key is unused
 * @param value register_srt_t* representing dissector SRT table
 * @param userdata is unused
 * @return True to continue iterating, false to stop.
 */
bool register_service_response_tables(const void *key, void *value, void *userdata);

#endif // __SERVICE_RESPONSE_TIME_DIALOG_H__
