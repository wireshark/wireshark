/* response_time_delay_dialog.h
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

class ResponseTimeDelayDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    ResponseTimeDelayDialog(QWidget &parent, CaptureFile &cf, struct register_rtd *rtd, const QString filter, int help_topic = 0);
    static TapParameterDialog *createRtdDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

protected:
    /** Add a response time delay table.
     *
     * @param rtd_table The table to add.
     */
    // gtk:service_response_table.h:init_srt_table
    void addRtdTable(const struct _rtd_stat_table *rtd_table);

private:
    struct register_rtd *rtd_;

    // Callbacks for register_tap_listener
    static void tapReset(void *rtdd_ptr);
    static void tapDraw(void *rtdd_ptr);

    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const;

private slots:
    virtual void fillTree();
};

/** Register function to register dissectors that support RTD for Qt.
 *
 * @param key is unused
 * @param value register_rtd_t* representing dissetor RTD table
 * @param userdata is unused
 */
gboolean register_response_time_delay_tables(const void *key, void *value, void *userdata);

#endif // __RESPONSE_TIME_DELAY_DIALOG_H__
