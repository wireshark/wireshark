/* response_time_delay_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

/** Register function to register dissectors that support RTD.
 *
 * @param data register_rtd_t* representing dissetor RTD table
 * @param user_data is unused
 */
void register_response_time_delay_tables(gpointer data, gpointer user_data);

#endif // __RESPONSE_TIME_DELAY_DIALOG_H__
