/* simple_statistics_dialog.h
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

#ifndef __SIMPLE_STATISTICS_DIALOG_H__
#define __SIMPLE_STATISTICS_DIALOG_H__

#include "tap_parameter_dialog.h"

struct _new_stat_data_t;

class SimpleStatisticsDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    SimpleStatisticsDialog(QWidget &parent, CaptureFile &cf, struct _stat_tap_table_ui *stu, const QString filter, int help_topic = 0);
    static TapParameterDialog *createSimpleStatisticsDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

protected:
    /** Add a simple statistics table.
     *
     * @param stat_data The table to add.
     */
    // gtk:service_response_table.h:init_srt_table
    void addMissingRows(struct _new_stat_data_t *stat_data);

private:
    struct _stat_tap_table_ui *stu_;

    // Callbacks for register_tap_listener
    static void tapReset(void *sd_ptr);
    static void tapDraw(void *sd_ptr);

    ~SimpleStatisticsDialog();

private slots:
    virtual void fillTree();

};

/** Register function to register dissectors that support a "simple" statistics table.
 *
 * @param data stat_tap_table_ui* representing dissetor stat table
 */
void register_simple_stat_tables(gpointer data, gpointer);

#endif // __SIMPLE_STATISTICS_DIALOG_H__

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
