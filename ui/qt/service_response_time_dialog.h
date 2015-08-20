/* service_response_time_dialog.h
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

#ifndef __SERVICE_RESPONSE_TIME_DIALOG_H__
#define __SERVICE_RESPONSE_TIME_DIALOG_H__

#include "tap_parameter_dialog.h"

struct register_srt;
struct _srt_stat_table;

class QTreeWidgetItem;

class ServiceResponseTimeDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    ServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, const QString filter, int help_topic = 0);
    static TapParameterDialog *createSrtDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

protected:
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

protected slots:
    virtual void fillTree();

private:
    // Callbacks for register_tap_listener
    static void tapReset(void *srtd_ptr);
    static void tapDraw(void *srtd_ptr);

    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const;
    virtual const QString filterExpression();

private slots:
    void statsTreeWidgetItemChanged();
};

/** Register function to register dissectors that support SRT.
 *
 * @param data register_srt_t* representing dissetor SRT table
 * @param user_data is unused
 */
void register_service_response_tables(gpointer data, gpointer user_data);

#endif // __SERVICE_RESPONSE_TIME_DIALOG_H__

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
