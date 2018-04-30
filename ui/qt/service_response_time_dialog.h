/* service_response_time_dialog.h
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

class ServiceResponseTimeDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    ServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, const QString filter, int help_topic = 0);
    ~ServiceResponseTimeDialog();
    static TapParameterDialog *createSrtDialog(QWidget &parent, const QString cfg_str, const QString filter, CaptureFile &cf);

public slots:
    void endRetapPackets();

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


    virtual void provideParameterData() {}

protected slots:
    void fillTree();

private:
    // Callbacks for register_tap_listener
    static void tapReset(void *srtd_ptr);
    static void tapDraw(void *srtd_ptr);

    virtual QList<QVariant> treeItemData(QTreeWidgetItem *ti) const;
    virtual const QString filterExpression();

    srt_data_t srt_data_;

private slots:
    void statsTreeWidgetItemChanged();
};

/** Register function to register dissectors that support SRT.
 *
 * @param key is unused
 * @param value register_srt_t* representing dissetor SRT table
 * @param userdata is unused
 */
gboolean register_service_response_tables(const void *key, void *value, void *userdata);

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
