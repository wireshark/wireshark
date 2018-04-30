/* simple_statistics_dialog.h
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
    void addMissingRows(struct _stat_data_t *stat_data);

private:
    struct _stat_tap_table_ui *stu_;

    // Callbacks for register_tap_listener
    static void tapReset(void *sd_ptr);
    static void tapDraw(void *sd_ptr);

    // How each item (SimpleStatisticsTreeWidgetItem) will be exported
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *) const;

    ~SimpleStatisticsDialog();

private slots:
    virtual void fillTree();

};

/** Register function to register dissectors that support a "simple" statistics table.
 *
 * @param key is tap string
 * @param value stat_tap_table_ui* representing dissetor stat table
 */
gboolean register_simple_stat_tables(const void *key, void *value, void*);

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
