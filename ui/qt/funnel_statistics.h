/* funnel_statistics.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FUNNELSTATISTICS_H
#define FUNNELSTATISTICS_H

#include <QObject>

#include "capture_file.h"
#include "funnel_text_dialog.h"
#include <ui/qt/filter_action.h>

struct _funnel_ops_t;
struct _funnel_progress_window_t;
struct progdlg;

class FunnelStatistics : public QObject
{
    Q_OBJECT
public:
    explicit FunnelStatistics(QObject *parent, CaptureFile &cf);
    ~FunnelStatistics();
    void retapPackets();
    struct progdlg *progressDialogNew(const gchar *task_title, const gchar *item_title, gboolean terminate_is_stop, gboolean *stop_flag);
    const char *displayFilter();
    void emitSetDisplayFilter(const QString filter);
    void reloadPackets();
    void reloadLuaPlugins();
    void emitApplyDisplayFilter();
    void emitOpenCaptureFile(QString cf_path, QString filter);
    static const QString &actionName() { return action_name_; }

signals:
    void openCaptureFile(QString cf_path, QString filter);
    void setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType);

public slots:
    void funnelActionTriggered();
    void displayFilterTextChanged(const QString &filter);

private:
    static const QString action_name_;
    struct _funnel_ops_t *funnel_ops_;
    struct _funnel_ops_id_t *funnel_ops_id_;

    CaptureFile &capture_file_;
    QByteArray display_filter_;
    QString prepared_filter_;
};

extern "C" {
    void funnel_statistics_reload_menus(void);
} // extern "C"

#endif // FUNNELSTATISTICS_H

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
