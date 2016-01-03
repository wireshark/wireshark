/* funnel_statistics.cpp
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

#ifndef FUNNELSTATISTICS_H
#define FUNNELSTATISTICS_H

#include <QObject>

#include "capture_file.h"

#include "funnel_text_dialog.h"

struct _funnel_ops_t;
struct _funnel_progress_window_t;
struct progdlg;

class FunnelStatistics : public QObject
{
    Q_OBJECT
public:
    explicit FunnelStatistics(QObject *parent, CaptureFile &cf);
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
    void setDisplayFilter(const QString filter);
    void applyDisplayFilter();
    void openCaptureFile(QString cf_path, QString filter);

public slots:
    void funnelActionTriggered();
    void displayFilterTextChanged(const QString &filter);

private:
    static const QString action_name_;
    struct _funnel_ops_t *funnel_ops_;
    CaptureFile &capture_file_;
    QByteArray display_filter_;
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
