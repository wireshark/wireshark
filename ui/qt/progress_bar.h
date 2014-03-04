/* progress_bar.h
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

#ifndef PROGRESS_BAR_H
#define PROGRESS_BAR_H

#include <glib.h>

#include "ui/progress_dlg.h"

#include <QProgressBar>

class ProgressBar;

// Define the structure describing a progress dialog.
struct progdlg {
    ProgressBar *progress_bar;       // This progress bar
    QWidget *top_level_window;	// Top-level window widget
};

class ProgressBar : public QProgressBar
{
    Q_OBJECT

public:
    explicit ProgressBar(QWidget *parent = 0);
    progdlg_t *show(bool animate, bool terminate_is_stop, gboolean *stop_flag, int value);

private:
    progdlg_t progress_dialog_;
    QString message_;
    QString status_;
    bool terminate_is_stop_;
    gboolean *stop_flag_;

public slots:

};

#endif // PROGRESS_BAR_H

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
