/* summary_dialog.h
 *
 * GSoC 2013 - QtShark
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

#ifndef SUMMARY_DIALOG_H
#define SUMMARY_DIALOG_H

#include "config.h"

#include <string.h>
#include <time.h>

#include "qt_ui_utils.h"

#include <epan/strutil.h>
#include <wiretap/wtap.h>

#include "globals.h"
#include "file.h"
#include "summary.h"

#ifdef HAVE_LIBPCAP
    #include "capture.h"
    #include "ui/capture_globals.h"
    #include "capture-pcap-util.h"
#endif

#include <QDialog>
#include <QClipboard>

namespace Ui {
class SummaryDialog;
}

class SummaryDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SummaryDialog(QWidget *parent = 0);
    ~SummaryDialog();


    QString TimeToString(time_t ti_time);
    void UpdateValues();
    QString SummaryToString();

signals:
    void captureCommentChanged();


protected slots:
    void RefreshData();
    void SaveComment();
    void HelpButton();
    void CopyComment();
    void on_tabWidget_currentChanged(int index);


private:
    Ui::SummaryDialog   *ui;

    QPushButton     *bRefresh;
    QPushButton     *bCopyComment;

    summary_tally       summary_;
};

#endif

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
