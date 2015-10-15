/* time_shift_dialog.h
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

#ifndef TIME_SHIFT_DIALOG_H
#define TIME_SHIFT_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"

#include "syntax_line_edit.h"

#include <QDialog>
#include <QPushButton>

namespace Ui {
class TimeShiftDialog;
}

class TimeShiftDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TimeShiftDialog(QWidget *parent = 0, capture_file *cf = NULL);
    ~TimeShiftDialog();

public slots:
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

signals:
    void timeShifted();

private:
    Ui::TimeShiftDialog *ts_ui_;
    capture_file *cap_file_;
    QPushButton *apply_button_;
    QString syntax_err_;

    void enableWidgets();
    void checkFrameNumber(SyntaxLineEdit &frame_le);
    void checkDateTime(SyntaxLineEdit &time_le);

private slots:
    void on_shiftAllButton_toggled(bool checked);
    void on_setOneButton_toggled(bool checked);
    void on_unshiftAllButton_toggled(bool checked);
    void on_setTwoCheckBox_toggled(bool checked);
    void on_shiftAllTimeLineEdit_textChanged(const QString &sa_text);
    void on_setOneTimeLineEdit_textChanged(const QString &so_text);
    void on_setOneFrameLineEdit_textChanged(const QString &frame_text);
    void on_setTwoFrameLineEdit_textChanged(const QString &frame_text);
    void on_setTwoTimeLineEdit_textChanged(const QString &st_text);
    void applyTimeShift();
    void on_buttonBox_helpRequested();
};

#endif // TIME_SHIFT_DIALOG_H
