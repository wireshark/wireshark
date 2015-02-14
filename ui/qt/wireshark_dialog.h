/* wireshark_dialog.cpp
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

#ifndef WIRESHARK_DIALOG_H
#define WIRESHARK_DIALOG_H

#include "capture_file.h"

#include <QDialog>

class WiresharkDialog : public QDialog
{
    Q_OBJECT

public:
    // XXX Unlike the entire QWidget API, parent is mandatory here.
    explicit WiresharkDialog(QWidget &, CaptureFile &capture_file);

signals:

public slots:

protected:
    virtual void keyPressEvent(QKeyEvent *event) { QDialog::keyPressEvent(event); }
    void setWindowSubtitle(const QString &subtitle);
    virtual void updateWidgets();

    CaptureFile &cap_file_;
    bool file_closed_;

protected slots:
    virtual void captureFileClosing();

private:
    const QString &windowSubtitle() { return subtitle_; }
    void setWindowTitleFromSubtitle();

    QString subtitle_;

private slots:
};

#endif // WIRESHARK_DIALOG_H

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
