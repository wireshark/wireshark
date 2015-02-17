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

/*
 * @file General dialog base class
 *
 * Base class which provides convenience methods for dialogs that handle
 * capture files. "General" is a misnomer but we already have a class named
 * "CaptureFileDialog".
 */

#include "config.h"

#include <glib.h>

#include "wireshark_dialog.h"

#include "wireshark_application.h"

// To do:
// - Use a dynamic property + Q_PROPERTY for the subtitle.
// - Save and load recent geometry.

WiresharkDialog::WiresharkDialog(QWidget &, CaptureFile &capture_file) :
    QDialog(NULL, Qt::Window),
    cap_file_(capture_file),
    file_closed_(false)
{
    setWindowIcon(wsApp->normalIcon());
    connect(&cap_file_, SIGNAL(captureFileClosing()), this, SLOT(captureFileClosing()));
    connect(&cap_file_, SIGNAL(captureFileClosed()), this, SLOT(captureFileClosing()));
    setWindowTitleFromSubtitle();
}

void WiresharkDialog::setWindowSubtitle(const QString &subtitle)
{
    subtitle_ = subtitle;
    setWindowTitleFromSubtitle();
}

void WiresharkDialog::setWindowTitleFromSubtitle()
{
    QString title = wsApp->windowTitleString(QStringList() << subtitle_ << cap_file_.fileTitle());
    QDialog::setWindowTitle(title);
}

void WiresharkDialog::updateWidgets()
{
    setWindowTitleFromSubtitle();
}

void WiresharkDialog::captureFileClosing()
{
    file_closed_ = true;
    setWindowTitleFromSubtitle();
    updateWidgets();
}

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
