/* capture_file_dialog.h
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef CAPTURE_FILE_DIALOG_H
#define CAPTURE_FILE_DIALOG_H

#include <QFileDialog>

class CaptureFileDialog : public QFileDialog
{
    // The GTK+ Open Capture File dialog has the following elements and features:
    //   - The ability to select a capture file from a list of known extensions
    //   - A display filter entry
    //   - Name resolution checkboxes
    //   - Capture file preview information
    // Ideally we should provide similar functionality here.
    //
    // You can subclass QFileDialog (which we've done here) and add widgets as
    // described at
    // http://developer.qt.nokia.com/faq/answer/how_can_i_add_widgets_to_my_qfiledialog_instance
    // However, Qt's idea of what a file dialog looks like isn't what Microsoft
    // and Apple think a file dialog looks like.
    //
    // On Windows Vista and later we should probably use IFileOpenDialog. On earlier
    // versions of Windows (including XP) we should use GetOpenFileName, which is
    // what we do in ui/win32/file_dlg_win32.c. On OS X we should use NSOpenPanel. On
    // other platforms we should fall back to QFileDialog.
    //
    // Yes, that's four implementations of the same window.
    //
    // If a plain native open file dialog is good enough we can just the static
    // version of QFileDialog::getOpenFileName. (Commenting out Q_OBJECT below
    // has the same effect.)

    Q_OBJECT
public:
    CaptureFileDialog(QWidget *parent = 0);

signals:

public slots:

};

#endif // CAPTURE_FILE_DIALOG_H
