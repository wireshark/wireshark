/* capture_file_properties_dialog.h
 *
 * GSoC 2013 - QtShark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILE_PROPERTIES_DIALOG_H
#define CAPTURE_FILE_PROPERTIES_DIALOG_H

#include <config.h>

#include <glib.h>

#include <string.h>
#include <time.h>

#include <epan/strutil.h>
#include <wiretap/wtap.h>

#include "file.h"

#ifdef HAVE_LIBPCAP
    #include "ui/capture.h"
    #include "ui/capture_globals.h"
#endif

#include "wireshark_dialog.h"

#include <QClipboard>

namespace Ui {
class CaptureFilePropertiesDialog;
}

class QAbstractButton;

class CaptureFilePropertiesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit CaptureFilePropertiesDialog(QWidget &parent, CaptureFile& capture_file);
    ~CaptureFilePropertiesDialog();

signals:
    void captureCommentChanged();

protected slots:
    void changeEvent(QEvent* event);


private:
    Ui::CaptureFilePropertiesDialog *ui;

    QString summaryToHtml();
    void fillDetails();

private slots:
    void updateWidgets();
    void on_buttonBox_helpRequested();
    void on_buttonBox_accepted();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_rejected();
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
