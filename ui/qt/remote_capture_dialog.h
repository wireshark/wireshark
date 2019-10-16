/* remote_capture_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef REMOTE_CAPTURE_DIALOG_H
#define REMOTE_CAPTURE_DIALOG_H

#include <config.h>

#ifdef HAVE_PCAP_REMOTE
#include <QDialog>
#include <glib.h>
#include "capture_opts.h"


namespace Ui {
class RemoteCaptureDialog;
}

class RemoteCaptureDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RemoteCaptureDialog(QWidget *parent = 0);
    ~RemoteCaptureDialog();

signals:
    void remoteAdded(GList *rlist, remote_options *roptions);

private slots:
    void on_pwAuth_toggled(bool checked);
    void on_nullAuth_toggled(bool checked);
    void apply_remote();
    void hostChanged(QString host);

private:
    Ui::RemoteCaptureDialog *ui;

    void fillComboBox();
};
#endif
#endif // REMOTE_CAPTURE_DIALOG_H

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
