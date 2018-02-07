/* capture_info_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#ifndef CAPTURE_INFO_DIALOG_H
#define CAPTURE_INFO_DIALOG_H

#include <QDialog>

class CaptureInfoDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CaptureInfoDialog(QWidget *parent = 0);

signals:

public slots:

};

#endif // CAPTURE_INFO_DIALOG_H

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
