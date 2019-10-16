/* scsi_service_response_time_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SCSI_SERVICE_RESPONSE_TIME_DIALOG_H__
#define __SCSI_SERVICE_RESPONSE_TIME_DIALOG_H__

#include "service_response_time_dialog.h"

class QComboBox;

class ScsiServiceResponseTimeDialog : public ServiceResponseTimeDialog
{
    Q_OBJECT

public:

    ScsiServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, const QString filter);
    static TapParameterDialog *createScsiSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf);

    void setScsiCommand(int command);

protected:
    virtual void provideParameterData();

private:
    QComboBox *command_combo_;
};

#endif // __SCSI_SERVICE_RESPONSE_TIME_DIALOG_H__

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
