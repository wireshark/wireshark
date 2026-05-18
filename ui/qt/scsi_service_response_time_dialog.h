/** @file
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

/**
 * @brief Dialog for displaying SCSI Service Response Time (SRT) statistics.
 */
class ScsiServiceResponseTimeDialog : public ServiceResponseTimeDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ScsiServiceResponseTimeDialog object.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param srt Pointer to the registered SRT structure.
     * @param filter The display filter to apply.
     */
    ScsiServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, const QString filter);

    /**
     * @brief Factory method to create a SCSI SRT dialog.
     * @param parent The parent widget.
     * @param opt_arg Optional arguments passed to the dialog.
     * @param cf The capture file.
     * @return A pointer to the created TapParameterDialog.
     */
    static TapParameterDialog *createScsiSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf);

    /**
     * @brief Sets the active SCSI command to display statistics for.
     * @param command The SCSI command index or code.
     */
    void setScsiCommand(int command);

protected:
    /**
     * @brief Provides parameter data for the service response time dialog.
     */
    virtual void provideParameterData();

private:
    /** @brief Combo box for selecting the SCSI command. */
    QComboBox *command_combo_;
};

#endif // __SCSI_SERVICE_RESPONSE_TIME_DIALOG_H__
