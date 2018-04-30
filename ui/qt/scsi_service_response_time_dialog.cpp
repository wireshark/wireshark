/* scsi_service_response_time_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "scsi_service_response_time_dialog.h"

#include <algorithm>
#include <stdio.h>

#include <epan/srt_table.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-scsi.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>

ScsiServiceResponseTimeDialog::ScsiServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, const QString filter) :
    ServiceResponseTimeDialog(parent, cf, srt, filter)
{
    setRetapOnShow(false);
    setHint(tr("<small><i>Select a command and enter a filter if desired, then press Apply.</i></small>"));

    QHBoxLayout *filter_layout = filterLayout();
    command_combo_ = new QComboBox(this);

    filter_layout->insertStretch(0, 1);
    filter_layout->insertWidget(0, command_combo_);
    filter_layout->insertWidget(0, new QLabel(tr("Command:")));

    setWindowSubtitle(tr("SCSI Service Response Times"));

    QStringList commands;
    commands << "SBC (disk)" << "SSC (tape)" << "MMC (cd/dvd)" << "SMC (tape robot)" << "OSD (object based)";
    command_combo_->addItems(commands);
}

TapParameterDialog *ScsiServiceResponseTimeDialog::createScsiSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf)
{
    QString filter;
    bool have_args = false;
    QString command;

    // rpc,srt,scsi,command[,<filter>
    QStringList args_l = QString(opt_arg).split(',');
    if (args_l.length() > 0) {
        command = args_l[0];
        if (args_l.length() > 1) {
            filter = QStringList(args_l.mid(1)).join(",");
        }
        have_args = true;
    }

    ScsiServiceResponseTimeDialog *scsi_dlg =  new ScsiServiceResponseTimeDialog(parent, cf, get_srt_table_by_name("scsi"), filter);

    if (have_args) {
        if (!command.isEmpty()) {
            scsi_dlg->setScsiCommand(command.toInt());
        }
    }

    return scsi_dlg;
}

void ScsiServiceResponseTimeDialog::setScsiCommand(int command)
{
    command_combo_->setCurrentIndex(command);
    fillTree();
}

void ScsiServiceResponseTimeDialog::provideParameterData()
{
    char* err;
    QString command;

    command = QString(",%1").arg(command_combo_->currentIndex());

    scsistat_param(srt_, command.toStdString().c_str(), &err);
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
