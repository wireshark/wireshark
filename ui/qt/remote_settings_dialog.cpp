/* remote_settings_dialog.cpp
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

// XXX This shouldn't exist. These controls should be in ManageInterfacesDialog instead.

#include "config.h"
#ifdef HAVE_PCAP_REMOTE
#include "remote_settings_dialog.h"
#include <ui_remote_settings_dialog.h>

RemoteSettingsDialog::RemoteSettingsDialog(QWidget *parent, interface_t *iface) :
    QDialog(parent),
    ui(new Ui::RemoteSettingsDialog)
{
    ui->setupUi(this);
    mydevice.name = g_strdup(iface->name);
    ui->rpcapBox->setCheckState(iface->remote_opts.remote_host_opts.nocap_rpcap?Qt::Checked:Qt::Unchecked);
    ui->udpBox->setCheckState(iface->remote_opts.remote_host_opts.datatx_udp?Qt::Checked:Qt::Unchecked);
#ifdef HAVE_PCAP_SETSAMPLING
    switch (iface->remote_opts.sampling_method)
    {
    case CAPTURE_SAMP_NONE:
        ui->sampleNone->setChecked(true);
        break;
    case CAPTURE_SAMP_BY_COUNT:
        ui->samplePkt->setChecked(true);
        ui->spinPkt->setValue(iface->remote_opts.sampling_param);
        break;
    case CAPTURE_SAMP_BY_TIMER:
        ui->sampleTime->setChecked(true);
        ui->spinTime->setValue(iface->remote_opts.sampling_param);
        break;
    }
#else
    ui->sampleLabel->setVisible(false);
    ui->sampleNone->setVisible(false);
    ui->samplePkt->setVisible(false);
    ui->sampleTime->setVisible(false);
    ui->spinPkt->setVisible(false);
    ui->spinTime->setVisible(false);
    ui->pktLabel->setVisible(false);
    ui->timeLabel->setVisible(false);
    resize(width(), height() - ui->sampleLabel->height() - 3 * ui->sampleNone->height());
#endif
    connect(this, SIGNAL(remoteSettingsChanged(interface_t *)), parent, SIGNAL(remoteSettingsChanged(interface_t *)));
}

RemoteSettingsDialog::~RemoteSettingsDialog()
{
    delete ui;
}

void RemoteSettingsDialog::on_buttonBox_accepted()
{
    mydevice.remote_opts.remote_host_opts.nocap_rpcap = (ui->rpcapBox->checkState()==Qt::Checked)?true:false;
    mydevice.remote_opts.remote_host_opts.datatx_udp = (ui->udpBox->checkState()==Qt::Checked)?true:false;
#ifdef HAVE_PCAP_SETSAMPLING
    if (ui->sampleNone->isChecked()) {
        mydevice.remote_opts.sampling_method = CAPTURE_SAMP_NONE;
        mydevice.remote_opts.sampling_param = 0;
    } else if (ui->samplePkt->isChecked()) {
        mydevice.remote_opts.sampling_method = CAPTURE_SAMP_BY_COUNT;
        mydevice.remote_opts.sampling_param = ui->spinPkt->value();
    } else {
        mydevice.remote_opts.sampling_method = CAPTURE_SAMP_BY_TIMER;
        mydevice.remote_opts.sampling_param = ui->spinTime->value();
    }
#endif
    emit remoteSettingsChanged(&mydevice);
}
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
