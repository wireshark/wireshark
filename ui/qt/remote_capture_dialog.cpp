/* remote_capture_dialog.cpp
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
#include <glib.h>
#include "qt_ui_utils.h"
#include "ui/capture_globals.h"
#include "remote_capture_dialog.h"
#include <ui_remote_capture_dialog.h>
#include "capture_opts.h"
#include "caputils/capture-pcap-util.h"
#include "ui/capture_ui_utils.h"
#include "epan/prefs.h"
#include "epan/to_str.h"
#include "ui/ui_util.h"
#include "ui/recent.h"

#include <QMessageBox>

static guint num_selected = 0;

RemoteCaptureDialog::RemoteCaptureDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RemoteCaptureDialog)
{
    ui->setupUi(this);

    fillComboBox();
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(apply_remote()));
    connect(this, SIGNAL(remoteAdded(GList *, remote_options*)), parent, SIGNAL(remoteAdded(GList *, remote_options*)));
    connect(ui->hostCombo, SIGNAL(currentIndexChanged(QString)), this, SLOT(hostChanged(QString)));
}

RemoteCaptureDialog::~RemoteCaptureDialog()
{
    delete ui;
}

void RemoteCaptureDialog::hostChanged(QString host)
{
    if (!host.compare(tr("Clear list"))) {
        free_remote_host_list();
        ui->hostCombo->clear();
    } else {
        struct remote_host *rh = recent_get_remote_host(host.toUtf8().constData());
        if (rh) {
            ui->portText->setText(QString(rh->remote_port));
            if (rh->auth_type == CAPTURE_AUTH_NULL) {
                ui->nullAuth->setChecked(true);
            } else {
                ui->pwAuth->setChecked(true);
            }
        }
    }

}

static void fillBox(gpointer key, gpointer, gpointer user_data)
{
    QComboBox *cb = (QComboBox *)user_data;
    cb->addItem(QString((gchar*)key));
}

void RemoteCaptureDialog::fillComboBox()
{
    GHashTable *ht = get_remote_host_list();
    ui->hostCombo->addItem(QString(""));
    if (g_hash_table_size(ht) > 0) {
        g_hash_table_foreach(ht, fillBox, ui->hostCombo);
        ui->hostCombo->insertSeparator(g_hash_table_size(ht)+1);
        ui->hostCombo->addItem(QString(tr("Clear list")));
    }
}

void RemoteCaptureDialog::apply_remote()
{
    int err;
    gchar *err_str;
    remote_options global_remote_opts;

    QString host = ui->hostCombo->currentText();
    global_remote_opts.src_type = CAPTURE_IFREMOTE;
    global_remote_opts.remote_host_opts.remote_host = qstring_strdup(host);
    QString port = ui->portText->text();
    global_remote_opts.remote_host_opts.remote_port = qstring_strdup(port);
    if (ui->pwAuth->isChecked()) {
        global_remote_opts.remote_host_opts.auth_type = CAPTURE_AUTH_PWD;
    } else {
        global_remote_opts.remote_host_opts.auth_type = CAPTURE_AUTH_NULL;
    }
    QString user = ui->userText->text();
    global_remote_opts.remote_host_opts.auth_username = qstring_strdup(user);
    QString pw = ui->pwText->text();
    global_remote_opts.remote_host_opts.auth_password = qstring_strdup(pw);
    global_remote_opts.remote_host_opts.datatx_udp  = FALSE;
    global_remote_opts.remote_host_opts.nocap_rpcap = TRUE;
    global_remote_opts.remote_host_opts.nocap_local = FALSE;
#ifdef HAVE_PCAP_SETSAMPLING
    global_remote_opts.sampling_method = CAPTURE_SAMP_NONE;
    global_remote_opts.sampling_param  = 0;
#endif

    GList *rlist = get_remote_interface_list(global_remote_opts.remote_host_opts.remote_host,
                                              global_remote_opts.remote_host_opts.remote_port,
                                              global_remote_opts.remote_host_opts.auth_type,
                                              global_remote_opts.remote_host_opts.auth_username,
                                              global_remote_opts.remote_host_opts.auth_password,
                                              &err, &err_str);
    if (rlist == NULL &&
        (err == CANT_GET_INTERFACE_LIST || err == DONT_HAVE_PCAP)) {
        QMessageBox::warning(this, tr("Error"),
                             (err == CANT_GET_INTERFACE_LIST?tr("No remote interfaces found."):tr("PCAP not found")));
        return;
    }
    if (ui->hostCombo->count() == 0) {
        ui->hostCombo->addItem("");
        ui->hostCombo->addItem(host);
        ui->hostCombo->insertSeparator(2);
        ui->hostCombo->addItem(QString(tr("Clear list")));
    } else {
        ui->hostCombo->insertItem(0, host);
    }
    struct remote_host *rh = recent_get_remote_host(host.toUtf8().constData());
    if (!rh) {
        rh = (struct remote_host *)g_malloc (sizeof (*rh));
        rh->r_host = qstring_strdup(host);
        rh->remote_port = qstring_strdup(port);
        rh->auth_type = global_remote_opts.remote_host_opts.auth_type;
        rh->auth_password = g_strdup("");
        rh->auth_username = g_strdup("");
        recent_add_remote_host(global_remote_opts.remote_host_opts.remote_host, rh);
    }
    emit remoteAdded(rlist, &global_remote_opts);
}

void RemoteCaptureDialog::on_pwAuth_toggled(bool checked)
{
    if (checked) {
        ui->userLabel->setEnabled(true);
        ui->userText->setEnabled(true);
        ui->pwLabel->setEnabled(true);
        ui->pwText->setEnabled(true);
    }
}

void RemoteCaptureDialog::on_nullAuth_toggled(bool checked)
{
    if (checked) {
        ui->userLabel->setEnabled(false);
        ui->userText->setEnabled(false);
        ui->pwLabel->setEnabled(false);
        ui->pwText->setEnabled(false);
    }
}
#endif /* HAVE_PCAP_REMOTE */

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
