/* remote_capture_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// XXX This shouldn't exist. These controls should be in ManageInterfacesDialog instead.

#include "config.h"
#ifdef HAVE_PCAP_REMOTE
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include "ui/capture_globals.h"
#include "remote_capture_dialog.h"
#include <ui_remote_capture_dialog.h>
#include "capture_opts.h"
#include "capture/capture-pcap-util.h"
#include "ui/capture_ui_utils.h"
#include "epan/prefs.h"
#include "epan/to_str.h"
#include "ui/ws_ui_util.h"
#include "ui/recent.h"

#include <QMessageBox>

RemoteCaptureDialog::RemoteCaptureDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RemoteCaptureDialog)
{
    ui->setupUi(this);

    fillComboBox();
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(apply_remote()));
    connect(this, SIGNAL(remoteAdded(GList *, remote_options*)), parent, SIGNAL(remoteAdded(GList *, remote_options*)));
    connect(ui->hostCombo, &QComboBox::currentTextChanged, this, &RemoteCaptureDialog::hostChanged);
}

RemoteCaptureDialog::~RemoteCaptureDialog()
{
    delete ui;
}

void RemoteCaptureDialog::hostChanged(const QString host)
{
    if (!host.compare(tr("Clear list"))) {
        recent_free_remote_host_list();
        ui->hostCombo->clear();
    } else {
        const struct remote_host *rh = nullptr;
        int index = ui->hostCombo->findText(host);
        if (index != -1) {
            rh = VariantPointer<const struct remote_host>::asPtr(ui->hostCombo->itemData(index));
        }
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

static void fillBox(void *value, void *user_data)
{
    QComboBox *cb = (QComboBox *)user_data;
    struct remote_host* rh = (struct remote_host*)value;
    cb->addItem(QString((char*)rh->r_host), VariantPointer<const struct remote_host>::asQVariant(rh));
}

void RemoteCaptureDialog::fillComboBox()
{
    int remote_host_list_size;

    ui->hostCombo->addItem(QString(""));
    remote_host_list_size = recent_get_remote_host_list_size();
    if (remote_host_list_size > 0) {
        recent_remote_host_list_foreach(fillBox, ui->hostCombo);
        ui->hostCombo->insertSeparator(remote_host_list_size+1);
        ui->hostCombo->addItem(QString(tr("Clear list")));
    }
}

void RemoteCaptureDialog::apply_remote()
{
    int err;
    char *err_str;
    remote_options global_remote_opts;

    QString host = ui->hostCombo->currentText();
    if (host.isEmpty()) {
        return;
    }
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
    global_remote_opts.remote_host_opts.datatx_udp  = false;
    global_remote_opts.remote_host_opts.nocap_rpcap = true;
    global_remote_opts.remote_host_opts.nocap_local = false;
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
    if (rlist == NULL) {
        if (err == 0)
            QMessageBox::warning(this, tr("Error"), tr("No remote interfaces found."));
        else if (err == CANT_GET_INTERFACE_LIST)
            QMessageBox::critical(this, tr("Error"), err_str);
        else if (err == DONT_HAVE_PCAP)
            QMessageBox::critical(this, tr("Error"), tr("PCAP not found"));
        else
            QMessageBox::critical(this, tr("Error"), "Unknown error");
        return;
    }

    // Add the remote host even if it already exists, to update the port and
    // auth type and move it to the front.
    struct remote_host* rh;
    rh = (struct remote_host *)g_malloc (sizeof (*rh));
    rh->r_host = qstring_strdup(host);
    rh->remote_port = qstring_strdup(port);
    rh->auth_type = global_remote_opts.remote_host_opts.auth_type;
    rh->auth_password = g_strdup("");
    rh->auth_username = g_strdup("");
    recent_add_remote_host(global_remote_opts.remote_host_opts.remote_host, rh);

    // We don't need to add the new entry to hostCombo since we only call
    // this when accepting the dialog.

    // Tell the parent ManageInterfacesDialog we added this.
    // XXX: If the remote hostname already exists in ManageInterfacesDialog,
    // this doesn't remove it. Most of the time it won't, but there is the
    // corner case of a host existing with empty (hence default, 2002) port,
    // and then adding it a second time explicitly starting port 2002.
    // Someone could bind rpcapd to multiple ports on the same host for
    // some reason too, I suppose.
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
