/* capture_preferences_frame.cpp
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

#include "config.h"

#include <glib.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture_globals.h"
#endif

#include "capture_preferences_frame.h"
#include <ui_capture_preferences_frame.h>
#include "wireshark_application.h"

#include <QSpacerItem>

#include "ui/capture_ui_utils.h"
#include "ui/ui_util.h"

#include <epan/prefs-int.h>

CapturePreferencesFrame::CapturePreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::CapturePreferencesFrame)
{
    ui->setupUi(this);

    pref_device_ = prefFromPrefPtr(&prefs.capture_device);
    pref_prom_mode_ = prefFromPrefPtr(&prefs.capture_prom_mode);
    pref_pcap_ng_ = prefFromPrefPtr(&prefs.capture_pcap_ng);
    pref_real_time_ = prefFromPrefPtr(&prefs.capture_real_time);
    pref_auto_scroll_ = prefFromPrefPtr(&prefs.capture_auto_scroll);

    // Setting the left margin via a style sheet clobbers its
    // appearance.
    int margin = style()->pixelMetric(QStyle::PM_LayoutLeftMargin);
    QRect geom = ui->defaultInterfaceSpacer->geometry();
    geom.setWidth(margin);
    ui->defaultInterfaceSpacer->setGeometry(geom);
}

CapturePreferencesFrame::~CapturePreferencesFrame()
{
    delete ui;
}

void CapturePreferencesFrame::showEvent(QShowEvent *)
{
    updateWidgets();
}

void CapturePreferencesFrame::updateWidgets()
{
#ifdef HAVE_LIBPCAP
    interface_t device;
    QString default_device_string;

    if (pref_device_->stashed_val.string) {
        default_device_string = pref_device_->stashed_val.string;
    }
    ui->defaultInterfaceComboBox->clear();
    if (global_capture_opts.all_ifaces->len == 0) {
        /*
         * No interfaces - try refreshing the local interfaces, to
         * see whether any have showed up (or privileges have changed
         * to allow us to access them).
         */
        wsApp->refreshLocalInterfaces();
    }
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

        /* Continue if capture device is hidden */
        if (device.hidden) {
            continue;
        }
        // InterfaceTree matches against device.name when selecting the
        // default interface, so add it here if needed. On Windows this
        // means that we show the user a big ugly UUID-laden device path.
        // We might be able to work around that by passing device.name as
        // the userData argument to addItem instead.
        QString item_text = device.display_name;
        if (!item_text.contains(device.name)) {
            item_text.append(QString(" (%1)").arg(device.name));
        }
        ui->defaultInterfaceComboBox->addItem(item_text);
    }

    if (!default_device_string.isEmpty()) {
        ui->defaultInterfaceComboBox->setEditText(default_device_string);
    } else {
        ui->defaultInterfaceComboBox->clearEditText();
    }

    ui->capturePromModeCheckBox->setChecked(pref_prom_mode_->stashed_val.boolval);
    ui->capturePcapNgCheckBox->setChecked(pref_pcap_ng_->stashed_val.boolval);
    ui->captureRealTimeCheckBox->setChecked(pref_real_time_->stashed_val.boolval);
    ui->captureAutoScrollCheckBox->setChecked(pref_auto_scroll_->stashed_val.boolval);
#endif // HAVE_LIBPCAP
}

void CapturePreferencesFrame::on_defaultInterfaceComboBox_editTextChanged(const QString &new_iface)
{
    g_free((void *)pref_device_->stashed_val.string);
    pref_device_->stashed_val.string = g_strdup(new_iface.toUtf8().constData());
}

void CapturePreferencesFrame::on_capturePromModeCheckBox_toggled(bool checked)
{
    pref_prom_mode_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_capturePcapNgCheckBox_toggled(bool checked)
{
    pref_pcap_ng_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_captureRealTimeCheckBox_toggled(bool checked)
{
    pref_real_time_->stashed_val.boolval = checked;
}

void CapturePreferencesFrame::on_captureAutoScrollCheckBox_toggled(bool checked)
{
    pref_auto_scroll_->stashed_val.boolval = checked;
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
