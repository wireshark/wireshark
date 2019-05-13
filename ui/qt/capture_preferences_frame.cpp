/* capture_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture_globals.h"
#endif

#include "capture_preferences_frame.h"
#include <ui/qt/models/pref_models.h>
#include <ui_capture_preferences_frame.h>
#include "wireshark_application.h"

#include <QSpacerItem>

#include "ui/capture_ui_utils.h"
#include "ui/ws_ui_util.h"

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
    pref_no_interface_load_ = prefFromPrefPtr(&prefs.capture_no_interface_load);
    pref_no_extcap_ = prefFromPrefPtr(&prefs.capture_no_extcap);

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
    interface_t *device;
    QString default_device_string;

    if (prefs_get_string_value(pref_device_, pref_stashed)) {
        default_device_string = prefs_get_string_value(pref_device_, pref_stashed);
    }
    ui->defaultInterfaceComboBox->clear();
    if ((global_capture_opts.all_ifaces->len == 0) &&
        (prefs_get_bool_value(pref_no_interface_load_, pref_stashed) == FALSE)) {
        /*
         * No interfaces - try refreshing the local interfaces, to
         * see whether any have showed up (or privileges have changed
         * to allow us to access them).
         */
        wsApp->refreshLocalInterfaces();
    }
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);

        /* Continue if capture device is hidden */
        if (device->hidden) {
            continue;
        }
        // InterfaceTree matches against device->name when selecting the
        // default interface, so add it here if needed. On Windows this
        // means that we show the user a big ugly UUID-laden device path.
        // We might be able to work around that by passing device->name as
        // the userData argument to addItem instead.
        QString item_text = device->display_name;
        if (!item_text.contains(device->name)) {
            item_text.append(QString(" (%1)").arg(device->name));
        }
        ui->defaultInterfaceComboBox->addItem(item_text);
    }

    if (!default_device_string.isEmpty()) {
        ui->defaultInterfaceComboBox->setEditText(default_device_string);
    } else {
        ui->defaultInterfaceComboBox->clearEditText();
    }

    ui->capturePromModeCheckBox->setChecked(prefs_get_bool_value(pref_prom_mode_, pref_stashed));
    ui->capturePcapNgCheckBox->setChecked(prefs_get_bool_value(pref_pcap_ng_, pref_stashed));
    ui->captureRealTimeCheckBox->setChecked(prefs_get_bool_value(pref_real_time_, pref_stashed));
    ui->captureAutoScrollCheckBox->setChecked(prefs_get_bool_value(pref_auto_scroll_, pref_stashed));
#endif // HAVE_LIBPCAP
    ui->captureNoInterfaceLoad->setChecked(prefs_get_bool_value(pref_no_interface_load_, pref_stashed));
    ui->captureNoExtcapCheckBox->setChecked(prefs_get_bool_value(pref_no_extcap_, pref_stashed));
}

void CapturePreferencesFrame::on_defaultInterfaceComboBox_editTextChanged(const QString &new_iface)
{
    prefs_set_string_value(pref_device_, new_iface.toUtf8().constData(), pref_stashed);
}

void CapturePreferencesFrame::on_capturePromModeCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_prom_mode_, checked, pref_stashed);
}

void CapturePreferencesFrame::on_capturePcapNgCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_pcap_ng_, checked, pref_stashed);
}

void CapturePreferencesFrame::on_captureRealTimeCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_real_time_, checked, pref_stashed);
}

void CapturePreferencesFrame::on_captureAutoScrollCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_auto_scroll_, checked, pref_stashed);
}

void CapturePreferencesFrame::on_captureNoInterfaceLoad_toggled(bool checked)
{
    prefs_set_bool_value(pref_no_interface_load_, checked, pref_stashed);
}

void CapturePreferencesFrame::on_captureNoExtcapCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_no_extcap_, checked, pref_stashed);
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
