/* capture_filter_validator.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/capture_filter_validator.h>

#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>
#include "ui/capture_opts.h"
#include "ui/capture_globals.h"
#endif
#include "extcap.h"

#include <QSet>

// A non-empty token reported on Acceptable input that the BPF backend could not
// definitively verify; the host maps Acceptable + this to the Deprecated state.
static const QString unverifiable_token_ = QStringLiteral("\x01unverifiable");

#define DUMMY_SNAPLENGTH 65535

CaptureFilterValidator::CaptureFilterValidator(QObject *parent) :
    FilterValidator(parent)
{
}

QValidator::State CaptureFilterValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);
    detail_ = Detail();

#ifdef HAVE_LIBPCAP
    const QString filter = input;
    if (filter.isEmpty())
        return QValidator::Acceptable;

    if (global_capture_opts.num_selected < 1) {
        detail_.errMsg = tr("No interfaces selected");
        return QValidator::Invalid;
    }

    QSet<int> active_dlts;
    QSet<unsigned> active_extcap;
    bool unverifiable = false;
    QString unverifiable_msg;

    for (unsigned if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
        if (!device->selected)
            continue;
        if (device->if_info.extcap == NULL || strlen(device->if_info.extcap) == 0) {
            if ((device->active_dlt >= DLT_USER0 && device->active_dlt <= DLT_USER15) ||
                device->active_dlt == -1) {
                // Capture filter for DLT_USER is unknown — cannot verify.
                unverifiable = true;
                unverifiable_msg = tr("Unable to check capture filter");
            } else {
                active_dlts.insert(device->active_dlt);
            }
        } else {
            active_extcap.insert(if_idx);
        }
    }

    const QByteArray filter_utf8 = filter.toUtf8();

    foreach (int dlt, active_dlts.values()) {
        pcap_t *pd = pcap_open_dead(dlt, DUMMY_SNAPLENGTH);
        if (pd == NULL)
            break; // no ability to verify

        struct bpf_program fcode;
#ifdef PCAP_NETMASK_UNKNOWN
        int pc_err = pcap_compile(pd, &fcode, filter_utf8.constData(), 1 /* optimize */, PCAP_NETMASK_UNKNOWN);
#else
        int pc_err = pcap_compile(pd, &fcode, filter_utf8.constData(), 1 /* optimize */, 0);
#endif
        if (pc_err) {
            const char *err_s = pcap_geterr(pd);
            // Some filters are rejected on a dead handle but valid on a live
            // capture (BPF extensions: ifindex/inbound/outbound).
            if (strstr(err_s, "when reading savefiles") /* libpcap >= 1.3.0 */ ||
                strstr(err_s, "not a live capture") /* libpcap >= 1.11.0 */) {
                unverifiable = true;
                unverifiable_msg = tr("Unable to check capture filter (BPF extensions require a live handle)");
            } else {
                detail_.errMsg = QString::fromUtf8(err_s);
                pcap_close(pd);
                return QValidator::Invalid;
            }
        } else {
            pcap_freecode(&fcode);
        }
        pcap_close(pd);
    }

    foreach (unsigned extcapif, active_extcap.values()) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, extcapif);
        char *error = NULL;
        extcap_filter_status status = extcap_verify_capture_filter(device->name, filter_utf8.constData(), &error);
        if (status == EXTCAP_FILTER_INVALID) {
            detail_.errMsg = QString::fromUtf8(error);
            g_free(error);
            return QValidator::Invalid;
        } else if (status != EXTCAP_FILTER_VALID) {
            unverifiable = true;
            unverifiable_msg = tr("Unable to check capture filter");
        }
        g_free(error);
    }

    if (unverifiable) {
        detail_.errMsg = unverifiable_msg;
        detail_.deprecatedToken = unverifiable_token_;
    }
    return QValidator::Acceptable;
#else // !HAVE_LIBPCAP
    Q_UNUSED(input);
    detail_.errMsg = tr("Syntax checking unavailable");
    detail_.deprecatedToken = unverifiable_token_;
    return QValidator::Acceptable;
#endif // HAVE_LIBPCAP
}
