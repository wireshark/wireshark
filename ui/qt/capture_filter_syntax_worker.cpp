/* capture_filter_syntax_worker.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#ifdef HAVE_LIBPCAP

#ifdef __MINGW32__
#include <_bsd_types.h>
#endif
#include <pcap.h>

#include "capture_opts.h"
#include "ui/capture_globals.h"
#endif
#include "extcap.h"

#include "capture_filter_syntax_worker.h"
#include <ui/qt/widgets/syntax_line_edit.h>

#include <QMutexLocker>
#include <QSet>

// We use a global mutex to protect pcap_compile since it calls gethostbyname.
// This probably isn't needed on Windows (where pcap_comple calls
// EnterCriticalSection + LeaveCriticalSection) or *BSD or macOS where
// gethostbyname(3) claims that it's thread safe.
static QMutex pcap_compile_mtx_;

#if 0
#include <QDebug>
#include <QThread>
#define DEBUG_SYNTAX_CHECK(state1, state2) qDebug() << "CF state" << QThread::currentThreadId() << state1 << "->" << state2 << ":" << filter
#define DEBUG_SLEEP_TIME 5000 // ms
#else
#define DEBUG_SYNTAX_CHECK(state1, state2)
#define DEBUG_SLEEP_TIME 0 // ms
#endif

#define DUMMY_SNAPLENGTH                65535
#define DUMMY_NETMASK                   0xFF000000

void CaptureFilterSyntaxWorker::checkFilter(const QString filter)
{
#ifdef HAVE_LIBPCAP
    QSet<int> active_dlts;
    QSet<unsigned> active_extcap;
    struct bpf_program fcode;
    pcap_t *pd;
    int pc_err;
    enum SyntaxLineEdit::SyntaxState state = SyntaxLineEdit::Valid;
    QString err_str;

    DEBUG_SYNTAX_CHECK("received", "?");

    if (global_capture_opts.num_selected < 1) {
        emit syntaxResult(filter, SyntaxLineEdit::Invalid, QString("No interfaces selected"));
        DEBUG_SYNTAX_CHECK("unknown", "no interfaces");
        return;
    }

    for (unsigned if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
        interface_t *device;

        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
        if (device->selected) {
            if (device->if_info.extcap == NULL || strlen(device->if_info.extcap) == 0) {
                if ((device->active_dlt >= DLT_USER0 && device->active_dlt <= DLT_USER15) || device->active_dlt == -1) {
                    // Capture filter for DLT_USER is unknown
                    state = SyntaxLineEdit::Deprecated;
                    err_str = "Unable to check capture filter";
                } else {
                    active_dlts.insert(device->active_dlt);
                }
            } else {
                active_extcap.insert(if_idx);
            }
        }
    }

    foreach(int dlt, active_dlts.values()) {
        pcap_compile_mtx_.lock();
        pd = pcap_open_dead(dlt, DUMMY_SNAPLENGTH);
        if (pd == NULL)
        {
            //don't have ability to verify capture filter
            break;
        }
#ifdef PCAP_NETMASK_UNKNOWN
        pc_err = pcap_compile(pd, &fcode, filter.toUtf8().data(), 1 /* Do optimize */, PCAP_NETMASK_UNKNOWN);
#else
        pc_err = pcap_compile(pd, &fcode, filter.toUtf8().data(), 1 /* Do optimize */, 0);
#endif

#if DEBUG_SLEEP_TIME > 0
        QThread::msleep(DEBUG_SLEEP_TIME);
#endif

        if (pc_err) {
            DEBUG_SYNTAX_CHECK("unknown", "known bad");
            state = SyntaxLineEdit::Invalid;
            err_str = pcap_geterr(pd);
        } else {
            DEBUG_SYNTAX_CHECK("unknown", "known good");
            pcap_freecode(&fcode);
        }
        pcap_close(pd);

        pcap_compile_mtx_.unlock();

        if (state == SyntaxLineEdit::Invalid) break;
    }
    // If it's already invalid, don't bother to check extcap
    if (state != SyntaxLineEdit::Invalid) {
        foreach(unsigned extcapif, active_extcap.values()) {
            interface_t *device;
            char *error = NULL;

            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, extcapif);
            extcap_filter_status status = extcap_verify_capture_filter(device->name, filter.toUtf8().constData(), &error);
            if (status == EXTCAP_FILTER_VALID) {
                DEBUG_SYNTAX_CHECK("unknown", "known good");
            } else if (status == EXTCAP_FILTER_INVALID) {
                DEBUG_SYNTAX_CHECK("unknown", "known bad");
                state = SyntaxLineEdit::Invalid;
                err_str = error;
                break;
            } else {
                state = SyntaxLineEdit::Deprecated;
                err_str = "Unable to check capture filter";
            }
            g_free(error);
        }
    }
    emit syntaxResult(filter, state, err_str);

    DEBUG_SYNTAX_CHECK("known", "idle");
#else
    emit syntaxResult(filter, SyntaxLineEdit::Deprecated, QString("Syntax checking unavailable"));
#endif // HAVE_LIBPCAP
}
