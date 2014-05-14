/* capture_filter_syntax_worker.cpp
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

#ifdef HAVE_LIBPCAP
#include <glib.h>
#include <pcap.h>
#include "capture_opts.h"
#include "ui/capture_globals.h"
#endif

#include "capture_filter_syntax_worker.h"

#include <QMutexLocker>
#include <QSet>

// Must be global
static QMutex pcap_compile_mtx_;

#if 0
#include <QDebug>
#include <QThread>
#define DEBUG_SYNTAX_CHECK(state1, state2) qDebug() << "CF state" << QThread::currentThreadId() << state1 << "->" << state2 << ":" << filter_text_ << ":" << filter
#else
#define DEBUG_SYNTAX_CHECK(state1, state2)
#endif

#define DUMMY_SNAPLENGTH                65535
#define DUMMY_NETMASK                   0xFF000000

void CaptureFilterSyntaxWorker::start() {
#ifdef HAVE_LIBPCAP
    forever {
        QString filter;
        QSet<gint> active_dlts;
        struct bpf_program fcode;
        pcap_t *pd;
        int pc_err;
        bool ok = true;
        QString err_str;

        data_mtx_.lock();
        while (filter_text_.isEmpty()) {
            data_cond_.wait(&data_mtx_);
        }

        DEBUG_SYNTAX_CHECK("pending", "unknown");
        filter = filter_text_;
        filter_text_ = QString();
        data_mtx_.unlock();

        if (global_capture_opts.num_selected < 1) {
            emit syntaxResult(filter, false, QString("No interfaces selected"));
            DEBUG_SYNTAX_CHECK("unknown", "no interfaces");
            continue;
        }

        for (guint if_idx = 0; if_idx < global_capture_opts.all_ifaces->len; if_idx++) {
            interface_t device;

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, if_idx);
            if (!device.locked && device.selected) {
                active_dlts.insert(device.active_dlt);
            }
        }

        foreach (gint dlt, active_dlts.toList()) {
            pcap_compile_mtx_.lock();
            pd = pcap_open_dead(dlt, DUMMY_SNAPLENGTH);
#ifdef PCAP_NETMASK_UNKNOWN
            pc_err = pcap_compile(pd, &fcode, filter.toUtf8().constData(), 1 /* Do optimize */, PCAP_NETMASK_UNKNOWN);
#else
            pc_err = pcap_compile(pd, &fcode, filter.toUtf8().constData(), 1 /* Do optimize */, 0);
#endif

            if (pc_err) {
                DEBUG_SYNTAX_CHECK("unknown", "known bad");
                ok = false;
                err_str = pcap_geterr(pd);
            } else {
                DEBUG_SYNTAX_CHECK("unknown", "known good");
            }
            pcap_close(pd);

            pcap_compile_mtx_.unlock();

            if (!ok) break;
        }
        emit syntaxResult(filter, ok, err_str);

        DEBUG_SYNTAX_CHECK("known", "idle");
    }
#endif // HAVE_LIBPCAP
}

void CaptureFilterSyntaxWorker::checkFilter(const QString &filter)
{
#ifdef HAVE_LIBPCAP
    QMutexLocker ml(&data_mtx_);
    /* Ruthlessly clobber the current state. */
    filter_text_ = filter;
    DEBUG_SYNTAX_CHECK("received", "?");
    data_cond_.wakeOne();
#else
    emit syntaxResult(filter, true, QString("Syntax checking unavailable"));
#endif // HAVE_LIBPCAP
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
