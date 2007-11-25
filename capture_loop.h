/* capture_loop.h
 * Do the low-level work of a capture
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


/** @file
 *
 *  Do the low-level work of a capture.
 *
 */

#ifndef __CAPTURE_LOOP_H__
#define __CAPTURE_LOOP_H__

/*
 * Get information about libpcap format from "wiretap/libpcap.h".
 * XXX - can we just use pcap_open_offline() to read the pipe?
 */
#include "wiretap/libpcap.h"

/** Do the low-level work of a capture.
 *  Returns TRUE if it succeeds, FALSE otherwise. */
extern int  capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats);

/** Stop a low-level capture (stops the capture child). */
extern void capture_loop_stop(void);


/*** the following is internal only (should be moved to capture_loop_int.h) ***/

#if !defined (__linux__)
#ifndef HAVE_PCAP_BREAKLOOP
/*
 * We don't have pcap_breakloop(), which is the only way to ensure that
 * pcap_dispatch(), pcap_loop(), or even pcap_next() or pcap_next_ex()
 * won't, if the call to read the next packet or batch of packets is
 * is interrupted by a signal on UN*X, just go back and try again to
 * read again.
 *
 * On UN*X, we catch SIGUSR1 as a "stop capturing" signal, and, in
 * the signal handler, set a flag to stop capturing; however, without
 * a guarantee of that sort, we can't guarantee that we'll stop capturing
 * if the read will be retried and won't time out if no packets arrive.
 *
 * Therefore, on at least some platforms, we work around the lack of
 * pcap_breakloop() by doing a select() on the pcap_t's file descriptor
 * to wait for packets to arrive, so that we're probably going to be
 * blocked in the select() when the signal arrives, and can just bail
 * out of the loop at that point.
 *
 * However, we don't want to that on BSD (because "select()" doesn't work
 * correctly on BPF devices on at least some releases of some flavors of
 * BSD), and we don't want to do it on Windows (because "select()" is
 * something for sockets, not for arbitrary handles).  (Note that "Windows"
 * here includes Cygwin; even in its pretend-it's-UNIX environment, we're
 * using WinPcap, not a UNIX libpcap.)
 *
 * Fortunately, we don't need to do it on BSD, because the libpcap timeout
 * on BSD times out even if no packets have arrived, so we'll eventually
 * exit pcap_dispatch() with an indication that no packets have arrived,
 * and will break out of the capture loop at that point.
 *
 * On Windows, we can't send a SIGUSR1 to stop capturing, so none of this
 * applies in any case.
 *
 * XXX - the various BSDs appear to define BSD in <sys/param.h>; we don't
 * want to include it if it's not present on this platform, however.
 */
# if !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__OpenBSD__) && \
    !defined(__bsdi__) && !defined(__APPLE__) && !defined(_WIN32) && \
    !defined(__CYGWIN__)
#  define MUST_DO_SELECT
# endif /* avoid select */
#endif /* HAVE_PCAP_BREAKLOOP */
#else /* linux */
/* whatever the deal with pcap_breakloop, linux doesn't support timeouts
 * in pcap_dispatch(); on the other hand, select() works just fine there.
 * Hence we use a select for that come what may.
 */
#define MUST_DO_SELECT
#endif

typedef void (*capture_packet_cb_fct)(u_char *, const struct pcap_pkthdr *, const u_char *);

/** init the capture filter */
typedef enum {
  INITFILTER_NO_ERROR,
  INITFILTER_BAD_FILTER,
  INITFILTER_OTHER_ERROR
} initfilter_status_t;

/*
 * Routines called by the capture loop code to report things.
 */

/** Report a new capture file having been opened. */
extern void
report_new_capture_file(const char *filename);

/** Report a number of new packets captured. */
extern void
report_packet_count(int packet_count);

/** Report the packet drops once the capture finishes. */
extern void
report_packet_drops(int drops);

/** Report an error in the capture. */
extern void
report_capture_error(const char *error_msg, const char *secondary_error_msg);

/** Report an error with a capture filter. */
extern void
report_cfilter_error(const char *cfilter, const char *errmsg);


#endif /* capture_loop.h */
