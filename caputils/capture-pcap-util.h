/* capture-pcap-util.h
 * Utility definitions for packet capture
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

#ifndef __CAPTURE_PCAP_UTIL_H__
#define __CAPTURE_PCAP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_LIBPCAP

#include <pcap.h>

#include "capture_opts.h"

/*
 * A snapshot length of 0 is useless - and libpcap/WinPcap don't guarantee
 * that a snapshot length of 0 will work, and, on some platforms, it won't
 * (with BPF, for example, the kernel is told the snapshot length via the
 * return value of the BPF program, and a return value of 0 means "drop
 * the packet"), so the minimum packet size is 1 byte.
 */
#define MIN_PACKET_SIZE 1	/* minimum amount of packet data we can read */

GList *get_interface_list(int *err, char **err_str);
#ifdef HAVE_PCAP_REMOTE
GList *get_remote_interface_list(const char *hostname, const char *port,
                                 int auth_type, const char *username,
                                 const char *passwd, int *err, char **err_str);
#endif /* HAVE_PCAP_REMOTE */

const char *linktype_val_to_name(int dlt);
int linktype_name_to_val(const char *linktype);

int get_pcap_datalink(pcap_t *pch, const char *devicename);

gboolean set_pcap_datalink(pcap_t *pcap_h, int datalink, char *name,
    char *errmsg, size_t errmsg_len,
    char *secondary_errmsg, size_t secondary_errmsg_len);

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
/*
 * Return TRUE if the pcap_t in question is set up for high-precision
 * time stamps, FALSE otherwise.
 */
gboolean have_high_resolution_timestamp(pcap_t *pcap_h);
#endif /* HAVE_PCAP_SET_TSTAMP_PRECISION */

extern if_capabilities_t *get_if_capabilities(interface_options *interface_opts,
    char **err_str);
extern pcap_t *open_capture_device(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    char (*open_err_str)[PCAP_ERRBUF_SIZE]);

#endif /* HAVE_LIBPCAP */

extern void get_compiled_caplibs_version(GString *str);

/*
 * Append to a GString an indication of the version of capture libraries
 * with which we're running, or an indication that we're not running
 * with capture libraries, if we were compiled with WinPcap but
 * WinPcap wasn't loaded, or nothing, if we weren't compiled with
 * libpcap/WinPcap.
 */
extern void get_runtime_caplibs_version(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_PCAP_UTIL_H__ */
