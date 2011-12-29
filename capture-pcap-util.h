/* capture-pcap-util.h
 * Utility definitions for packet capture
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

#ifndef __CAPTURE_PCAP_UTIL_H__
#define __CAPTURE_PCAP_UTIL_H__

#ifdef HAVE_LIBPCAP

#include <pcap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
#endif

const char *linktype_val_to_name(int dlt);
int linktype_name_to_val(const char *linktype);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HAVE_LIBPCAP */

/*
 * Append to a GString an indication of the version of libpcap/WinPcap
 * with which we were compiled, if we were, or an indication that we
 * weren't compiled with libpcap/WinPcap, if we weren't.
 */
extern void get_compiled_pcap_version(GString *str);

/*
 * Append to a GString an indication of the version of libpcap/WinPcap
 * with which we're running, or an indication that we're not running
 * with libpcap/WinPcap, if we were compiled with libpcap/WinPcap,
 * or nothing, if we weren't compiled with libpcap/WinPcap.
 */
extern void get_runtime_pcap_version(GString *str);

#endif /* __CAPTURE_PCAP_UTIL_H__ */
