/* capture-pcap-util.h
 * Utility definitions for packet capture
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CAPTURE_PCAP_UTIL_H__
#define __CAPTURE_PCAP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef HAVE_LIBPCAP

#include "wspcap.h"

#include "capture_opts.h"

/*
 * A snapshot length of 0 is useless - and libpcap/WinPcap/Npcap don't guarantee
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

/*
 * Error values.
 */
typedef enum {
    CAP_DEVICE_OPEN_NO_ERR,              /* No error */
    CAP_DEVICE_OPEN_ERR_PERMISSIONS,     /* Error is known to be a permissions error */
    CAP_DEVICE_OPEN_ERR_NOT_PERMISSIONS, /* Error is known not to be a permissions error */
    CAP_DEVICE_OPEN_ERR_GENERIC          /* Error is not known to be one or the other */
} cap_device_open_err;
extern if_capabilities_t *get_if_capabilities(interface_options *interface_opts,
    cap_device_open_err *err, char **err_str);
extern pcap_t *open_capture_device(capture_options *capture_opts,
    interface_options *interface_opts,
    int timeout, cap_device_open_err *open_err,
    char (*open_err_str)[PCAP_ERRBUF_SIZE]);

#endif /* HAVE_LIBPCAP */

extern void get_compiled_caplibs_version(GString *str);

/*
 * Append to a GString an indication of the version of capture libraries
 * with which we're running, or an indication that we're not running
 * with capture libraries, if we were compiled with WinPcap or Npcap but
 * WinPcap/Npcap wasn't loaded, or nothing, if we weren't compiled with
 * libpcap/WinPcap/Npcap.
 */
extern void get_runtime_caplibs_version(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_PCAP_UTIL_H__ */
