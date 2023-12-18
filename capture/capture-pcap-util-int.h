/** @file
 *
 * Definitions of routines internal to the libpcap/WinPcap/Npcap utilities
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PCAP_UTIL_INT_H__
#define __PCAP_UTIL_INT_H__

extern if_info_t *if_info_new(const char *name, const char *description,
	bool loopback);
extern void if_info_add_address(if_info_t *if_info, struct sockaddr *addr);
#ifdef HAVE_PCAP_REMOTE
extern GList *get_interface_list_findalldevs_ex(const char *hostname,
    const char *port, int auth_type, const char *username, const char *passwd,
    int *err, char **err_str);
#endif /* HAVE_PCAP_REMOTE */
extern GList *get_interface_list_findalldevs(int *err, char **err_str);

extern if_capabilities_t *get_if_capabilities_local(interface_options *interface_opts,
    cap_device_open_status *status, char **status_str);
extern pcap_t *open_capture_device_local(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE]);
#ifdef HAVE_PCAP_CREATE
extern if_capabilities_t *get_if_capabilities_pcap_create(interface_options *interface_opts,
    cap_device_open_status *status, char **status_str);
extern pcap_t *open_capture_device_pcap_create(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE]);
#endif /* HAVE_PCAP_CREATE */
extern if_capabilities_t *get_if_capabilities_pcap_open_live(interface_options *interface_opts,
    cap_device_open_status *status, char **status_str);
extern pcap_t *open_capture_device_pcap_open_live(interface_options *interface_opts,
    int timeout, cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE]);

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_interface_list()".  This is used to let the error message string
 * be platform-dependent.
 */
extern char *cant_get_if_list_error_message(const char *err_str);

/*
 * Get a longer, secondary error message corrresponding to why getting
 * capabilities or opening a device failed. This is used to let the error
 * message string be platform-dependent.
 */
extern const char *get_pcap_failure_secondary_error_message(cap_device_open_status open_status,
    const char *open_status_str);

#endif /* __PCAP_UTIL_INT_H__ */
