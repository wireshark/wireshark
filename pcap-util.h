/* pcap-util.h
 * Utility definitions for packet capture
 *
 * $Id: pcap-util.h,v 1.5 2003/10/10 06:05:48 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __PCAP_UTIL_H__
#define __PCAP_UTIL_H__

#ifdef HAVE_LIBPCAP

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int get_pcap_linktype(pcap_t *pch, char *devname);

#define MAX_WIN_IF_NAME_LEN 511

/*
 * The list of interfaces returned by "get_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char	*name;
	char	*description;
} if_info_t;

GList *get_interface_list(int *err, char *err_str);

/* Error values from "get_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	0	/* error getting list */
#define	NO_INTERFACES_FOUND	1	/* list is empty */

void free_interface_list(GList *if_list);

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

#endif /* __PCAP_UTIL_H__ */
