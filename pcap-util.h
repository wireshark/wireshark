/* pcap-util.h
 * Utility definitions for packet capture
 *
 * $Id: pcap-util.h,v 1.1 2001/11/09 07:44:48 guy Exp $
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

GList *get_interface_list(int *err, char *err_str);

/* Error values from "get_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	0	/* error getting list */
#define	NO_INTERFACES_FOUND	1	/* list is empty */

void free_interface_list(GList *if_list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HAVE_LIBPCAP */

#endif /* __PCAP_UTIL_H__ */
