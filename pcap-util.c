/* pcap-util.c
 * Utility routines for packet capture
 *
 * $Id: pcap-util.c,v 1.20 2003/11/21 08:30:40 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <glib.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <pcap.h>

#include <wtap.h>
#include <wtap-capture.h>

#include "pcap-util.h"
#include "pcap-util-int.h"

/*
 * Get the data-link type for a libpcap device.
 * This works around AIX 5.x's non-standard and incompatible-with-the-
 * rest-of-the-universe libpcap.
 */
int
get_pcap_linktype(pcap_t *pch, char *devname
#ifndef AIX
	_U_
#endif
)
{
	int linktype;
#ifdef AIX
	char *ifacename;
#endif

	linktype = pcap_datalink(pch);
#ifdef AIX

	/*
	 * The libpcap that comes with AIX 5.x uses RFC 1573 ifType values
	 * rather than DLT_ values for link-layer types; the ifType values
	 * for LAN devices are:
	 *
	 *	Ethernet	6
	 *	802.3		7
	 *	Token Ring	9
	 *	FDDI		15
	 *
	 * and the ifType value for a loopback device is 24.
	 *
	 * The AIX names for LAN devices begin with:
	 *
	 *	Ethernet		en
	 *	802.3			et
	 *	Token Ring		tr
	 *	FDDI			fi
	 *
	 * and the AIX names for loopback devices begin with "lo".
	 *
	 * (The difference between "Ethernet" and "802.3" is presumably
	 * whether packets have an Ethernet header, with a packet type,
	 * or an 802.3 header, with a packet length, followed by an 802.2
	 * header and possibly a SNAP header.)
	 *
	 * If the device name matches "linktype" interpreted as an ifType
	 * value, rather than as a DLT_ value, we will assume this is AIX's
	 * non-standard, incompatible libpcap, rather than a standard libpcap,
	 * and will map the link-layer type to the standard DLT_ value for
	 * that link-layer type, as that's what the rest of Ethereal expects.
	 *
	 * (This means the capture files won't be readable by a tcpdump
	 * linked with AIX's non-standard libpcap, but so it goes.  They
	 * *will* be readable by standard versions of tcpdump, Ethereal,
	 * and so on.)
	 *
	 * XXX - if we conclude we're using AIX libpcap, should we also
	 * set a flag to cause us to assume the time stamps are in
	 * seconds-and-nanoseconds form, and to convert them to
	 * seconds-and-microseconds form before processing them and
	 * writing them out?
	 */

	/*
	 * Find the last component of the device name, which is the
	 * interface name.
	 */
	ifacename = strchr(devname, '/');
	if (ifacename == NULL)
		ifacename = devnames;

	/* See if it matches any of the LAN device names. */
	if (strncmp(ifacename, "en", 2) == 0) {
		if (linktype == 6) {
			/*
			 * That's the RFC 1573 value for Ethernet; map it
			 * to DLT_EN10MB.
			 */
			linktype = 1;
		}
	} else if (strncmp(ifacename, "et", 2) == 0) {
		if (linktype == 7) {
			/*
			 * That's the RFC 1573 value for 802.3; map it to
			 * DLT_EN10MB.
			 * (libpcap, tcpdump, Ethereal, etc. don't care if
			 * it's Ethernet or 802.3.)
			 */
			linktype = 1;
		}
	} else if (strncmp(ifacename, "tr", 2) == 0) {
		if (linktype == 9) {
			/*
			 * That's the RFC 1573 value for 802.5 (Token Ring);
			 * map it to DLT_IEEE802, which is what's used for
			 * Token Ring.
			 */
			linktype = 6;
		}
	} else if (strncmp(ifacename, "fi", 2) == 0) {
		if (linktype == 15) {
			/*
			 * That's the RFC 1573 value for FDDI; map it to
			 * DLT_FDDI.
			 */
			linktype = 10;
		}
	} else if (strncmp(ifacename, "lo", 2) == 0) {
		if (linktype == 24) {
			/*
			 * That's the RFC 1573 value for "software loopback"
			 * devices; map it to DLT_NULL, which is what's used
			 * for loopback devices on BSD.
			 */
			linktype = 0;
		}
	}
#endif

	return linktype;
}

if_info_t *
if_info_new(char *name, char *description)
{
	if_info_t *if_info;

	if_info = g_malloc(sizeof (if_info_t));
	if_info->name = g_strdup(name);
	if (description == NULL)
		if_info->description = NULL;
	else
		if_info->description = g_strdup(description);
	return if_info;
}

#ifdef HAVE_PCAP_FINDALLDEVS
GList *
get_interface_list_findalldevs(int *err, char *err_str)
{
	GList  *il = NULL;
	pcap_if_t *alldevs, *dev;
	if_info_t *if_info;

	if (pcap_findalldevs(&alldevs, err_str) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		return NULL;
	}

	if (alldevs == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
		return NULL;
	}

	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if_info = if_info_new(dev->name, dev->description);
		il = g_list_append(il, if_info);
	}
	pcap_freealldevs(alldevs);

	return il;
}
#endif /* HAVE_PCAP_FINDALLDEVS */

static void
free_if_cb(gpointer data, gpointer user_data _U_)
{
	if_info_t *if_info = data;

	g_free(if_info->name);
	if (if_info->description != NULL)
		g_free(if_info->description);
}

void
free_interface_list(GList *if_list)
{
	g_list_foreach(if_list, free_if_cb, NULL);
	g_list_free(if_list);
}

/*
 * Get the data-link types available for a libpcap device.
 */
static data_link_info_t *
create_data_link_info(int dlt)
{
	data_link_info_t *data_link_info;
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
	const char *typename;
#endif
	int wtap_encap;

	data_link_info = g_malloc(sizeof (data_link_info_t));
	data_link_info->dlt = dlt;
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
	typename = pcap_datalink_val_to_name(dlt);
	if (typename != NULL)
		data_link_info->name = g_strdup(typename);
	else
#endif
		data_link_info->name = g_strdup_printf("DLT %d", dlt);
	wtap_encap = wtap_pcap_encap_to_wtap_encap(dlt);
	if (wtap_encap == WTAP_ENCAP_UNKNOWN) {
		/*
		 * We don't support this in Wiretap.
		 * However, we should, so you can capture on it.
		 * Put in an entry for it, with no description.
		 */
		data_link_info->description = NULL;
	} else {
		/*
		 * If this is null, that's a bug in
		 * "wtap_pcap_encap_to_wtap_encap()" - it should always
		 * return a valid encapsulation type - so we assume it's
		 * not null.
		 */
		data_link_info->description =
		    g_strdup(wtap_encap_string(wtap_encap));
	}
	return data_link_info;
}

GList *
get_pcap_linktype_list(char *devname, char *err_buf)
{
	GList *linktype_list = NULL;
	pcap_t *pch;
	int deflt;
#ifdef HAVE_PCAP_SET_DATALINK
	int *linktypes;
	int i, nlt;
#endif
	data_link_info_t *data_link_info;

	pch = pcap_open_live(devname, MIN_PACKET_SIZE, 0, 0, err_buf);
	if (pch == NULL)
		return NULL;
	err_buf[0] = '\0';	/* an empty list doesn't mean an error */
	deflt = get_pcap_linktype(pch, devname);
#ifdef HAVE_PCAP_LIST_DATALINKS
	nlt = pcap_list_datalinks(pch, &linktypes);
	if (nlt == 0 || linktypes == NULL)
		return NULL;
	for (i = 0; i < nlt; i++) {
		data_link_info = create_data_link_info(linktypes[i]);

		/*
		 * XXX - for 802.11, make the most detailed 802.11
		 * version the default, rather than the one the
		 * device has as the default?
		 */
		if (linktypes[i] == deflt)
			linktype_list = g_list_prepend(linktype_list,
			    data_link_info);
		else
			linktype_list = g_list_append(linktype_list,
			    data_link_info);
	}
	free(linktypes);
#else
	data_link_info = create_data_link_info(deflt);
	linktype_list = g_list_append(linktype_list, data_link_info);
#endif

	pcap_close(pch);
	return linktype_list;
}

static void
free_linktype_cb(gpointer data, gpointer user_data _U_)
{
	data_link_info_t *linktype_info = data;

	g_free(linktype_info->name);
	if (linktype_info->description != NULL)
		g_free(linktype_info->description);
}

void
free_pcap_linktype_list(GList *linktype_list)
{
	g_list_foreach(linktype_list, free_linktype_cb, NULL);
	g_list_free(linktype_list);
}

/* Set the data link type on a pcap. */
const char *
set_pcap_linktype(pcap_t *pch, char *devname, int dlt)
{
#ifdef HAVE_PCAP_SET_DATALINK
	if (pcap_set_datalink(pch, dlt) == 0)
		return NULL;	/* no error */
	return pcap_geterr(pch);
#else
	/* Let them set it to the type it is; reject any other request. */
	if (get_pcap_linktype(pch, devname) == dlt)
		return NULL;	/* no error */
	return "That DLT is not one of the DLTs supported by this device";
#endif
}

#endif /* HAVE_LIBPCAP */
