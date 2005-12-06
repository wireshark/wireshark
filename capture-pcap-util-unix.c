/* capture-pcap-util-unix.c
 * UN*X-specific utility routines for packet capture
 *
 * $Id$
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

#include <glib.h>

#ifdef HAVE_LIBPCAP

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <pcap.h>

/*
 * Keep Digital UNIX happy when including <net/if.h>.
 */
struct mbuf;
struct rtentry;
#include <net/if.h>

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#include "capture-pcap-util.h"
#include "capture-pcap-util-int.h"

#ifndef HAVE_PCAP_FINDALLDEVS
struct search_user_data {
	char	*name;
	if_info_t *if_info;
};

static void
search_for_if_cb(gpointer data, gpointer user_data);
#endif

GList *
get_interface_list(int *err, char *err_str)
{
#ifdef HAVE_PCAP_FINDALLDEVS
	return get_interface_list_findalldevs(err, err_str);
#else
	GList  *il = NULL;
	gint    nonloopback_pos = 0;
	struct  ifreq *ifr, *last;
	struct  ifconf ifc;
	struct  ifreq ifrflags;
	int     sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct search_user_data user_data;
	pcap_t *pch;
	int len, lastlen;
	char *buf;
	if_info_t *if_info;

	if (sock < 0) {
		*err = CANT_GET_INTERFACE_LIST;
		g_snprintf(err_str, PCAP_ERRBUF_SIZE, "Error opening socket: %s",
		    strerror(errno));
		return NULL;
	}

	/*
	 * This code came from: W. Richard Stevens: "UNIX Network Programming",
	 * Networking APIs: Sockets and XTI, Vol 1, page 434.
	 */
	lastlen = 0;
	len = 100 * sizeof(struct ifreq);
	for ( ; ; ) {
		buf = g_malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		memset (buf, 0, len);
		if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0) {
				g_snprintf(err_str, PCAP_ERRBUF_SIZE,
					"SIOCGIFCONF ioctl error getting list of interfaces: %s",
					strerror(errno));
				goto fail;
			}
		} else {
			if ((unsigned) ifc.ifc_len < sizeof(struct ifreq)) {
				g_snprintf(err_str, PCAP_ERRBUF_SIZE,
					"SIOCGIFCONF ioctl gave too small return buffer");
				goto fail;
			}
			if (ifc.ifc_len == lastlen)
				break;			/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);	/* increment */
		g_free(buf);
	}
	ifr = (struct ifreq *) ifc.ifc_req;
	last = (struct ifreq *) ((char *) ifr + ifc.ifc_len);
	while (ifr < last) {
		/*
		 * Skip entries that begin with "dummy", or that include
		 * a ":" (the latter are Solaris virtuals).
		 */
		if (strncmp(ifr->ifr_name, "dummy", 5) == 0 ||
		    strchr(ifr->ifr_name, ':') != NULL)
			goto next;

		/*
		 * If we already have this interface name on the list,
		 * don't add it, but, if we don't already have an IP
		 * address for it, add that address (SIOCGIFCONF returns,
		 * at least on BSD-flavored systems, one entry per
		 * interface *address*; if an interface has multiple
		 * addresses, we get multiple entries for it).
		 */
		user_data.name = ifr->ifr_name;
		user_data.if_info = NULL;
		g_list_foreach(il, search_for_if_cb, &user_data);
		if (user_data.if_info != NULL) {
			if_info_add_address(user_data.if_info, &ifr->ifr_addr);
			goto next;
		}

		/*
		 * Get the interface flags.
		 */
		memset(&ifrflags, 0, sizeof ifrflags);
		strncpy(ifrflags.ifr_name, ifr->ifr_name,
		    sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				goto next;
			g_snprintf(err_str, PCAP_ERRBUF_SIZE,
				"SIOCGIFFLAGS error getting flags for interface %s: %s",
			    ifr->ifr_name, strerror(errno));
			goto fail;
		}

		/*
		 * Skip interfaces that aren't up.
		 */
		if (!(ifrflags.ifr_flags & IFF_UP))
			goto next;

		/*
		 * Skip interfaces that we can't open with "libpcap".
		 * Open with the minimum packet size - it appears that the
		 * IRIX SIOCSNOOPLEN "ioctl" may fail if the capture length
		 * supplied is too large, rather than just truncating it.
		 */
		pch = pcap_open_live(ifr->ifr_name, MIN_PACKET_SIZE, 0, 0,
		    err_str);
		if (pch == NULL)
			goto next;
		pcap_close(pch);

		/*
		 * If it's a loopback interface, add it at the end of the
		 * list, otherwise add it after the last non-loopback
		 * interface, so all loopback interfaces go at the end - we
		 * don't want a loopback interface to be the default capture
		 * device unless there are no non-loopback devices.
		 */
		if_info = if_info_new(ifr->ifr_name, NULL);
		if_info_add_address(if_info, &ifr->ifr_addr);
		if ((ifrflags.ifr_flags & IFF_LOOPBACK) ||
		    strncmp(ifr->ifr_name, "lo", 2) == 0) {
			if_info->loopback = TRUE;
			il = g_list_append(il, if_info);
		} else {
			if_info->loopback = FALSE;
			il = g_list_insert(il, if_info, nonloopback_pos);
			/*
			 * Insert the next non-loopback interface after this
			 * one.
			 */
			nonloopback_pos++;
		}

	next:
#ifdef HAVE_SA_LEN
		ifr = (struct ifreq *) ((char *) ifr +
		    (ifr->ifr_addr.sa_len > sizeof(ifr->ifr_addr) ?
			ifr->ifr_addr.sa_len : sizeof(ifr->ifr_addr)) +
		    IFNAMSIZ);
#else
		ifr = (struct ifreq *) ((char *) ifr + sizeof(struct ifreq));
#endif
	}

#ifdef linux
	/*
	 * OK, maybe we have support for the "any" device, to do a cooked
	 * capture on all interfaces at once.
	 * Try opening it and, if that succeeds, add it to the end of
	 * the list of interfaces.
	 */
	pch = pcap_open_live("any", MIN_PACKET_SIZE, 0, 0, err_str);
	if (pch != NULL) {
		/*
		 * It worked; we can use the "any" device.
		 */
		if_info = if_info_new("any",
		    "Pseudo-device that captures on all interfaces");
		il = g_list_insert(il, if_info, -1);
		pcap_close(pch);
	}
#endif

	g_free(ifc.ifc_buf);
	close(sock);

	if (il == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
	}
	return il;

fail:
	if (il != NULL)
		free_interface_list(il);
	g_free(ifc.ifc_buf);
	close(sock);
	*err = CANT_GET_INTERFACE_LIST;
	return NULL;
#endif /* HAVE_PCAP_FINDALLDEVS */
}

#ifndef HAVE_PCAP_FINDALLDEVS
static void
search_for_if_cb(gpointer data, gpointer user_data)
{
	struct search_user_data *search_user_data = user_data;
	if_info_t *if_info = data;

	if (strcmp(if_info->name, search_user_data->name) == 0)
		search_user_data->if_info = if_info;
}
#endif /* HAVE_PCAP_FINDALLDEVS */

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_interface_list()".
 */
gchar *
cant_get_if_list_error_message(const char *err_str)
{
	return g_strdup_printf("Can't get list of interfaces: %s", err_str);
}

/*
 * Append the version of libpcap with which we were compiled to a GString.
 */
void
get_compiled_pcap_version(GString *str)
{
#ifdef HAVE_PCAP_VERSION
	extern char pcap_version[];

	g_string_sprintfa(str, "with libpcap %s", pcap_version);
#else
	g_string_append(str, "with libpcap (version unknown)");
#endif
}

/*
 * Append the version of libpcap with which we we're running to a GString.
 */
void
get_runtime_pcap_version(GString *str)
{
	g_string_sprintfa(str, "with ");
#ifdef HAVE_PCAP_LIB_VERSION
	g_string_sprintfa(str, pcap_lib_version());
#else
	g_string_append(str, "libpcap (version unknown)");
#endif
	g_string_append(str, " ");
}

#else /* HAVE_LIBPCAP */

/*
 * Append an indication that we were not compiled with libpcap
 * to a GString.
 */
void
get_compiled_pcap_version(GString *str)
{
	g_string_append(str, "without libpcap");
}

/*
 * Don't append anything, as we weren't even compiled to use WinPcap.
 */
void
get_runtime_pcap_version(GString *str _U_)
{
}

#endif /* HAVE_LIBPCAP */
