/* pcap-util.c
 * Utility routines for packet capture
 *
 * $Id: pcap-util.c,v 1.3 2001/11/09 08:16:24 guy Exp $
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
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <pcap.h>

#ifndef WIN32
#include <net/if.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#include "globals.h"

#ifdef WIN32
#include "capture-wpcap.h"
#endif

#include "pcap-util.h"

/*
 * Get the data-link type for a libpcap device.
 * This works around AIX 5.x's non-standard and incompatible-with-the-
 * rest-of-the-universe libpcap.
 */
int
get_pcap_linktype(pcap_t *pch, char *devname)
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
	 * The AIX names for LAN devices begin with:
	 *
	 *	Ethernet		en
	 *	802.3			et
	 *	Token Ring		tr
	 *	FDDI			fi
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
	} else if (strncmp(ifacename, "tr") == 0) {
		if (linktype == 9) {
			/*
			 * That's the RFC 1573 value for 802.5 (Token Ring);
			 * map it to DLT_IEEE802, which is what's used for
			 * Token Ring.
			 */
			linktype = 6;
		}
	} else if (strncmp(ifacename, "fi") == 0) {
		if (linktype == 15) {
			/*
			 * That's the RFC 1573 value for FDDI; map it to
			 * DLT_FDDI.
			 */
			linktype = 10;
		}
	}
#endif

	return linktype;
}

/*
 * If the ability to capture packets is added to Wiretap, these
 * routines should be moved to the Wiretap source (with
 * "get_interface_list()" and "free_interface_list()" renamed to
 * "wtap_get_interface_list()" and "wtap_free_interface_list()",
 * and modified to use Wiretap routines to attempt to open the
 * interface.
 */

struct search_user_data {
	char	*name;
	int	found;
};

static void
search_for_if_cb(gpointer data, gpointer user_data);

static void
free_if_cb(gpointer data, gpointer user_data);

#ifndef WIN32
GList *
get_interface_list(int *err, char *err_str)
{
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

	if (sock < 0) {
		sprintf(err_str, "Error opening socket: %s",
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
				sprintf(err_str,
					"SIOCGIFCONF ioctl error getting list of interfaces: %s",
					strerror(errno));
				goto fail;
			}
		} else {
			if ((unsigned) ifc.ifc_len < sizeof(struct ifreq)) {
				sprintf(err_str,
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
		 * Skip addresses that begin with "dummy", or that include
		 * a ":" (the latter are Solaris virtuals).
		 */
		if (strncmp(ifr->ifr_name, "dummy", 5) == 0 ||
		    strchr(ifr->ifr_name, ':') != NULL)
			goto next;

		/*
		 * If we already have this interface name on the list,
		 * don't add it (SIOCGIFCONF returns, at least on
		 * BSD-flavored systems, one entry per interface *address*;
		 * if an interface has multiple addresses, we get multiple
		 * entries for it).
		 */
		user_data.name = ifr->ifr_name;
		user_data.found = FALSE;
		g_list_foreach(il, search_for_if_cb, &user_data);
		if (user_data.found)
			goto next;

		/*
		 * Get the interface flags.
		 */
		memset(&ifrflags, 0, sizeof ifrflags);
		strncpy(ifrflags.ifr_name, ifr->ifr_name,
		    sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				goto next;
			sprintf(err_str, "SIOCGIFFLAGS error getting flags for interface %s: %s",
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
		if ((ifrflags.ifr_flags & IFF_LOOPBACK) ||
		    strncmp(ifr->ifr_name, "lo", 2) == 0)
			il = g_list_insert(il, g_strdup(ifr->ifr_name), -1);
		else {
			il = g_list_insert(il, g_strdup(ifr->ifr_name),
			    nonloopback_pos);
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
		il = g_list_insert(il, g_strdup("any"), -1);
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
	if (il != NULL) {
		g_list_foreach(il, free_if_cb, NULL);
		g_list_free(il);
	}
	g_free(ifc.ifc_buf);
	close(sock);
	*err = CANT_GET_INTERFACE_LIST;
	return NULL;
}

static void
search_for_if_cb(gpointer data, gpointer user_data)
{
	struct search_user_data *search_user_data = user_data;

	if (strcmp((char *)data, search_user_data->name) == 0)
		search_user_data->found = TRUE;
}
#else
GList *
get_interface_list(int *err, char *err_str) {
  GList  *il = NULL;
  wchar_t *names;
  char *win95names; 
  char newname[255];
  int i, j, done;
  
  names = (wchar_t *)pcap_lookupdev(err_str);
  i = done = 0;

  if (names) {
	  if (names[0]<256) { 
		  /* If names[0] is less than 256 it means the first byte is 0
		     This implies that we are using unicode characters */
		  do 
		  { 
			  j = 0; 
			  while (names[i] != 0) 
				  newname[j++] = names[i++]; 
			  i++; 
			  if (names[i] == 0) 
				  done = 1; 
			  newname[j++] = 0; 
			  il = g_list_append(il, g_strdup(newname)); 
		  } while (!done); 
	  } 
	  else { 
		  /* Otherwise we are in Windows 95/98 and using ascii(8 bit)
		     characters */
		  do 
		  { 
			  win95names=(char *)names; 
			  j = 0; 
			  while (win95names[i] != 0) 
				  newname[j++] = win95names[i++]; 
			  i++; 
			  if (win95names[i] == 0) 
				  done = 1; 
			  newname[j++] = 0; 
			  il = g_list_append(il, g_strdup(newname)); 
		  } while (!done); 
	  } 
  }
  return(il);
}
#endif

static void
free_if_cb(gpointer data, gpointer user_data)
{
	g_free(data);
}

void
free_interface_list(GList *if_list)
{
	while (if_list != NULL) {
		g_free(if_list->data);
		if_list = g_list_remove_link(if_list, if_list);
	}
}

#endif /* HAVE_LIBPCAP */
