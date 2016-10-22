/* capture-pcap-util-unix.c
 * UN*X-specific utility routines for packet capture
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

#include "config.h"

#include <glib.h>

#ifdef HAVE_LIBPCAP

#include <pcap.h>

#ifdef __APPLE__
#include <dlfcn.h>
#endif

#ifndef HAVE_PCAP_FINDALLDEVS

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

/*
 * Keep Digital UNIX happy when including <net/if.h>.
 */
struct mbuf;
struct rtentry;
#include <net/if.h>

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#endif  /* HAVE_PCAP_FINDALLDEVS */

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#include "caputils/capture_ifinfo.h"
#include "caputils/capture-pcap-util.h"
#include "caputils/capture-pcap-util-int.h"

#ifdef HAVE_PCAP_REMOTE
GList *
get_remote_interface_list(const char *hostname, const char *port,
			  int auth_type, const char *username,
			  const char *passwd, int *err, char **err_str)
{
	struct pcap_rmtauth auth;
	char source[PCAP_BUF_SIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	GList *result;

	if (pcap_createsrcstr(source, PCAP_SRC_IFREMOTE, hostname, port,
			      NULL, errbuf) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		if (err_str != NULL)
			*err_str = cant_get_if_list_error_message(errbuf);
		return NULL;
	}

	auth.type = auth_type;
	auth.username = g_strdup(username);
	auth.password = g_strdup(passwd);

	result = get_interface_list_findalldevs_ex(source, &auth, err, err_str);
	g_free(auth.username);
	g_free(auth.password);

	return result;
}
#endif

#ifdef HAVE_PCAP_FINDALLDEVS
GList *
get_interface_list(int *err, char **err_str)
{
	return get_interface_list_findalldevs(err, err_str);
}
#else /* HAVE_PCAP_FINDALLDEVS */
struct search_user_data {
	char	*name;
	if_info_t *if_info;
};

static void
search_for_if_cb(gpointer data, gpointer user_data)
{
	struct search_user_data *search_user_data = (struct search_user_data*)user_data;
	if_info_t *if_info = (if_info_t *)data;

	if (strcmp(if_info->name, search_user_data->name) == 0)
		search_user_data->if_info = if_info;
}

GList *
get_interface_list(int *err, char **err_str)
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
	if_info_t *if_info;
	char errbuf[PCAP_ERRBUF_SIZE];
	gboolean loopback;

	if (sock < 0) {
		*err = CANT_GET_INTERFACE_LIST;
		if (err_str != NULL) {
			*err_str = g_strdup_printf(
			    "Can't get list of interfaces: error opening socket: %s",
			    g_strerror(errno));
		}
		return NULL;
	}

	/*
	 * This code came from: W. Richard Stevens: "UNIX Network Programming",
	 * Networking APIs: Sockets and XTI, Vol 1, page 434.
	 */
	lastlen = 0;
	len = 100 * sizeof(struct ifreq);
	for ( ; ; ) {
		buf = (char *)g_malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		memset (buf, 0, len);
		if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0) {
				if (err_str != NULL) {
					*err_str = g_strdup_printf(
					    "Can't get list of interfaces: SIOCGIFCONF ioctl error: %s",
					    g_strerror(errno));
				}
				goto fail;
			}
		} else {
			if ((unsigned int) ifc.ifc_len < sizeof(struct ifreq)) {
				if (err_str != NULL) {
					*err_str = g_strdup(
					    "Can't get list of interfaces: SIOCGIFCONF ioctl gave too small return buffer");
				}
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
		g_strlcpy(ifrflags.ifr_name, ifr->ifr_name,
		    sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				goto next;
			if (err_str != NULL) {
				*err_str = g_strdup_printf(
				    "Can't get list of interfaces: SIOCGIFFLAGS error getting flags for interface %s: %s",
				    ifr->ifr_name, g_strerror(errno));
			}
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
		    errbuf);
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
		loopback = ((ifrflags.ifr_flags & IFF_LOOPBACK) ||
		    strncmp(ifr->ifr_name, "lo", 2) == 0);
		if_info = if_info_new(ifr->ifr_name, NULL, loopback);
		if_info_add_address(if_info, &ifr->ifr_addr);
		if (loopback)
			il = g_list_append(il, if_info);
		else {
			il = g_list_insert(il, if_info, nonloopback_pos);
			/*
			 * Insert the next non-loopback interface after this
			 * one.
			 */
			nonloopback_pos++;
		}

	next:
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
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
	pch = pcap_open_live("any", MIN_PACKET_SIZE, 0, 0, errbuf);
	if (pch != NULL) {
		/*
		 * It worked; we can use the "any" device.
		 */
		if_info = if_info_new("any",
		    "Pseudo-device that captures on all interfaces", FALSE);
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
		*err = 0;
		if (err_str != NULL)
			*err_str = NULL;
	}
	return il;

fail:
	if (il != NULL)
		free_interface_list(il);
	g_free(ifc.ifc_buf);
	close(sock);
	*err = CANT_GET_INTERFACE_LIST;
	return NULL;
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

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
/*
 * Request high-resolution time stamps.
 *
 * We don't check for errors - if this fails, we just live with boring old
 * microsecond-resolution time stamps. The only errors pcap_set_tstamp_precision()
 * is documenting as returning are PCAP_ERROR_TSTAMP_PRECISION_NOTSUP, which just
 * means we can't do nanosecond precision on this adapter, in which case we
 * just live with whatever resolution we get by default, and
 * PCAP_ERROR_ACTIVATED, which shouldn't happen as we shouldn't call this
 * after we've activated the pcap_t.
 */
void
request_high_resolution_timestamp(pcap_t *pcap_h)
{
#ifdef __APPLE__
	/*
	 * On OS X, if you build with a newer SDK, pcap_set_tstamp_precision()
	 * is available, so the code will be built with it.
	 *
	 * However, if you then try to run on an older release that
	 * doesn't have pcap_set_tstamp_precision(), the dynamic linker
	 * will fail, as it won't find pcap_set_tstamp_precision().
	 *
	 * libpcap doesn't use OS X "weak linking" for new routines,
	 * so we can't just check whether a pointer to
	 * pcap_set_tstamp_precision() is null and, if it is, not
	 * call it.  We have to, instead, use dlopen() to load
	 * libpcap, and dlsym() to find a pointer to pcap_set_tstamp_precision(),
	 * and if we find the pointer, call it.
	 */
	static gboolean initialized = FALSE;
	static int (*p_pcap_set_tstamp_precision)(pcap_t *, int);

	if (!initialized) {
		p_pcap_set_tstamp_precision =
		    (int (*)(pcap_t *, int))
		      dlsym(RTLD_NEXT, "pcap_set_tstamp_precision");
		initialized = TRUE;
	}
	if (p_pcap_set_tstamp_precision != NULL)
		(*p_pcap_set_tstamp_precision)(pcap_h, PCAP_TSTAMP_PRECISION_NANO);
#else /* __APPLE__ */
	/*
	 * On other UN*Xes we require that we be run on an OS version
	 * with a libpcap equal to or later than the version with which
	 * we were built.
	 */
	pcap_set_tstamp_precision(pcap_h, PCAP_TSTAMP_PRECISION_NANO);
#endif /* __APPLE__ */
}

/*
 * Return TRUE if the pcap_t in question is set up for high-precision
 * time stamps, FALSE otherwise.
 */
gboolean
have_high_resolution_timestamp(pcap_t *pcap_h)
{
#ifdef __APPLE__
	/*
	 * See above.
	 */
	static gboolean initialized = FALSE;
	static int (*p_pcap_get_tstamp_precision)(pcap_t *);

	if (!initialized) {
		p_pcap_get_tstamp_precision =
		    (int (*)(pcap_t *))
		      dlsym(RTLD_NEXT, "pcap_get_tstamp_precision");
		initialized = TRUE;
	}
	if (p_pcap_get_tstamp_precision != NULL)
		return (*p_pcap_get_tstamp_precision)(pcap_h) == PCAP_TSTAMP_PRECISION_NANO;
	else
		return FALSE;	/* Can't get implies couldn't set */
#else /* __APPLE__ */
	/*
	 * On other UN*Xes we require that we be run on an OS version
	 * with a libpcap equal to or later than the version with which
	 * we were built.
	 */
	return pcap_get_tstamp_precision(pcap_h) == PCAP_TSTAMP_PRECISION_NANO;
#endif /* __APPLE__ */
}

#endif /* HAVE_PCAP_SET_TSTAMP_PRECISION */

if_capabilities_t *
get_if_capabilities_local(interface_options *interface_opts, char **err_str)
{
#ifdef HAVE_PCAP_CREATE
	return get_if_capabilities_pcap_create(interface_opts, err_str);
#else
	return get_if_capabilities_pcap_open_live(interface_opts, err_str);
#endif
}

pcap_t *
open_capture_device_local(capture_options *capture_opts,
    interface_options *interface_opts, int timeout,
    char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	/*
	 * We're not opening a remote device; use pcap_create() and
	 * pcap_activate() if we have them, so that we can set various
	 * options, otherwise use pcap_open_live().
	 */
#ifdef HAVE_PCAP_CREATE
	return open_capture_device_pcap_create(capture_opts,
	    interface_opts, timeout, open_err_str);
#else
	return open_capture_device_pcap_open_live(interface_opts, timeout,
	    open_err_str);
#endif
}

/*
 * Get the versions of libpcap, libpcap, and libnl with which we were
 * compiled, and append them to a GString.
 */
void
get_compiled_caplibs_version(GString *str)
{
	/*
	 * NOTE: in *some* flavors of UN*X, the data from a shared
	 * library might be linked into executable images that are
	 * linked with that shared library, in which case you could
	 * look at pcap_version[] to get the version with which
	 * the program was compiled.
	 *
	 * In other flavors of UN*X, that doesn't happen, so
	 * pcap_version[] gives you the version the program is
	 * running with, not the version it was built with, and,
	 * in at least some of them, if the length of a data item
	 * referred to by the executable - such as the pcap_version[]
	 * string - isn't the same in the version of the library
	 * with which the program was built and the version with
	 * which it was run, the run-time linker will complain,
	 * which is Not Good.
	 *
	 * So, for now, we just give up on reporting the version
	 * of libpcap with which we were compiled.
	 */
	g_string_append(str, "with libpcap");

	/*
	 * XXX - these libraries are actually used only by dumpcap,
	 * but we mention them here so that a user reporting a bug
	 * can get information about dumpcap's libraries without
	 * having to run dumpcap.
	 */
	/* LIBCAP */
	g_string_append(str, ", ");
#ifdef HAVE_LIBCAP
	g_string_append(str, "with POSIX capabilities");
#ifdef _LINUX_CAPABILITY_VERSION
	g_string_append(str, " (Linux)");
#endif /* _LINUX_CAPABILITY_VERSION */
#else /* HAVE_LIBCAP */
	g_string_append(str, "without POSIX capabilities");
#endif /* HAVE_LIBCAP */

#ifdef __linux__
	/* This is a Linux-specific library. */
	/* LIBNL */
	g_string_append(str, ", ");
#if defined(HAVE_LIBNL1)
	g_string_append(str, "with libnl 1");
#elif defined(HAVE_LIBNL2)
	g_string_append(str, "with libnl 2");
#elif defined(HAVE_LIBNL3)
	g_string_append(str, "with libnl 3");
#else /* no libnl */
	g_string_append(str, "without libnl");
#endif /* libnl version */
#endif /* __linux__ */
}

/*
 * Append the version of libpcap with which we we're running to a GString.
 */
void
get_runtime_caplibs_version(GString *str)
{
	g_string_append_printf(str, "with ");
#ifdef HAVE_PCAP_LIB_VERSION
	g_string_append(str, pcap_lib_version());
#else
	g_string_append(str, "libpcap (version unknown)");
#endif
}

#else /* HAVE_LIBPCAP */

/*
 * Append an indication that we were not compiled with libpcap
 * to a GString.  Don't even bother mentioning the other
 * libraries.
 */
void
get_compiled_caplibs_version(GString *str)
{
	g_string_append(str, "without libpcap");
}

/*
 * Don't append anything, as we weren't even compiled to use libpcap.
 */
void
get_runtime_caplibs_version(GString *str _U_)
{
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
