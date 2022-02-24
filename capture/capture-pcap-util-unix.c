/* capture-pcap-util-unix.c
 * UN*X-specific utility routines for packet capture
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <string.h>
#include <ws_attributes.h>
#include <wsutil/feature_list.h>

#ifdef HAVE_LIBPCAP

#include "wspcap.h"

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#include "capture/capture_ifinfo.h"
#include "capture/capture-pcap-util.h"
#include "capture/capture-pcap-util-int.h"

#ifdef HAVE_PCAP_REMOTE
GList *
get_remote_interface_list(const char *hostname, const char *port,
			  int auth_type, const char *username,
			  const char *passwd, int *err, char **err_str)
{
	return get_interface_list_findalldevs_ex(hostname, port, auth_type,
	    username, passwd, err, err_str);
}
#endif

GList *
get_interface_list(int *err, char **err_str)
{
	return get_interface_list_findalldevs(err, err_str);
}

/*
 * Get an error message string for a CANT_GET_INTERFACE_LIST error from
 * "get_interface_list()".
 */
gchar *
cant_get_if_list_error_message(const char *err_str)
{
	return ws_strdup_printf("Can't get list of interfaces: %s", err_str);
}

if_capabilities_t *
get_if_capabilities_local(interface_options *interface_opts,
    cap_device_open_status *status, char **status_str)
{
#ifdef HAVE_PCAP_CREATE
	return get_if_capabilities_pcap_create(interface_opts, status,
	    status_str);
#else
	return get_if_capabilities_pcap_open_live(interface_opts, status,
	    status_str);
#endif
}

pcap_t *
open_capture_device_local(capture_options *capture_opts
#ifndef HAVE_PCAP_CREATE
	_U_
#endif
	,
    interface_options *interface_opts, int timeout,
    cap_device_open_status *open_status,
    char (*open_status_str)[PCAP_ERRBUF_SIZE])
{
	/*
	 * We're not opening a remote device; use pcap_create() and
	 * pcap_activate() if we have them, so that we can set various
	 * options, otherwise use pcap_open_live().
	 */
#ifdef HAVE_PCAP_CREATE
	return open_capture_device_pcap_create(capture_opts,
	    interface_opts, timeout, open_status, open_status_str);
#else
	return open_capture_device_pcap_open_live(interface_opts, timeout,
	    open_status, open_status_str);
#endif
}

/*
 * Get the versions of libpcap, libpcap, and libnl with which we were
 * compiled, and append them to a GString.
 */
void
gather_caplibs_compile_info(feature_list l)
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
#ifdef HAVE_PCAP_REMOTE
	/*
	 * We have remote pcap support in libpcap.
	 */
	with_feature(l, "libpcap (including remote capture support)");
#else
	with_feature(l, "libpcap");
#endif

	/*
	 * XXX - these libraries are actually used only by dumpcap,
	 * but we mention them here so that a user reporting a bug
	 * can get information about dumpcap's libraries without
	 * having to run dumpcap.
	 */
	/* LIBCAP */
#ifdef HAVE_LIBCAP
#ifdef _LINUX_CAPABILITY_VERSION
	with_feature(l, "POSIX capabilities (Linux)");
#else /* _LINUX_CAPABILITY_VERSION */
	with_feature(l, "POSIX capabilities");
#endif /* _LINUX_CAPABILITY_VERSION */
#else /* HAVE_LIBCAP */
	without_feature(l, "POSIX capabilities");
#endif /* HAVE_LIBCAP */

#ifdef __linux__
	/* This is a Linux-specific library. */
	/* LIBNL */
#if defined(HAVE_LIBNL1)
	with_feature(l, "libnl 1");
#elif defined(HAVE_LIBNL2)
	with_feature(l, "libnl 2");
#elif defined(HAVE_LIBNL3)
	with_feature(l, "libnl 3");
#else /* no libnl */
	without_feature(l, "libnl");
#endif /* libnl version */
#endif /* __linux__ */
}

void
gather_caplibs_runtime_info(feature_list l)
{
	const char *vstr = pcap_lib_version();

	/*
	 * Remove the substring "version" from the output of pcap_lib_version()
	 * to be consistent with our format.
	 */
	if (g_str_has_prefix(vstr, "libpcap version ")) /* Sanity check */
		with_feature(l, "libpcap %s", vstr + strlen("libpcap version "));
	else
		with_feature(l, "%s", vstr);
}

#else /* HAVE_LIBPCAP */

/*
 * Append an indication that we were not compiled with libpcap
 * to a GString.  Don't even bother mentioning the other
 * libraries.
 */
void
gather_caplibs_compile_info(feature_list l)
{
	without_feature(l, "libpcap");
}

void
gather_caplibs_runtime_info(feature_list l _U_)
{
}

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
