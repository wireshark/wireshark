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

#include <ws_attributes.h>

#ifdef HAVE_LIBPCAP

#include "wspcap.h"

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
	return g_strdup_printf("Can't get list of interfaces: %s", err_str);
}

if_capabilities_t *
get_if_capabilities_local(interface_options *interface_opts,
    cap_device_open_err *err, char **err_str)
{
#ifdef HAVE_PCAP_CREATE
	return get_if_capabilities_pcap_create(interface_opts, err, err_str);
#else
	return get_if_capabilities_pcap_open_live(interface_opts, err, err_str);
#endif
}

pcap_t *
open_capture_device_local(capture_options *capture_opts
#ifndef HAVE_PCAP_CREATE
	_U_
#endif
	,
    interface_options *interface_opts, int timeout,
    cap_device_open_err *open_err, char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
	/*
	 * We're not opening a remote device; use pcap_create() and
	 * pcap_activate() if we have them, so that we can set various
	 * options, otherwise use pcap_open_live().
	 */
#ifdef HAVE_PCAP_CREATE
	return open_capture_device_pcap_create(capture_opts,
	    interface_opts, timeout, open_err, open_err_str);
#else
	return open_capture_device_pcap_open_live(interface_opts, timeout,
	    open_err, open_err_str);
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
#ifdef HAVE_PCAP_REMOTE
	/*
	 * We have remote pcap support in libpcap.
	 */
	g_string_append(str, " (including remote capture support)");
#endif

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
	g_string_append(str, pcap_lib_version());
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
