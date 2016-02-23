/* extcap_base.h
 * Base function for extcaps
 *
 * Copyright 2016, Dario Lombardo
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
#ifndef __EXTCAP_BASE_H__
#define __EXTCAP_BASE_H__

#include "config.h"

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef HAVE_GETOPT_H
	#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
	#include "wsutil/wsgetopt.h"
#endif

#ifdef _WIN32
	#include <io.h>
#endif

#if defined(_WIN32) && !defined(__CYGWIN__)
	#ifdef HAVE_WINDOWS_H
		#include <windows.h>
	#endif

	#include <ws2tcpip.h>

	#ifdef HAVE_WINSOCK2_H
		#include <winsock2.h>
	#endif

	#include <process.h>

	#define socket_handle_t SOCKET
#else
	/*
	 * UN*X, or Windows pretending to be UN*X with the aid of Cygwin.
	 */
	#define closesocket(socket)	close(socket)
	#define socket_handle_t		int
	#define INVALID_SOCKET		(-1)
	#define SOCKET_ERROR		(-1)
#endif

#ifdef HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#define EXTCAP_BASE_OPTIONS_ENUM \
	EXTCAP_OPT_LIST_INTERFACES, \
	EXTCAP_OPT_VERSION, \
	EXTCAP_OPT_LIST_DLTS, \
	EXTCAP_OPT_INTERFACE, \
	EXTCAP_OPT_CONFIG, \
	EXTCAP_OPT_CAPTURE, \
	EXTCAP_OPT_CAPTURE_FILTER, \
	EXTCAP_OPT_FIFO \


#define EXTCAP_BASE_OPTIONS \
	{ "extcap-interfaces",		no_argument,		NULL, EXTCAP_OPT_LIST_INTERFACES}, \
	{ "extcap-version", 		optional_argument,	NULL, EXTCAP_OPT_VERSION}, \
	{ "extcap-dlts",		no_argument,		NULL, EXTCAP_OPT_LIST_DLTS}, \
	{ "extcap-interface",		required_argument,	NULL, EXTCAP_OPT_INTERFACE}, \
	{ "extcap-config",		no_argument,		NULL, EXTCAP_OPT_CONFIG}, \
	{ "capture",			no_argument,		NULL, EXTCAP_OPT_CAPTURE}, \
	{ "extcap-capture-filter",	required_argument,	NULL, EXTCAP_OPT_CAPTURE_FILTER}, \
	{ "fifo",			required_argument,	NULL, EXTCAP_OPT_FIFO} \

#if defined(_WIN32)
	BOOLEAN IsHandleRedirected(DWORD handle);
	void attach_parent_console();
#endif

#define errmsg_print(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }

typedef struct _extcap_parameters
{
	char * fifo;
	char * interface;
	char * capture_filter;

	char * version;
	char * helppage;
	uint8_t capture;
	uint8_t show_config;

	/* private content */
	GList * interfaces;
	uint8_t do_version;
	uint8_t do_list_dlts;
	uint8_t do_list_interfaces;

} extcap_parameters;

void extcap_base_register_interface(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltdescription );
void extcap_base_register_interface_ext(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltname, const char * dltdescription );
void extcap_base_set_util_info(extcap_parameters * extcap, const char * major, const char * minor, const char * release, const char * helppage);
uint8_t extcap_base_parse_options(extcap_parameters * extcap, int result, char * optargument);
uint8_t extcap_base_handle_interface(extcap_parameters * extcap);
void extcap_base_cleanup(extcap_parameters ** extcap);

#endif

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
