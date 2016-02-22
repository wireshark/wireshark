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

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>

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

#define EXTCAP_BASE_OPTIONS_ENUM \
	OPT_LIST_INTERFACES, \
	OPT_LIST_DLTS, \
	OPT_INTERFACE, \
	OPT_CONFIG, \
	OPT_CAPTURE, \
	OPT_CAPTURE_FILTER, \
	OPT_FIFO \


#define EXTCAP_BASE_OPTIONS \
	{ "extcap-interfaces",		no_argument,		NULL, OPT_LIST_INTERFACES}, \
	{ "extcap-dlts",		no_argument,		NULL, OPT_LIST_DLTS}, \
	{ "extcap-interface",		required_argument,	NULL, OPT_INTERFACE}, \
	{ "extcap-config",		no_argument,		NULL, OPT_CONFIG}, \
	{ "capture",			no_argument,		NULL, OPT_CAPTURE}, \
	{ "extcap-capture-filter",	required_argument,	NULL, OPT_CAPTURE_FILTER}, \
	{ "fifo",			required_argument,	NULL, OPT_FIFO} \

#ifdef _WIN32
BOOLEAN IsHandleRedirected(DWORD handle);
void attach_parent_console();
#endif

#define errmsg_print(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }

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
