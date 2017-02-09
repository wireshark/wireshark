/* socket.h
 * Socket wrappers
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
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "config.h"

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
	#define socklen_t int
#else
	/*
	 * UN*X, or Windows pretending to be UN*X with the aid of Cygwin.
	 */
	#ifdef HAVE_UNISTD_H
		/*
		 * For close().
		 */
		#include <unistd.h>
	#endif
	#ifdef HAVE_SYS_SOCKET_H
		#include <sys/socket.h>
	#endif

	#define closesocket(socket)	close(socket)
	#define socket_handle_t		int
	#define INVALID_SOCKET		(-1)
	#define SOCKET_ERROR		(-1)
#endif

#ifdef HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#endif /* __SOCKET_H__ */

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
