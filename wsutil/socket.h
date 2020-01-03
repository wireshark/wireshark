/* socket.h
 * Socket wrappers
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "ws_symbol_export.h"

#if defined(_WIN32) && !defined(__CYGWIN__)
	#include <windows.h>
	#include <ws2tcpip.h>
	#include <winsock2.h>
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
#ifndef INVALID_SOCKET
	#define INVALID_SOCKET		(-1)
#endif
	#define SOCKET_ERROR		(-1)
#endif

#ifdef HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Initialize sockets.
 *
 * Returns NULL on success, a g_malloc()ed error message on failure.
 */
WS_DLL_PUBLIC gchar *ws_init_sockets(void);

/*
 * Clean up sockets.
 */
WS_DLL_PUBLIC void ws_cleanup_sockets(void);

/*
 * Convert the strings ipv4_address:port or [ipv6_address]:port to a
 * sockaddr object. Ports are optional. Receives default port
 * in host byte order.
 */
WS_DLL_PUBLIC int
ws_socket_ptoa(struct sockaddr_storage *dst, const gchar *src,
			guint16 def_port);

#ifdef	__cplusplus
}
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
