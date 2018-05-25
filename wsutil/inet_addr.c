/* inet_addr.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "inet_addr.h"

#include <errno.h>
#include <string.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>		/* needed to define AF_ values on UNIX */
#endif

#ifdef _WIN32
#include <Ws2tcpip.h>	/* indirectly defines AF_ values on Windows */
#define _NTOP_SRC_CAST_ (PVOID)
#else
#define _NTOP_SRC_CAST_
#endif

/*
 * We assume and require an inet_pton/inet_ntop that supports AF_INET
 * and AF_INET6.
 */

static inline gboolean
_inet_pton(int af, const gchar *src, gpointer dst)
{
    gint ret = inet_pton(af, src, dst);
    if (G_UNLIKELY(ret < 0)) {
        /* EAFNOSUPPORT */
        if (af == AF_INET) {
            memset(dst, 0, sizeof(struct in_addr));
            g_critical("ws_inet_pton4: EAFNOSUPPORT");
        }
        else if (af == AF_INET6) {
            memset(dst, 0, sizeof(struct in6_addr));
            g_critical("ws_inet_pton6: EAFNOSUPPORT");
        }
        else {
            g_assert(0);
        }
        errno = EAFNOSUPPORT;
    }
    return ret == 1;
}

static inline const gchar *
_inet_ntop(int af, gconstpointer src, gchar *dst, guint dst_size)
{
    const gchar *ret = inet_ntop(af, _NTOP_SRC_CAST_ src, dst, dst_size);
    if (G_UNLIKELY(ret == NULL)) {
        int saved_errno = errno;
        gchar *errmsg = "<<ERROR>>";
        switch (errno) {
            case EAFNOSUPPORT:
                errmsg = "<<EAFNOSUPPORT>>";
                g_critical("ws_inet_ntop: EAFNOSUPPORT");
                break;
            case ENOSPC:
                errmsg = "<<ENOSPC>>";
                break;
            default:
                break;
        }
        /* set result to something that can't be confused with a valid conversion */
        g_strlcpy(dst, errmsg, dst_size);
        /* set errno for caller */
        errno = saved_errno;
    }
    return dst;
}

const gchar *
ws_inet_ntop4(gconstpointer src, gchar *dst, guint dst_size)
{
    return _inet_ntop(AF_INET, src, dst, dst_size);
}

gboolean
ws_inet_pton4(const gchar *src, guint32 *dst)
{
    return _inet_pton(AF_INET, src, dst);
}

const gchar *
ws_inet_ntop6(gconstpointer src, gchar *dst, guint dst_size)
{
    return _inet_ntop(AF_INET6, src, dst, dst_size);
}

gboolean
ws_inet_pton6(const gchar *src, ws_in6_addr *dst)
{
    return _inet_pton(AF_INET6, src, dst);
}
