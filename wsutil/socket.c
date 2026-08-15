/* socket.c
 * Socket wrappers
 *
 * Copyright 2019, Gerald Combs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#ifdef HAVE_STRUCT_UCRED
// defined in sys/socket.h
#define _GNU_SOURCE // For struct ucred on Linux
#endif
#include "socket.h"

#include <stdlib.h>
#include <errno.h>

#if defined(HAVE_GETPEEREID)
#include <unistd.h>
#endif

#if defined(HAVE_GETPEERUCRED)
#include <ucred.h> // For Solaris/Illumos ucred-related routines
#endif

#include <wsutil/inet_addr.h>

#ifdef _WIN32
#include <objbase.h>
#include <wsutil/unicode-utils.h>
#include <wsutil/win32-utils.h>
#define in_port_t   uint16_t
# ifdef HAVE_AF_UNIX
# include <afunix.h>
# endif
#endif

char *
ws_init_sockets(void)
{
    char    *errmsg = NULL;
#ifdef _WIN32
    int      err;
    WORD     wVersionRequested;
    WSADATA  wsaData;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        errmsg = ws_strdup_printf("Couldn't initialize Windows Sockets: %s",
                                 win32strerror(err));
    }
#endif
    return errmsg;
}

void
ws_cleanup_sockets(void)
{
#ifdef _WIN32
    /* XXX - any reason to check the error return? */
    WSACleanup();
#endif
}

int
ws_socket_ptoa(struct sockaddr_storage *dst, const char *src,
                    uint16_t def_port)
{
    int ret = -1, af = -1;
    char *addr_src, *p;
    char *addr_str = NULL, *port_str = NULL;
    union {
        ws_in4_addr ip4;
        ws_in6_addr ip6;
    } addr;
    char *endptr;
    long num;
    in_port_t port;

    addr_src = g_strdup(src);

    /* Is it an IPv6/IPv4 literal address enclosed in braces? */
    if (*addr_src == '[') {
        addr_str = addr_src + 1;
        if ((p = strchr(addr_str, ']')) == NULL) {
            errno = EINVAL;
            goto out;
        }
        *p++ = '\0';
        if (*p == ':') {
            port_str = p + 1;
        }
        else if (*p != '\0') {
            errno = EINVAL;
            goto out;
        }
        if (ws_inet_pton6(addr_str, &addr.ip6)) {
            af = AF_INET6;
        }
        else if (ws_inet_pton4(addr_str, &addr.ip4)) {
            af = AF_INET;
        }
        else {
            errno = EINVAL;
            goto out;
        }
    }
    else {
        /* It is an IPv4 dotted decimal. */
        addr_str = addr_src;
        if ((p = strchr(addr_str, ':')) != NULL) {
            *p++ = '\0';
            port_str = p;
        }
        if (ws_inet_pton4(addr_str, &addr.ip4)) {
            af = AF_INET;
        }
        else {
            errno = EINVAL;
            goto out;
        }
    }

    if (port_str != NULL && *port_str != '\0') {
        num = strtol(port_str, &endptr, 10);
        /* We want the entire string to be a valid decimal representation. */
        if (endptr == port_str || *endptr != '\0' || num < 0 || num > UINT16_MAX) {
            errno = EINVAL;
            goto out;
        }
        port = g_htons(num);
    }
    else {
        port = g_htons(def_port);
    }

    /* sockaddr_storage is guaranteed to fit any sockaddr type. */
    if (af == AF_INET6) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)dst;
        memset(sa, 0, sizeof(struct sockaddr_in6));
        sa->sin6_family = AF_INET6;
        sa->sin6_port = port;
        memcpy(&sa->sin6_addr, &addr.ip6, sizeof(struct in6_addr));
        ret = 0;
    }
    else if (af == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)dst;
        memset(sa, 0, sizeof(struct sockaddr_in));
        sa->sin_family = AF_INET;
        sa->sin_port = port;
        memcpy(&sa->sin_addr, &addr.ip4, sizeof(struct in_addr));
        ret = 0;
    }
    else {
        ws_assert_not_reached();
    }

out:
    g_free(addr_src);
    return ret;
}

#ifndef _WIN32
    // Non-Windows OSes; try to provide something that acts like
    // BSD getpeereid(), which returns the peer's EUID and EGID.
static int ws_getpeereid(int sock, uid_t *euid, gid_t *egid) {
#if defined(HAVE_GETPEEREID)
    // The BSDs and some other platforms, including Solaris 11.4 SRU 81
    // and AIX at least as far back as 5.3
    return getpeereid(sock, euid, egid);
#elif defined(HAVE_GETPEERUCRED)
    // Solaris/Illumos without getpeereid()
    struct ucred *cred;
    bool peer_euid_is_ours;

    if (getpeerucred(sock, ucred) == -1) {
        return -1;
    }

    *euid = ucred_geteuid(ucred);
    *guid = ucred_getegid(ucred);
    return 0;
#elif defined(HAVE_STRUCT_UCRED)
    // Linux, Haiku
    struct ucred cred;
    socklen_t len = sizeof(struct ucred);

    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
        return -1;
    }

    *euid = cred.uid;
    *egid = cred.gid;
    return 0;
#else
    // Other platforms - just fail
    // Suppress unused argument warnings
    (void) sock;
    (void) euid;
    (void) egid;
    errno = EOPNOTSUPP;
    return false;
#endif
}

bool ws_verify_peercred(socket_handle_t sock) {
    uid_t euid;
    gid_t egid;

    if (ws_getpeereid(sock, &euid, &egid) == -1) {
        return false;
    }

    return geteuid() == euid;
}
#else /* _WIN32 */
bool ws_verify_peercred(socket_handle_t sock _U_) {
    // Windows, now that it supports Unix domain sockets through an
    // implementation as Named Pipes, might support a way to retrieve
    // the user credentials of the peer too.
    //
    // However, we only use this right now for abstract domain sockets,
    // which we only support under Linux (and only Linux supports).
    return false;
}
#endif /* _WIN32 */

int ws_socketpair(int type, socket_handle_t sv[2])
{
#ifdef HAVE_AF_UNIX
# ifdef _WIN32
    // Win32 now has AF_UNIX, but doesn't have socketpair
    int e;
    SOCKET listen_sock = INVALID_SOCKET;
    SOCKET pair[2] = { INVALID_SOCKET, INVALID_SOCKET };

    listen_sock = socket(AF_UNIX, type, 0);
    if (listen_sock == INVALID_SOCKET) return -1;

    /* Create a random temporary filename. */
    GString *tempname = g_string_new(g_get_tmp_dir());
    GUID guid;
    CoCreateGuid(&guid);
    wchar_t wideGuid[40];
    StringFromGUID2(&guid, wideGuid, 40);

    g_string_append_printf(tempname, "\\sock_%s", utf_16to8(wideGuid));

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    (void)g_strlcpy(sa.sun_path, tempname->str, sizeof(sa.sun_path));
    if (bind(listen_sock, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) goto fail;
    if (listen(listen_sock, 1) == SOCKET_ERROR) goto fail;

    pair[0] = socket(AF_UNIX, type, 0);
    if (pair[0] == INVALID_SOCKET) goto fail;
    if (connect(pair[0], (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) goto fail;

    pair[1] = accept(listen_sock, NULL, NULL);
    if (pair[1] == INVALID_SOCKET) goto fail;

    closesocket(listen_sock);
    DeleteFileA(tempname->str);
    g_string_free(tempname, true);

    /* Make it POSIX-like and not modify the contents of sv on failure. */
    sv[0] = pair[0];
    sv[1] = pair[1];
    return 0;
fail:
    e = WSAGetLastError();
    if (listen_sock != INVALID_SOCKET) {
        closesocket(listen_sock);
        DeleteFileA(tempname->str);
    }
    g_string_free(tempname, true);
    if (pair[0] != INVALID_SOCKET) closesocket(listen_sock);
    if (pair[1] != INVALID_SOCKET) closesocket(listen_sock);
    WSASetLastError(e);
    return -1;
# else /* _WIN32 */
    return socketpair(AF_UNIX, type, 0, sv);
# endif
#else /* HAVE_AF_UNIX */
    /* Even all supported Windows has AF_UNIX now. We could try to
     * fake something with loopback sockets. */
    errno = EAFNOSUPPORT;
    return -1;
#endif
}
