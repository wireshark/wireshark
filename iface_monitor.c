/* iface_monitor.c
 * interface monitor by Pontus Fuchs <pontus.fuchs@gmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#include "config.h"
#include "iface_monitor.h"

#ifdef HAVE_LIBNL

#include <stdio.h>
#include <strings.h>
#include <errno.h>

#include <net/if.h>

#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/route/link.h>

/* libnl 1.x compatibility code */
#ifdef HAVE_LIBNL1
#define nl_sock nl_handle
#define nl_socket_disable_seq_check nl_disable_sequence_check

static inline struct nl_handle *nl_socket_alloc(void)
{
    return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
    nl_handle_destroy(h);
}
#endif /* HAVE_LIBNL1 */

static struct nl_sock *iface_mon_sock;

static void
iface_mon_handler2(struct nl_object *obj, void *arg)
{
    struct rtnl_link *filter;
    struct rtnl_link *link_obj;
    int flags, up;
    char *ifname;
    iface_mon_cb cb = arg;

    filter = rtnl_link_alloc();
    if (!filter) {
        fprintf(stderr, "error allocating filter\n");
        return;
    }

    if (nl_object_match_filter (obj, OBJ_CAST (filter)) == 0) {
        rtnl_link_put(filter);
        return;
    }

    link_obj = (struct rtnl_link *) obj;
    flags = rtnl_link_get_flags (link_obj);
    ifname = rtnl_link_get_name(link_obj);

    up = (flags & IFF_UP) ? 1 : 0;

    cb(ifname, up);

    rtnl_link_put(filter);

    return;
}

static int
iface_mon_handler(struct nl_msg *msg, void *arg)
{
    nl_msg_parse (msg, &iface_mon_handler2, arg);
    return 0;
}

static int
iface_mon_nl_init(void *arg)
{
    int err;

    iface_mon_sock = nl_socket_alloc();
    if (!iface_mon_sock) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -ENOMEM;
    }

    nl_socket_disable_seq_check(iface_mon_sock);

    nl_socket_modify_cb(iface_mon_sock, NL_CB_VALID, NL_CB_CUSTOM, iface_mon_handler, arg);

    if (nl_connect(iface_mon_sock, NETLINK_ROUTE)) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        err = -ENOLINK;
        goto out_handle_destroy;
    }

    nl_socket_add_membership(iface_mon_sock, RTNLGRP_LINK);

    return 0;

out_handle_destroy:
    nl_socket_free(iface_mon_sock);
    return err;
}

void
iface_mon_event(void)
{
    nl_recvmsgs_default(iface_mon_sock);
}

int
iface_mon_get_sock(void)
{
    return nl_socket_get_fd(iface_mon_sock);
}

int
iface_mon_start(iface_mon_cb cb)
{
    return iface_mon_nl_init(cb);
}

void
iface_mon_stop(void)
{
    if(iface_mon_sock)
        nl_socket_free(iface_mon_sock);
    iface_mon_sock = NULL;
}

#else /* HAVE_LIBNL */

int
iface_mon_start(iface_mon_cb cb _U_)
{
    return -1;
}

void
iface_mon_stop(void)
{
}

int
iface_mon_get_sock(void)
{
    return -1;
}

void
iface_mon_event(void)
{
}

#endif /* HAVE_LIBNL */
