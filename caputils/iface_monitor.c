/* iface_monitor.c
 * interface monitor by Pontus Fuchs <pontus.fuchs@gmail.com>
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

#include <config.h>

#ifdef HAVE_LIBPCAP

#include <caputils/iface_monitor.h>

#if defined(HAVE_LIBNL)

/*
 * Linux with libnl.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

DIAG_OFF(pedantic)
#include <netlink/msg.h>
DIAG_ON(pedantic)
#include <netlink/attr.h>
DIAG_OFF(pedantic)
#include <netlink/route/link.h>
DIAG_ON(pedantic)

#ifndef IFF_UP
/*
 * Apparently, some versions of libnl drag in headers that define IFF_UP
 * and others don't.  Include <net/if.h> iff IFF_UP isn't already defined,
 * so that if <linux/if.h> has been included by some or all of the
 * netlink headers, we don't include <net/if.h> and get a bunch of
 * complaints about various structures being redefined.
 */
#include <net/if.h>
#endif

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
    iface_mon_cb cb = (iface_mon_cb)arg;

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

    /*
     * You can't bind a PF_PACKET socket to an interface that's not
     * up, so an interface going down is an "interface should be
     * removed" indication.
     *
     * XXX - what indication, if any, do we get if the interface
     * *completely goes away*?
     *
     * XXX - can we get events if an interface's link-layer or
     * network addresses change?
     */
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
    int err;

    iface_mon_sock = nl_socket_alloc();
    if (!iface_mon_sock) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -ENOMEM;
    }

    nl_socket_disable_seq_check(iface_mon_sock);

    nl_socket_modify_cb(iface_mon_sock, NL_CB_VALID, NL_CB_CUSTOM, iface_mon_handler, (void *)cb);

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
iface_mon_stop(void)
{
    if(iface_mon_sock)
        nl_socket_free(iface_mon_sock);
    iface_mon_sock = NULL;
}

#elif defined(__APPLE__)

/*
 * OS X.
 */

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/kern_event.h>

#include <glib.h>

static int s;
static iface_mon_cb callback;

int
iface_mon_start(iface_mon_cb cb)
{
    int ret;
    struct kev_request key;

    /* Create a socket of type PF_SYSTEM to listen for events. */
    s = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
    if (s == -1)
        return -errno;

    /*
     * Ask for DLIL messages.
     *
     * XXX - also ask for KEV_INET_SUBCLASS and KEV_INET6_SUBCLASS,
     * to detect new or changed network addresses, so those can be
     * updated as well?  Can we specify multiple filters on a socket,
     * or must we specify KEV_ANY_SUBCLASS and filter the events after
     * receiving them?
     */
    key.vendor_code = KEV_VENDOR_APPLE;
    key.kev_class = KEV_NETWORK_CLASS;
    key.kev_subclass = KEV_DL_SUBCLASS;
    if (ioctl(s, SIOCSKEVFILT, &key) == -1) {
        ret = -errno;
        close(s);
        return ret;
    }

    callback = cb;
    return 0;
}

void
iface_mon_stop(void)
{
    close(s);
}

int
iface_mon_get_sock(void)
{
    return s;
}

/*
 * Size of buffer for kernel network event.
 */
#define NET_EVENT_DATA_SIZE    (KEV_MSG_HEADER_SIZE + sizeof (struct net_event_data))

void
iface_mon_event(void)
{
    char msg[NET_EVENT_DATA_SIZE];
    ssize_t received;
    struct kern_event_msg *kem;
    struct net_event_data *evd;
    size_t evd_len;
    char ifr_name[IFNAMSIZ];

    received = recv(s, msg, sizeof msg, 0);
    if (received < 0) {
        /* Error - ignore. */
        return;
    }
    if ((size_t)received < sizeof msg) {
        /* Short read - ignore. */
        return;
    }
    kem = (struct kern_event_msg *)msg;
    evd_len = kem->total_size - KEV_MSG_HEADER_SIZE;
    if (evd_len != sizeof (struct net_event_data)) {
        /* Length of the message is bogus. */
        return;
    }
    evd = (struct net_event_data *)&kem->event_data[0];
    g_snprintf(ifr_name, IFNAMSIZ, "%s%u", evd->if_name, evd->if_unit);

    /*
     * Check type of event.
     *
     * Note: if we also ask for KEV_INET_SUBCLASS, we will get
     * events with keys
     *
     *    KEV_INET_NEW_ADDR
     *    KEV_INET_CHANGED_ADDR
     *    KEV_INET_CHANGED_ADDR
     *    KEV_INET_SIFDSTADDR
     *    KEV_INET_SIFBRDADDR
     *    KEV_INET_SIFNETMASK
     *
     * reflecting network address changes, with the data being a
     * struct kev_in_data rather than struct net_event_data, and
     * if we also ask for KEV_INET6_SUBCLASS, we will get events
     * with keys
     *
     *    KEV_INET6_NEW_LL_ADDR
     *    KEV_INET6_NEW_USER_ADDR
     *    KEV_INET6_NEW_RTADV_ADDR
     *    KEV_INET6_ADDR_DELETED
     *
     * with the data being a struct kev_in6_data.
     */
    switch (kem->event_code) {

    case KEV_DL_IF_ATTACHED:
        /*
         * A new interface has arrived.
         *
         * XXX - what we really want is "a new BPFable interface
         * has arrived", but that's not available.  While we're
         * asking for additional help from BPF, it'd also be
         * nice if we could ask it for a list of all interfaces
         * that have had bpfattach()/bpf_attach() done on them,
         * so we don't have to try to open the device in order
         * to see whether we should show it as something on
         * which we can capture.
         */
        callback(ifr_name, 1);
        break;

    case KEV_DL_IF_DETACHED:
        /*
         * An existing interface has been removed.
         *
         * XXX - use KEV_DL_IF_DETACHING instead, as that's
         * called shortly after bpfdetach() is called, and
         * bpfdetach() makes an interface no longer BPFable,
         * and that's what we *really* care about.
         */
        callback(ifr_name, 0);
        break;

    default:
        /*
         * Is there any reason to care about:
         *
         *    KEV_DL_LINK_ON
         *    KEV_DL_LINK_OFF
         *    KEV_DL_SIFFLAGS
         *    KEV_DL_LINK_ADDRESS_CHANGED
         *    KEV_DL_IFCAP_CHANGED
         *
         * or any of the other events?  On Snow Leopard and, I think,
         * earlier releases, you can't attach a BPF device to an
         * interface that's not up, so KEV_DL_SIFFLAGS might be
         * worth listening to so that we only say "here's a new
         * interface" when it goes up; on Lion (and possibly Mountain
         * Lion), an interface doesn't have to be up in order to
         * have a BPF device attached to it.
         */
        break;
    }
}

#else /* don't have something we support */

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

#endif /* HAVE_LIBPCAP */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
