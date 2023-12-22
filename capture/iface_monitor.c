/* iface_monitor.c
 * interface monitor by Pontus Fuchs <pontus.fuchs@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "iface_monitor.h"

#ifdef HAVE_LIBPCAP

#if defined(HAVE_LIBNL)

/*
 * Linux with libnl.
 *
 * Use Netlink to get indications of new/removed intrfaces.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

DIAG_OFF_PEDANTIC
#include <netlink/msg.h>
DIAG_ON_PEDANTIC
#include <netlink/attr.h>
DIAG_OFF_PEDANTIC
#include <netlink/route/link.h>
DIAG_ON_PEDANTIC

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

#ifdef HAVE_LIBNL1
    cb(ifname, 0, up);
#else
    int msg_type = nl_object_get_msgtype(obj);

    switch (msg_type) {
    case RTM_NEWLINK:
        cb(ifname, 1, up);
        break;
    case RTM_DELLINK:
        cb(ifname, 0, 0);
        break;
    default:
        /* Ignore other events */
        break;
    }
#endif

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
 * macOS.
 *
 * Use a PF_SYSTEM socket to get indications of new/removed intrfaces.
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
    snprintf(ifr_name, IFNAMSIZ, "%s%u", evd->if_name, evd->if_unit);

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
        callback(ifr_name, 1, 1);
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
        callback(ifr_name, 0, 0);
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

#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)

/*
 * FreeBSD, NetBSD, OpenBSD, DragonFly BSD.
 *
 * Use a PF_ROUTE socket to get indications of new/removed intrfaces.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/in_var.h>

static int s;
static iface_mon_cb callback;

int
iface_mon_start(iface_mon_cb cb)
{
#ifdef RO_MSGFILTER
    unsigned char msgfilter[] = {
        RTM_IFANNOUNCE,
    };
#endif

    /* Create a socket of type PF_ROUTE to listen for events. */
    s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s == -1)
        return -errno;

#ifdef RO_MSGFILTER
    /*
     * This OS supports filtering PF_ROUTE sockets for specific
     * events; we only want interface announcement events.
     *
     * If this fails, we just live with extra events that we ignore,
     * which we also do on platforms that don't support filtering.
     */
    (void) setsockopt(s, PF_ROUTE, RO_MSGFILTER, &msgfilter, sizeof msgfilter);
#endif
#ifdef SO_RERROR
    /*
     * This OS supports getting error reports from recvmsg() if a
     * receive buffer overflow occurs.  If that happens, it means
     * that we may have lost interface reports, so we should
     * probably just refetch all interface data.
     *
     * If we can't get those error reports, we're out of luck.
     */
    int n = 1;
    (void) setsockopt(s, SOL_SOCKET, SO_RERROR, &n, sizeof(n));
#endif

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

void
iface_mon_event(void)
{
    union msgbuf {
        char buf[2048];
        struct rt_msghdr hd;
        struct if_announcemsghdr ifan;
    } msgbuf;
    struct iovec iov[1];
    struct msghdr msg;
    bool message_seen = false;
    ssize_t received;

    iov[0].iov_base = &msgbuf;
    iov[0].iov_len = sizeof msgbuf;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    while (!message_seen) {
        received = recvmsg(s, &msg, 0);
        if (received == -1) {
            if (errno == ENOBUFS) {
                /*
                 * Receive buffer overflow.  Keep reading,
                 * to get any messages in the socket buffer.
                 *
                 * XXX - that means we may have lost indications;
                 * should there be a callback that indicates that
                 * all interface data should be refreshed?
                 */
                continue;
            } else {
                /*
                 * Other error - just ignore.
                 */
                return;
            }
        }

        /*
         * We've seen a message.
         */
        message_seen = true;
    }
    if (received != 0) {
        /*
         * XXX - should we check received, to make sure it's large
         * enough?
         */
        if (msgbuf.hd.rtm_version != RTM_VERSION)
            return;

        switch (msgbuf.hd.rtm_type) {

        case RTM_IFANNOUNCE:
            switch (msgbuf.ifan.ifan_what) {

            case IFAN_ARRIVAL:
                /*
                 * A new interface has arrived.
                 *
                 * XXX - see comment about interface arrivals in the
                 * macOS section; it applies here as well.
                 */
                callback(msgbuf.ifan.ifan_name, 1, 1);
                break;

            case IFAN_DEPARTURE:
                /*
                 * An existing interface has been removed.
                 */
                callback(msgbuf.ifan.ifan_name, 0, 0);
                break;

            default:
                /*
                 * Ignore other notifications.
                 */
                break;
            }
            break;

        default:
            /*
             * Ignore other messages.
             */
            break;
        }
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
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
