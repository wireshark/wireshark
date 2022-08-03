/* addr_resolv.c
 * Routines for network object lookup
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Add option to resolv VLAN ID to describing name
 * Uli Heilmeier, March 2016
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <wsutil/strtoi.h>
#include <wsutil/ws_assert.h>

/*
 * Win32 doesn't have SIGALRM (and it's the OS where name lookup calls
 * are most likely to take a long time, given the way address-to-name
 * lookups are done over NBNS).
 *
 * macOS does have SIGALRM, but if you longjmp() out of a name resolution
 * call in a signal handler, you might crash, because the state of the
 * resolution code that sends messages to lookupd might be inconsistent
 * if you jump out of it in middle of a call.
 *
 * There's no guarantee that longjmp()ing out of name resolution calls
 * will work on *any* platform; OpenBSD got rid of the alarm/longjmp
 * code in tcpdump, to avoid those sorts of problems, and that was
 * picked up by tcpdump.org tcpdump.
 *
 * So, for now, we do not use alarm() and SIGALRM to time out host name
 * lookups.  If we get a lot of complaints about lookups taking a long time,
 * we can reconsider that decision.  (Note that tcpdump originally added
 * such a timeout mechanism that for the benefit of systems using NIS to
 * look up host names; that might now be fixed in NIS implementations, for
 * those sites still using NIS rather than DNS for that....  tcpdump no
 * longer does that, for the same reasons that we don't.)
 *
 * If we're using an asynchronous DNS resolver, that shouldn't be an issue.
 * If we're using a synchronous name lookup mechanism (which we'd do mainly
 * to support resolving addresses and host names using more mechanisms than
 * just DNS, such as NIS, NBNS, or Mr. Hosts File), we could do that in
 * a separate thread, making it, in effect, asynchronous.
 */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>     /* needed to define AF_ values on UNIX */
#endif

#ifdef _WIN32
#include <winsock2.h>       /* needed to define AF_ values on Windows */
#include <ws2tcpip.h>
#endif

#ifdef _WIN32
# define socklen_t unsigned int
#endif
#include <ares.h>
#include <ares_version.h>

#include <glib.h>

#include "packet.h"
#include "addr_and_mask.h"
#include "ipv6.h"
#include "addr_resolv.h"
#include "wsutil/filesystem.h"

#include <wsutil/report_message.h>
#include <wsutil/file_util.h>
#include <wsutil/pint.h>
#include <wsutil/inet_addr.h>

#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/maxmind_db.h>
#include <epan/prefs.h>
#include <epan/uat.h>

#define ENAME_HOSTS     "hosts"
#define ENAME_SUBNETS   "subnets"
#define ENAME_ETHERS    "ethers"
#define ENAME_IPXNETS   "ipxnets"
#define ENAME_MANUF     "manuf"
#define ENAME_WKA       "wka"
#define ENAME_SERVICES  "services"
#define ENAME_VLANS     "vlans"
#define ENAME_SS7PCS    "ss7pcs"
#define ENAME_ENTERPRISES "enterprises.tsv"

#define HASHETHSIZE      2048
#define HASHHOSTSIZE     2048
#define HASHIPXNETSIZE    256
#define SUBNETLENGTHSIZE   32  /*1-32 inc.*/

/* hash table used for IPv4 lookup */

#define HASH_IPV4_ADDRESS(addr) (g_htonl(addr) & (HASHHOSTSIZE - 1))


typedef struct sub_net_hashipv4 {
    guint             addr;
    /* XXX: No longer needed?*/
    guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
    struct sub_net_hashipv4   *next;
    gchar             name[MAXNAMELEN];
} sub_net_hashipv4_t;

/* Array of entries of subnets of different lengths */
typedef struct {
    gsize        mask_length;      /*1-32*/
    guint32      mask;             /* e.g. 255.255.255.*/
    sub_net_hashipv4_t** subnet_addresses; /* Hash table of subnet addresses */
} subnet_length_entry_t;


/* hash table used for IPX network lookup */

/* XXX - check goodness of hash function */

#define HASH_IPX_NET(net)   ((net) & (HASHIPXNETSIZE - 1))

typedef struct hashipxnet {
    guint               addr;
    struct hashipxnet  *next;
    gchar               name[MAXNAMELEN];
} hashipxnet_t;

typedef struct hashvlan {
    guint               id;
/*    struct hashvlan     *next; */
    gchar               name[MAXVLANNAMELEN];
} hashvlan_t;

typedef struct ss7pc {
    guint32             id; /* 1st byte NI, 3 following bytes: Point Code */
    gchar               pc_addr[MAXNAMELEN];
    gchar               name[MAXNAMELEN];
} hashss7pc_t;

/* hash tables used for ethernet and manufacturer lookup */
#define HASHETHER_STATUS_UNRESOLVED     1
#define HASHETHER_STATUS_RESOLVED_DUMMY 2
#define HASHETHER_STATUS_RESOLVED_NAME  3

struct hashether {
    guint             status;  /* (See above) */
    guint8            addr[6];
    char              hexaddr[6*3];
    char              resolved_name[MAXNAMELEN];
};

struct hashmanuf {
    guint             status;  /* (See above) */
    guint8            addr[3];
    char              hexaddr[3*3];
    char              resolved_name[MAXNAMELEN];
    char              resolved_longname[MAXNAMELEN];
};

/* internal ethernet type */
typedef struct _ether
{
    guint8            addr[6];
    char              name[MAXNAMELEN];
    char              longname[MAXNAMELEN];
} ether_t;

/* internal ipxnet type */
typedef struct _ipxnet
{
    guint             addr;
    char              name[MAXNAMELEN];
} ipxnet_t;

/* internal vlan type */
typedef struct _vlan
{
    guint             id;
    char              name[MAXVLANNAMELEN];
} vlan_t;

// Maps guint -> hashipxnet_t*
static wmem_map_t *ipxnet_hash_table = NULL;
static wmem_map_t *ipv4_hash_table = NULL;
static wmem_map_t *ipv6_hash_table = NULL;
// Maps guint -> hashvlan_t*
static wmem_map_t *vlan_hash_table = NULL;
static wmem_map_t *ss7pc_hash_table = NULL;

// Maps IP address -> manually set hostname.
static wmem_map_t *manually_resolved_ipv4_list = NULL;
static wmem_map_t *manually_resolved_ipv6_list = NULL;

static addrinfo_lists_t addrinfo_lists = { NULL, NULL};

struct cb_serv_data {
    gchar       *service;
    port_type    proto;
};

// Maps guint -> hashmanuf_t*
static wmem_map_t *manuf_hashtable = NULL;
static wmem_map_t *wka_hashtable = NULL;
static wmem_map_t *eth_hashtable = NULL;
// Maps guint -> serv_port_t*
static wmem_map_t *serv_port_hashtable = NULL;
static GHashTable *enterprises_hashtable = NULL;

static subnet_length_entry_t subnet_length_entries[SUBNETLENGTHSIZE]; /* Ordered array of entries */
static gboolean have_subnet_entry = FALSE;

static gboolean new_resolved_objects = FALSE;

static GPtrArray* extra_hosts_files = NULL;

static hashether_t *add_eth_name(const guint8 *addr, const gchar *name);
static void add_serv_port_cb(const guint32 port, gpointer ptr);

/* http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx#existing
 * One-at-a-Time hash
 */
guint
ipv6_oat_hash(gconstpointer key)
{
    int len = 16;
    const unsigned char *p = (const unsigned char *)key;
    guint h = 0;
    int i;

    for ( i = 0; i < len; i++ ) {
        h += p[i];
        h += ( h << 10 );
        h ^= ( h >> 6 );
    }

    h += ( h << 3 );
    h ^= ( h >> 11 );
    h += ( h << 15 );

    return h;
}

gboolean
ipv6_equal(gconstpointer v1, gconstpointer v2)
{

    if (memcmp(v1, v2, sizeof (ws_in6_addr)) == 0) {
        return TRUE;
    }

    return FALSE;
}

/*
 * Flag controlling what names to resolve.
 */
e_addr_resolve gbl_resolv_flags = {
    TRUE,   /* mac_name */
    FALSE,  /* network_name */
    FALSE,  /* transport_name */
    TRUE,   /* dns_pkt_addr_resolution */
    TRUE,   /* use_external_net_name_resolver */
    FALSE,  /* load_hosts_file_from_profile_only */
    FALSE,  /* vlan_name */
    FALSE   /* ss7 point code names */
};
static guint name_resolve_concurrency = 500;
static gboolean resolve_synchronously = FALSE;

/*
 *  Global variables (can be changed in GUI sections)
 *  XXX - they could be changed in GUI code, but there's currently no
 *  GUI code to change them.
 */

gchar *g_ethers_path    = NULL;     /* global ethers file     */
gchar *g_pethers_path   = NULL;     /* personal ethers file   */
gchar *g_wka_path       = NULL;     /* global well-known-addresses file */
gchar *g_manuf_path     = NULL;     /* global manuf file      */
gchar *g_ipxnets_path   = NULL;     /* global ipxnets file    */
gchar *g_pipxnets_path  = NULL;     /* personal ipxnets file  */
gchar *g_services_path  = NULL;     /* global services file   */
gchar *g_pservices_path = NULL;     /* personal services file */
gchar *g_pvlan_path     = NULL;     /* personal vlans file    */
gchar *g_ss7pcs_path    = NULL;     /* personal ss7pcs file   */
gchar *g_enterprises_path = NULL;   /* global enterprises file   */
gchar *g_penterprises_path = NULL;  /* personal enterprises file */
                                    /* first resolving call   */

/*
 * Submitted asynchronous queries trigger a callback (c_ares_ghba_cb()).
 * Queries are added to c_ares_queue_head. During processing, queries are
 * popped off the front of c_ares_queue_head and submitted using
 * ares_gethostbyaddr().
 * The callback processes the response, then frees the request.
 */
typedef struct _async_dns_queue_msg
{
    union {
        guint32           ip4;
        ws_in6_addr ip6;
    } addr;
    int                 family;
} async_dns_queue_msg_t;

typedef struct _async_hostent {
    int addr_size;
    int   copied;
    void *addrp;
} async_hostent_t;

/*
 * Submitted synchronous queries trigger a callback (c_ares_ghba_sync_cb()).
 * The callback processes the response, sets completed to TRUE if
 * completed is non-NULL, then frees the request.
 */
typedef struct _sync_dns_data
{
    union {
        guint32      ip4;
        ws_in6_addr  ip6;
    } addr;
    int              family;
    gboolean        *completed;
} sync_dns_data_t;

static ares_channel ghba_chan; /* ares_gethostbyaddr -- Usually non-interactive, no timeout */
static ares_channel ghbn_chan; /* ares_gethostbyname -- Usually interactive, timeout */

static  gboolean  async_dns_initialized = FALSE;
static  guint       async_dns_in_flight = 0;
static  wmem_list_t *async_dns_queue_head = NULL;

//UAT for providing a list of DNS servers to C-ARES for name resolution
gboolean use_custom_dns_server_list = FALSE;
struct dns_server_data {
    char *ipaddr;
    guint32 udp_port;
    guint32 tcp_port;
};

UAT_CSTRING_CB_DEF(dnsserverlist_uats, ipaddr, struct dns_server_data)
UAT_DEC_CB_DEF(dnsserverlist_uats, tcp_port, struct dns_server_data)
UAT_DEC_CB_DEF(dnsserverlist_uats, udp_port, struct dns_server_data)

static uat_t *dnsserver_uat = NULL;
static struct dns_server_data  *dnsserverlist_uats = NULL;
static guint ndnsservers = 0;

static void
dns_server_free_cb(void *data)
{
    struct dns_server_data *h = (struct dns_server_data*)data;

    g_free(h->ipaddr);
}

static void*
dns_server_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    const struct dns_server_data *src = (const struct dns_server_data *)src_;
    struct dns_server_data       *dst = (struct dns_server_data *)dst_;

    dst->ipaddr = g_strdup(src->ipaddr);
    dst->udp_port = src->udp_port;
    dst->tcp_port = src->tcp_port;

    return dst;
}

static gboolean
dnsserver_uat_fld_ip_chk_cb(void* r _U_, const char* ipaddr, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    //Check for a valid IPv4 or IPv6 address.
    if (ipaddr && g_hostname_is_ip_address(ipaddr)) {
        *err = NULL;
        return TRUE;
    }

    *err = ws_strdup_printf("No valid IP address given.");
    return FALSE;
}

static gboolean
dnsserver_uat_fld_port_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char** err)
{
    if (!p || strlen(p) == 0u) {
        // This should be removed in favor of Decode As. Make it optional.
        *err = NULL;
        return TRUE;
    }

    if (strcmp(p, "53") != 0){
        guint16 port;
        if (!ws_strtou16(p, NULL, &port)) {
            *err = g_strdup("Invalid port given.");
            return FALSE;
        }
    }

    *err = NULL;
    return TRUE;
}

static void
c_ares_ghba_sync_cb(void *arg, int status, int timeouts _U_, struct hostent *he) {
    sync_dns_data_t *sdd = (sync_dns_data_t *)arg;
    char **p;

    if (status == ARES_SUCCESS) {
        for (p = he->h_addr_list; *p != NULL; p++) {
            switch(sdd->family) {
                case AF_INET:
                    add_ipv4_name(sdd->addr.ip4, he->h_name);
                    break;
                case AF_INET6:
                    add_ipv6_name(&sdd->addr.ip6, he->h_name);
                    break;
                default:
                    /* Throw an exception? */
                    break;
            }
        }

    }

    /*
     * Let our caller know that this is complete.
     */
    *sdd->completed = TRUE;

    /*
     * Free the structure for this call.
     */
    g_free(sdd);
}

static void
wait_for_sync_resolv(gboolean *completed) {
    int nfds;
    fd_set rfds, wfds;
    struct timeval tv;

    while (!*completed) {
        /*
         * Not yet resolved; wait for something to show up on the
         * address-to-name C-ARES channel.
         *
         * To quote the source code for ares_timeout() as of C-ARES
         * 1.12.0, "WARNING: Beware that this is linear in the number
         * of outstanding requests! You are probably far better off
         * just calling ares_process() once per second, rather than
         * calling ares_timeout() to figure out when to next call
         * ares_process().", although we should have only one request
         * outstanding.
         *
         * And, yes, we have to reset it each time, as select(), in
         * some OSes modifies the timeout to reflect the time remaining
         * (e.g., Linux) and select() in other OSes doesn't (most if not
         * all other UN*Xes, Windows?), so we can't rely on *either*
         * behavior.
         */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        nfds = ares_fds(ghba_chan, &rfds, &wfds);
        if (nfds > 0) {
            if (select(nfds, &rfds, &wfds, NULL, &tv) == -1) { /* call to select() failed */
                /* If it's interrupted by a signal, no need to put out a message */
                if (errno != EINTR)
                    fprintf(stderr, "Warning: call to select() failed, error is %s\n", g_strerror(errno));
                return;
            }
            ares_process(ghba_chan, &rfds, &wfds);
        }
    }
}

static void
sync_lookup_ip4(const guint32 addr)
{
    gboolean completed = FALSE;
    sync_dns_data_t *sdd;

    if (!async_dns_initialized) {
        /*
         * c-ares not initialized.  Bail out.
         */
        return;
    }

    /*
     * Start the request.
     */
    sdd = g_new(sync_dns_data_t, 1);
    sdd->family = AF_INET;
    sdd->addr.ip4 = addr;
    sdd->completed = &completed;
    ares_gethostbyaddr(ghba_chan, &addr, sizeof(guint32), AF_INET,
                       c_ares_ghba_sync_cb, sdd);

    /*
     * Now wait for it to finish.
     */
    wait_for_sync_resolv(&completed);
}

static void
sync_lookup_ip6(const ws_in6_addr *addr)
{
    gboolean completed = FALSE;
    sync_dns_data_t *sdd;

    if (!async_dns_initialized) {
        /*
         * c-ares not initialized.  Bail out.
         */
        return;
    }

    /*
     * Start the request.
     */
    sdd = g_new(sync_dns_data_t, 1);
    sdd->family = AF_INET6;
    memcpy(&sdd->addr.ip6, addr, sizeof(sdd->addr.ip6));
    sdd->completed = &completed;
    ares_gethostbyaddr(ghba_chan, &addr, sizeof(ws_in6_addr), AF_INET6,
                       c_ares_ghba_sync_cb, sdd);

    /*
     * Now wait for it to finish.
     */
    wait_for_sync_resolv(&completed);
}

void
set_resolution_synchrony(gboolean synchronous)
{
    resolve_synchronously = synchronous;
    maxmind_db_set_synchrony(synchronous);
}

static void
c_ares_set_dns_servers(void)
{
    if ((!async_dns_initialized) || (!use_custom_dns_server_list))
        return;

    if (ndnsservers == 0) {
        //clear the list of servers.  This may effectively disable name resolution
        ares_set_servers_ports(ghba_chan, NULL);
        ares_set_servers_ports(ghbn_chan, NULL);
    } else {
        struct ares_addr_port_node* servers = wmem_alloc_array(NULL, struct ares_addr_port_node, ndnsservers);
        ws_in4_addr ipv4addr;
        ws_in6_addr ipv6addr;
        gboolean invalid_IP_found = FALSE;
        struct ares_addr_port_node* server;
        guint i;
        for (i = 0, server = servers; i < ndnsservers-1; i++, server++) {
            if (ws_inet_pton6(dnsserverlist_uats[i].ipaddr, &ipv6addr)) {
                server->family = AF_INET6;
                memcpy(&server->addr.addr6, &ipv6addr, 16);
            } else if (ws_inet_pton4(dnsserverlist_uats[i].ipaddr, &ipv4addr)) {
                server->family = AF_INET;
                memcpy(&server->addr.addr4, &ipv4addr, 4);
            } else {
                //This shouldn't happen, but just in case...
                invalid_IP_found = TRUE;
                server->family = 0;
                memset(&server->addr.addr4, 0, 4);
                break;
            }

            server->udp_port = (int)dnsserverlist_uats[i].udp_port;
            server->tcp_port = (int)dnsserverlist_uats[i].tcp_port;

            server->next = (server+1);
        }
        if (!invalid_IP_found) {
            if (ws_inet_pton6(dnsserverlist_uats[i].ipaddr, &ipv6addr)) {
                server->family = AF_INET6;
                memcpy(&server->addr.addr6, &ipv6addr, 16);
            }
            else if (ws_inet_pton4(dnsserverlist_uats[i].ipaddr, &ipv4addr)) {
                server->family = AF_INET;
                memcpy(&server->addr.addr4, &ipv4addr, 4);
            } else {
                //This shouldn't happen, but just in case...
                server->family = 0;
                memset(&server->addr.addr4, 0, 4);
            }
        }
        server->udp_port = (int)dnsserverlist_uats[i].udp_port;
        server->tcp_port = (int)dnsserverlist_uats[i].tcp_port;

        server->next = NULL;

        ares_set_servers_ports(ghba_chan, servers);
        ares_set_servers_ports(ghbn_chan, servers);
        wmem_free(NULL, servers);
    }
}

typedef struct {
    guint32      mask;
    gsize        mask_length;
    const gchar* name; /* Shallow copy */
} subnet_entry_t;

/* Maximum supported line length of hosts, services, manuf, etc. */
#define MAX_LINELEN     1024

/** Read a line without trailing (CR)LF. Returns -1 on failure.  */
static int
fgetline(char *buf, int size, FILE *fp)
{
    if (fgets(buf, size, fp)) {
        int len = (int)strcspn(buf, "\r\n");
        buf[len] = '\0';
        return len;
    }
    return -1;

} /* fgetline */


/*
 *  Local function definitions
 */
static subnet_entry_t subnet_lookup(const guint32 addr);
static void subnet_entry_set(guint32 subnet_addr, const guint8 mask_length, const gchar* name);


static void
add_service_name(port_type proto, const guint port, const char *service_name)
{
    serv_port_t *serv_port_table;

    serv_port_table = (serv_port_t *)wmem_map_lookup(serv_port_hashtable, GUINT_TO_POINTER(port));
    if (serv_port_table == NULL) {
        serv_port_table = wmem_new0(wmem_epan_scope(), serv_port_t);
        wmem_map_insert(serv_port_hashtable, GUINT_TO_POINTER(port), serv_port_table);
    }

    switch(proto) {
        case PT_TCP:
            wmem_free(wmem_epan_scope(), serv_port_table->tcp_name);
            serv_port_table->tcp_name = wmem_strdup(wmem_epan_scope(), service_name);
            break;
        case PT_UDP:
            wmem_free(wmem_epan_scope(), serv_port_table->udp_name);
            serv_port_table->udp_name = wmem_strdup(wmem_epan_scope(), service_name);
            break;
        case PT_SCTP:
            wmem_free(wmem_epan_scope(), serv_port_table->sctp_name);
            serv_port_table->sctp_name = wmem_strdup(wmem_epan_scope(), service_name);
            break;
        case PT_DCCP:
            wmem_free(wmem_epan_scope(), serv_port_table->dccp_name);
            serv_port_table->dccp_name = wmem_strdup(wmem_epan_scope(), service_name);
            break;
        default:
            return;
            /* Should not happen */
    }

    new_resolved_objects = TRUE;
}


static void
parse_service_line (char *line)
{
    gchar *cp;
    gchar *service;
    gchar *port;
    port_type proto;
    struct cb_serv_data cb_data;
    range_t *port_rng = NULL;

    if ((cp = strchr(line, '#')))
        *cp = '\0';

    if ((cp = strtok(line, " \t")) == NULL)
        return;

    service = cp;

    if ((cp = strtok(NULL, " \t")) == NULL)
        return;

    port = cp;

    if (strtok(cp, "/") == NULL)
        return;

    if (range_convert_str(NULL, &port_rng, port, G_MAXUINT16) != CVT_NO_ERROR) {
        wmem_free (NULL, port_rng);
        return;
    }

    while ((cp = strtok(NULL, "/")) != NULL) {
        if (strcmp(cp, "tcp") == 0) {
            proto = PT_TCP;
        }
        else if (strcmp(cp, "udp") == 0) {
            proto = PT_UDP;
        }
        else if (strcmp(cp, "sctp") == 0) {
            proto = PT_SCTP;
        }
        else if (strcmp(cp, "dccp") == 0) {
            proto = PT_DCCP;
        }
        else {
            break;
        }
        cb_data.service = service;
        cb_data.proto = proto;
        range_foreach(port_rng, add_serv_port_cb, &cb_data);
    }

    wmem_free (NULL, port_rng);
} /* parse_service_line */


static void
add_serv_port_cb(const guint32 port, gpointer ptr)
{
    struct cb_serv_data *cb_data = (struct cb_serv_data *)ptr;

    if ( port ) {
        add_service_name(cb_data->proto, port, cb_data->service);
    }
}


static gboolean
parse_services_file(const char * path)
{
    FILE *serv_p;
    char    buf[MAX_LINELEN];

    /* services hash table initialization */
    serv_p = ws_fopen(path, "r");

    if (serv_p == NULL)
        return FALSE;

    while (fgetline(buf, sizeof(buf), serv_p) >= 0) {
        parse_service_line(buf);
    }

    fclose(serv_p);
    return TRUE;
}

/* -----------------
 * unsigned integer to ascii
 */
static gchar *
wmem_utoa(wmem_allocator_t *allocator, guint port)
{
    gchar *bp = (gchar *)wmem_alloc(allocator, MAXNAMELEN);

    /* XXX, guint32_to_str() ? */
    guint32_to_str_buf(port, bp, MAXNAMELEN);
    return bp;
}

static const gchar *
_serv_name_lookup(port_type proto, guint port, serv_port_t **value_ret)
{
    serv_port_t *serv_port_table;

    serv_port_table = (serv_port_t *)wmem_map_lookup(serv_port_hashtable, GUINT_TO_POINTER(port));

    if (value_ret != NULL)
        *value_ret = serv_port_table;

    if (serv_port_table == NULL)
        return NULL;

    switch (proto) {
        case PT_UDP:
            return serv_port_table->udp_name;
        case PT_TCP:
            return serv_port_table->tcp_name;
        case PT_SCTP:
            return serv_port_table->sctp_name;
        case PT_DCCP:
            return serv_port_table->dccp_name;
        default:
            break;
    }
    return NULL;
}

const gchar *
try_serv_name_lookup(port_type proto, guint port)
{
    return _serv_name_lookup(proto, port, NULL);
}

const gchar *
serv_name_lookup(port_type proto, guint port)
{
    serv_port_t *serv_port_table = NULL;
    const char *name;

    name = _serv_name_lookup(proto, port, &serv_port_table);
    if (name != NULL)
        return name;

    if (serv_port_table == NULL) {
        serv_port_table = wmem_new0(wmem_epan_scope(), serv_port_t);
        wmem_map_insert(serv_port_hashtable, GUINT_TO_POINTER(port), serv_port_table);
    }
    if (serv_port_table->numeric == NULL) {
        serv_port_table->numeric = wmem_strdup_printf(wmem_epan_scope(), "%u", port);
    }

    return serv_port_table->numeric;
}

static void
initialize_services(void)
{
    gboolean parse_file = TRUE;
    ws_assert(serv_port_hashtable == NULL);
    serv_port_hashtable = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    /* Compute the pathname of the services file. */
    if (g_services_path == NULL) {
        g_services_path = get_datafile_path(ENAME_SERVICES);
    }
    parse_services_file(g_services_path);

    /* Compute the pathname of the personal services file */
    if (g_pservices_path == NULL) {
        /* Check profile directory before personal configuration */
        g_pservices_path = get_persconffile_path(ENAME_SERVICES, TRUE);
        if (!parse_services_file(g_pservices_path)) {
            g_free(g_pservices_path);
            g_pservices_path = get_persconffile_path(ENAME_SERVICES, FALSE);
        } else {
            parse_file = FALSE;
        }
    }
    if (parse_file) {
        parse_services_file(g_pservices_path);
    }
}

static void
service_name_lookup_cleanup(void)
{
    serv_port_hashtable = NULL;
    g_free(g_services_path);
    g_services_path = NULL;
    g_free(g_pservices_path);
    g_pservices_path = NULL;
}

static void
parse_enterprises_line (char *line)
{
    char *tok, *dec_str, *org_str;
    guint32 dec;
    gboolean had_comment = FALSE;

    /* Stop the line at any comment found */
    if ((tok = strchr(line, '#'))) {
        *tok = '\0';
        had_comment = TRUE;
    }
    /* Get enterprise number */
    dec_str = strtok(line, " \t");
    if (!dec_str)
        return;
    /* Get enterprise name */
    org_str = strtok(NULL, ""); /* everything else */
    if (org_str && had_comment) {
        /* Only need to strip after (between name and where comment was) */
        org_str = g_strchomp(org_str);
    }
    if (!org_str)
        return;

    /* Add entry using number as key */
    if (!ws_strtou32(dec_str, NULL, &dec))
        return;
    g_hash_table_insert(enterprises_hashtable, GUINT_TO_POINTER(dec), g_strdup(org_str));
}


static gboolean
parse_enterprises_file(const char * path)
{
    FILE *fp;
    char    buf[MAX_LINELEN];

    fp = ws_fopen(path, "r");
    if (fp == NULL)
        return FALSE;

    while (fgetline(buf, sizeof(buf), fp) >= 0) {
        parse_enterprises_line(buf);
    }

    fclose(fp);
    return TRUE;
}

static void
initialize_enterprises(void)
{
    ws_assert(enterprises_hashtable == NULL);
    enterprises_hashtable = g_hash_table_new_full(NULL, NULL, NULL, g_free);

    if (g_enterprises_path == NULL) {
        g_enterprises_path = get_datafile_path(ENAME_ENTERPRISES);
    }
    parse_enterprises_file(g_enterprises_path);

    if (g_penterprises_path == NULL) {
        /* Check profile directory before personal configuration */
        g_penterprises_path = get_persconffile_path(ENAME_ENTERPRISES, TRUE);
        if (!file_exists(g_penterprises_path)) {
            g_free(g_penterprises_path);
            g_penterprises_path = get_persconffile_path(ENAME_ENTERPRISES, FALSE);
        }
    }
    parse_enterprises_file(g_penterprises_path);
}

const gchar *
try_enterprises_lookup(guint32 value)
{
    return (const gchar *)g_hash_table_lookup(enterprises_hashtable, GUINT_TO_POINTER(value));
}

const gchar *
enterprises_lookup(guint32 value, const char *unknown_str)
{
    const gchar *s;

    s = try_enterprises_lookup(value);
    if (s != NULL)
        return s;
    if (unknown_str != NULL)
        return unknown_str;
    return "<Unknown>";
}

void
enterprises_base_custom(char *buf, guint32 value)
{
    const gchar *s;

    if ((s = try_enterprises_lookup(value)) == NULL)
        s = ITEM_LABEL_UNKNOWN_STR;
    snprintf(buf, ITEM_LABEL_LENGTH, "%s (%u)", s, value);
}

static void
enterprises_cleanup(void)
{
    ws_assert(enterprises_hashtable);
    g_hash_table_destroy(enterprises_hashtable);
    enterprises_hashtable = NULL;
    ws_assert(g_enterprises_path);
    g_free(g_enterprises_path);
    g_enterprises_path = NULL;
    g_free(g_penterprises_path);
    g_penterprises_path = NULL;
    g_free(g_pservices_path);
    g_pservices_path = NULL;
}

/* Fill in an IP4 structure with info from subnets file or just with the
 * string form of the address.
 */
static void
fill_dummy_ip4(const guint addr, hashipv4_t* volatile tp)
{
    subnet_entry_t subnet_entry;

    /* Overwrite if we get async DNS reply */

    /* Do we have a subnet for this address? */
    subnet_entry = subnet_lookup(addr);
    if (0 != subnet_entry.mask) {
        /* Print name, then '.' then IP address after subnet mask */
        guint32 host_addr;
        gchar buffer[WS_INET_ADDRSTRLEN];
        gchar* paddr;
        gsize i;

        host_addr = addr & (~subnet_entry.mask);
        ip_to_str_buf((guint8 *)&host_addr, buffer, WS_INET_ADDRSTRLEN);
        paddr = buffer;

        /* Skip to first octet that is not totally masked
         * If length of mask is 32, we chomp the whole address.
         * If the address string starts '.' (should not happen?),
         * we skip that '.'.
         */
        i = subnet_entry.mask_length / 8;
        while(*(paddr) != '\0' && i > 0) {
            if (*(++paddr) == '.') {
                --i;
            }
        }

        /* There are more efficient ways to do this, but this is safe if we
         * trust snprintf and MAXNAMELEN
         */
        snprintf(tp->name, MAXNAMELEN, "%s%s", subnet_entry.name, paddr);
    } else {
        /* XXX: This means we end up printing "1.2.3.4 (1.2.3.4)" in many cases */
        ip_to_str_buf((const guint8 *)&addr, tp->name, MAXNAMELEN);
    }
}


/* Fill in an IP6 structure with the string form of the address.
 */
static void
fill_dummy_ip6(hashipv6_t* volatile tp)
{
    /* Overwrite if we get async DNS reply */
    (void) g_strlcpy(tp->name, tp->ip6, MAXNAMELEN);
}

static void
c_ares_ghba_cb(void *arg, int status, int timeouts _U_, struct hostent *he) {
    async_dns_queue_msg_t *caqm = (async_dns_queue_msg_t *)arg;
    char **p;

    if (!caqm) return;
    /* XXX, what to do if async_dns_in_flight == 0? */
    async_dns_in_flight--;

    if (status == ARES_SUCCESS) {
        for (p = he->h_addr_list; *p != NULL; p++) {
            switch(caqm->family) {
                case AF_INET:
                    add_ipv4_name(caqm->addr.ip4, he->h_name);
                    break;
                case AF_INET6:
                    add_ipv6_name(&caqm->addr.ip6, he->h_name);
                    break;
                default:
                    /* Throw an exception? */
                    break;
            }
        }
    }
    wmem_free(wmem_epan_scope(), caqm);
}

/* --------------- */
static hashipv4_t *
new_ipv4(const guint addr)
{
    hashipv4_t *tp = wmem_new(wmem_epan_scope(), hashipv4_t);
    tp->addr = addr;
    tp->flags = 0;
    tp->name[0] = '\0';
    ip_to_str_buf((const guint8 *)&addr, tp->ip, sizeof(tp->ip));
    return tp;
}

static hashipv4_t *
host_lookup(const guint addr)
{
    hashipv4_t * volatile tp;

    tp = (hashipv4_t *)wmem_map_lookup(ipv4_hash_table, GUINT_TO_POINTER(addr));
    if (tp == NULL) {
        /*
         * We don't already have an entry for this host name; create one,
         * and then try to resolve it.
         */
        tp = new_ipv4(addr);
        fill_dummy_ip4(addr, tp);
        wmem_map_insert(ipv4_hash_table, GUINT_TO_POINTER(addr), tp);
    } else if (tp->flags & TRIED_OR_RESOLVED_MASK) {
        return tp;
    }

    /*
     * This hasn't been resolved yet, and we haven't tried to
     * resolve it already.
     */

    if (!gbl_resolv_flags.network_name)
        return tp;

    if (gbl_resolv_flags.use_external_net_name_resolver) {
        tp->flags |= TRIED_RESOLVE_ADDRESS;

        if (async_dns_initialized) {
            /* c-ares is initialized, so we can use it */
            if (resolve_synchronously || name_resolve_concurrency == 0) {
                /*
                 * Either all names are to be resolved synchronously or
                 * the concurrencly level is 0; do the resolution
                 * synchronously.
                 */
                sync_lookup_ip4(addr);
            } else {
                /*
                 * Names are to be resolved asynchronously, and we
                 * allow at least one asynchronous request in flight;
                 * post an asynchronous request.
                 */
                async_dns_queue_msg_t *caqm;

                caqm = wmem_new(wmem_epan_scope(), async_dns_queue_msg_t);
                caqm->family = AF_INET;
                caqm->addr.ip4 = addr;
                wmem_list_append(async_dns_queue_head, (gpointer) caqm);
            }
        }
    }

    return tp;

} /* host_lookup */

/* --------------- */
static hashipv6_t *
new_ipv6(const ws_in6_addr *addr)
{
    hashipv6_t *tp = wmem_new(wmem_epan_scope(), hashipv6_t);
    memcpy(tp->addr, addr->bytes, sizeof tp->addr);
    tp->flags = 0;
    tp->name[0] = '\0';
    ip6_to_str_buf(addr, tp->ip6, sizeof(tp->ip6));
    return tp;
}

/* ------------------------------------ */
static hashipv6_t *
host_lookup6(const ws_in6_addr *addr)
{
    hashipv6_t * volatile tp;

    tp = (hashipv6_t *)wmem_map_lookup(ipv6_hash_table, addr);
    if (tp == NULL) {
        /*
         * We don't already have an entry for this host name; create one,
         * and then try to resolve it.
         */
        ws_in6_addr *addr_key;

        addr_key = wmem_new(wmem_epan_scope(), ws_in6_addr);
        tp = new_ipv6(addr);
        memcpy(addr_key, addr, 16);
        fill_dummy_ip6(tp);
        wmem_map_insert(ipv6_hash_table, addr_key, tp);
    } else if (tp->flags & TRIED_OR_RESOLVED_MASK) {
        return tp;
    }

    /*
     * This hasn't been resolved yet, and we haven't tried to
     * resolve it already.
     */

    if (!gbl_resolv_flags.network_name)
        return tp;

    if (gbl_resolv_flags.use_external_net_name_resolver) {
        tp->flags |= TRIED_RESOLVE_ADDRESS;

        if (async_dns_initialized) {
            /* c-ares is initialized, so we can use it */
            if (resolve_synchronously || name_resolve_concurrency == 0) {
                /*
                 * Either all names are to be resolved synchronously or
                 * the concurrencly level is 0; do the resolution
                 * synchronously.
                 */
                sync_lookup_ip6(addr);
            } else {
                /*
                 * Names are to be resolved asynchronously, and we
                 * allow at least one asynchronous request in flight;
                 * post an asynchronous request.
                 */
                async_dns_queue_msg_t *caqm;

                caqm = wmem_new(wmem_epan_scope(), async_dns_queue_msg_t);
                caqm->family = AF_INET6;
                memcpy(&caqm->addr.ip6, addr, sizeof(caqm->addr.ip6));
                wmem_list_append(async_dns_queue_head, (gpointer) caqm);
            }
        }
    }

    return tp;

} /* host_lookup6 */

/*
 * Ethernet / manufacturer resolution
 *
 * The following functions implement ethernet address resolution and
 * ethers files parsing (see ethers(4)).
 *
 * The manuf file has the same format as ethers(4) except that names are
 * truncated to MAXMANUFLEN-1 (8) characters and that an address contains
 * only 3 bytes (instead of 6).
 *
 * Notes:
 *
 * I decide to not use the existing functions (see ethers(3) on some
 * operating systems) for the following reasons:
 * - performance gains (use of hash tables and some other enhancements),
 * - use of two ethers files (system-wide and per user),
 * - avoid the use of NIS maps,
 * - lack of these functions on some systems.
 *
 * So the following functions do _not_ behave as the standard ones.
 *
 * -- Laurent.
 */

/*
 * Converts Ethernet addresses of the form aa:bb:cc or aa:bb:cc:dd:ee:ff/28.
 * '-' is also supported as a separator. The
 * octets must be exactly two hexadecimal characters and the mask must be either
 * 28 or 36. Pre-condition: cp MUST be at least 21 bytes.
 */
static gboolean
parse_ether_address_fast(const guchar *cp, ether_t *eth, unsigned int *mask,
        const gboolean accept_mask)
{
    /* XXX copied from strutil.c */
    /* a map from ASCII hex chars to their value */
    static const gint8 str_to_nibble[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    const guint8 *str_to_nibble_usg = (const guint8 *)str_to_nibble;

    guchar sep = cp[2];
    if ((sep != ':' && sep != '-') || cp[5] != sep) {
        /* Unexpected separators. */
        return FALSE;
    }

    /* N.B. store octet values in an int to detect invalid (-1) entries */
    int num0 = (str_to_nibble_usg[cp[0]] << 4) | (gint8)str_to_nibble_usg[cp[1]];
    int num1 = (str_to_nibble_usg[cp[3]] << 4) | (gint8)str_to_nibble_usg[cp[4]];
    int num2 = (str_to_nibble_usg[cp[6]] << 4) | (gint8)str_to_nibble_usg[cp[7]];

    if ((num0 | num1 | num2) & 0x100) {
        /* Not hexadecimal numbers. */
        return FALSE;
    }

    eth->addr[0] = (guint8)num0;
    eth->addr[1] = (guint8)num1;
    eth->addr[2] = (guint8)num2;

    if (cp[8] == '\0' && accept_mask) {
        /* Indicate that this is a manufacturer ID (0 is not allowed as a mask). */
        *mask = 0;
        return TRUE;
    } else if (cp[8] != sep || !accept_mask) {
        /* Format not handled by this fast path. */
        return FALSE;
    }

    /* N.B. store octet values in an int to detect invalid (-1) entries */
    int num3 = (str_to_nibble_usg[cp[9]]  << 4) | (gint8)str_to_nibble_usg[cp[10]];
    int num4 = (str_to_nibble_usg[cp[12]] << 4) | (gint8)str_to_nibble_usg[cp[13]];
    int num5 = (str_to_nibble_usg[cp[15]] << 4) | (gint8)str_to_nibble_usg[cp[16]];

    if (((num3 | num4 | num5) & 0x100) || cp[11] != sep || cp[14] != sep)  {
        /* Not hexadecimal numbers or invalid separators. */
        return FALSE;
    }

    eth->addr[3] = (guint8)num3;
    eth->addr[4] = (guint8)num4;
    eth->addr[5] = (guint8)num5;
    if (cp[17] == '\0') {
        /* We got 6 bytes, so this is a MAC address (48 is not allowed as a mask). */
        *mask = 48;
        return TRUE;
    } else if (cp[17] != '/' || cp[20] != '\0') {
        /* Format not handled by this fast path. */
        return FALSE;
    }

    int m1 = cp[18];
    int m2 = cp[19];
    if (m1 == '3' && m2 == '6') {   /* Mask /36 */
        eth->addr[4] &= 0xf0;
        eth->addr[5] = 0;
        *mask = 36;
        return TRUE;
    }
    if (m1 == '2' && m2 == '8') {   /* Mask /28 */
        eth->addr[3] &= 0xf0;
        eth->addr[4] = 0;
        eth->addr[5] = 0;
        *mask = 28;
        return TRUE;
    }
    /* Unsupported mask */
    return FALSE;
}

/*
 * If "accept_mask" is FALSE, cp must point to an address that consists
 * of exactly 6 bytes.
 * If "accept_mask" is TRUE, parse an up-to-6-byte sequence with an optional
 * mask.
 */
static gboolean
parse_ether_address(const char *cp, ether_t *eth, unsigned int *mask,
        const gboolean accept_mask)
{
    int i;
    unsigned long num;
    char *p;
    char sep = '\0';

    for (i = 0; i < 6; i++) {
        /* Get a hex number, 1 or 2 digits, no sign characters allowed. */
        if (!g_ascii_isxdigit(*cp))
            return FALSE;
        num = strtoul(cp, &p, 16);
        if (p == cp)
            return FALSE; /* failed */
        if (num > 0xFF)
            return FALSE; /* not a valid octet */
        eth->addr[i] = (guint8) num;
        cp = p;     /* skip past the number */

        /* OK, what character terminated the octet? */
        if (*cp == '/') {
            /* "/" - this has a mask. */
            if (!accept_mask) {
                /* Entries with masks are not allowed in this file. */
                return FALSE;
            }
            cp++; /* skip past the '/' to get to the mask */
            if (!g_ascii_isdigit(*cp))
                return FALSE;   /* no sign allowed */
            num = strtoul(cp, &p, 10);
            if (p == cp)
                return FALSE;   /* failed */
            cp = p;   /* skip past the number */
            if (*cp != '\0' && !g_ascii_isspace(*cp))
                return FALSE;   /* bogus terminator */
            if (num == 0 || num >= 48)
                return FALSE;   /* bogus mask */
            /* Mask out the bits not covered by the mask */
            *mask = (int)num;
            for (i = 0; num >= 8; i++, num -= 8)
                ;   /* skip octets entirely covered by the mask */
            /* Mask out the first masked octet */
            eth->addr[i] &= (0xFF << (8 - num));
            i++;
            /* Mask out completely-masked-out octets */
            for (; i < 6; i++)
                eth->addr[i] = 0;
            return TRUE;
        }
        if (*cp == '\0') {
            /* We're at the end of the address, and there's no mask. */
            if (i == 2) {
                /* We got 3 bytes, so this is a manufacturer ID. */
                if (!accept_mask) {
                    /* Manufacturer IDs are not allowed in this file */
                    return FALSE;
                }
                /* Indicate that this is a manufacturer ID (0 is not allowed
                   as a mask). */
                *mask = 0;
                return TRUE;
            }

            if (i == 5) {
                /* We got 6 bytes, so this is a MAC address (48 is not allowed as a mask). */
                if (accept_mask)
                    *mask = 48;
                return TRUE;
            }

            /* We didn't get 3 or 6 bytes, and there's no mask; this is
               illegal. */
            return FALSE;
        } else {
            if (sep == '\0') {
                /* We don't know the separator used in this number; it can either
                   be ':', '-', or '.'. */
                if (*cp != ':' && *cp != '-' && *cp != '.')
                    return FALSE;
                sep = *cp;  /* subsequent separators must be the same */
            } else {
                /* It has to be the same as the first separator */
                if (*cp != sep)
                    return FALSE;
            }
        }
        cp++;
    }

    return TRUE;
}

static int
parse_ether_line(char *line, ether_t *eth, unsigned int *mask,
        const gboolean accept_mask)
{
    /*
     *  See the ethers(4) or ethers(5) man page for ethers file format
     *  (not available on all systems).
     *  We allow both ethernet address separators (':' and '-'),
     *  as well as Wireshark's '.' separator.
     */

    gchar *cp;

    line = g_strstrip(line);
    if (line[0] == '\0' || line[0] == '#')
        return -1;

    if ((cp = strchr(line, '#'))) {
        *cp = '\0';
        g_strchomp(line);
    }

    if ((cp = strtok(line, " \t")) == NULL)
        return -1;

    /* First try to match the common format for the large ethers file. */
    if (!parse_ether_address_fast(cp, eth, mask, accept_mask)) {
        /* Fallback for the well-known addresses (wka) file. */
        if (!parse_ether_address(cp, eth, mask, accept_mask))
            return -1;
    }

    if ((cp = strtok(NULL, " \t")) == NULL)
        return -1;

    (void) g_strlcpy(eth->name, cp, MAXNAMELEN);

    if ((cp = strtok(NULL, "\t")) != NULL)
    {
        (void) g_strlcpy(eth->longname, cp, MAXNAMELEN);
    } else {
        /* Make the long name the short name */
        (void) g_strlcpy(eth->longname, eth->name, MAXNAMELEN);
    }

    return 0;

} /* parse_ether_line */

static FILE *eth_p = NULL;

static void
set_ethent(char *path)
{
    if (eth_p)
        rewind(eth_p);
    else
        eth_p = ws_fopen(path, "r");
}

static void
end_ethent(void)
{
    if (eth_p) {
        fclose(eth_p);
        eth_p = NULL;
    }
}

static ether_t *
get_ethent(unsigned int *mask, const gboolean accept_mask)
{

    static ether_t eth;
    char    buf[MAX_LINELEN];

    if (eth_p == NULL)
        return NULL;

    while (fgetline(buf, sizeof(buf), eth_p) >= 0) {
        if (parse_ether_line(buf, &eth, mask, accept_mask) == 0) {
            return &eth;
        }
    }

    return NULL;

} /* get_ethent */

static ether_t *
get_ethbyaddr(const guint8 *addr)
{

    ether_t *eth;

    set_ethent(g_pethers_path);

    while (((eth = get_ethent(NULL, FALSE)) != NULL) && memcmp(addr, eth->addr, 6) != 0)
        ;

    if (eth == NULL) {
        end_ethent();

        set_ethent(g_ethers_path);

        while (((eth = get_ethent(NULL, FALSE)) != NULL) && memcmp(addr, eth->addr, 6) != 0)
            ;

        end_ethent();
    }

    return eth;

} /* get_ethbyaddr */

static hashmanuf_t *
manuf_hash_new_entry(const guint8 *addr, char* name, char* longname)
{
    guint manuf_key;
    hashmanuf_t *manuf_value;
    char *endp;

    /* manuf needs only the 3 most significant octets of the ethernet address */
    manuf_key = (addr[0] << 16) + (addr[1] << 8) + addr[2];
    manuf_value = wmem_new(wmem_epan_scope(), hashmanuf_t);

    memcpy(manuf_value->addr, addr, 3);
    if (name != NULL) {
        (void) g_strlcpy(manuf_value->resolved_name, name, MAXNAMELEN);
        manuf_value->status = HASHETHER_STATUS_RESOLVED_NAME;
        if (longname != NULL) {
            (void) g_strlcpy(manuf_value->resolved_longname, longname, MAXNAMELEN);
        }
        else {
            (void) g_strlcpy(manuf_value->resolved_longname, name, MAXNAMELEN);
        }
    }
    else {
        manuf_value->status = HASHETHER_STATUS_UNRESOLVED;
        manuf_value->resolved_name[0] = '\0';
        manuf_value->resolved_longname[0] = '\0';
    }
    /* Values returned by bytes_to_hexstr_punct() are *not* null-terminated */
    endp = bytes_to_hexstr_punct(manuf_value->hexaddr, addr, sizeof(manuf_value->addr), ':');
    *endp = '\0';

    wmem_map_insert(manuf_hashtable, GUINT_TO_POINTER(manuf_key), manuf_value);
    return manuf_value;
}

static void
wka_hash_new_entry(const guint8 *addr, char* name)
{
    guint8 *wka_key;

    wka_key = (guint8 *)wmem_alloc(wmem_epan_scope(), 6);
    memcpy(wka_key, addr, 6);

    wmem_map_insert(wka_hashtable, wka_key, wmem_strdup(wmem_epan_scope(), name));
}

static void
add_manuf_name(const guint8 *addr, unsigned int mask, gchar *name, gchar *longname)
{
    switch (mask)
    {
    case 0:
        /* This is a manufacturer ID; add it to the manufacturer ID hash table */
        manuf_hash_new_entry(addr, name, longname);
        break;

    case 48:
        /* This is a well-known MAC address; add it to the Ethernet hash table */
        add_eth_name(addr, name);
        break;

    default:
        /* This is a range of well-known addresses; add it to the well-known-address table */
        wka_hash_new_entry(addr, name);
        break;
    }
} /* add_manuf_name */

static hashmanuf_t *
manuf_name_lookup(const guint8 *addr)
{
    guint32       manuf_key;
    guint8       oct;
    hashmanuf_t  *manuf_value;

    /* manuf needs only the 3 most significant octets of the ethernet address */
    manuf_key = addr[0];
    manuf_key = manuf_key<<8;
    oct = addr[1];
    manuf_key = manuf_key | oct;
    manuf_key = manuf_key<<8;
    oct = addr[2];
    manuf_key = manuf_key | oct;


    /* first try to find a "perfect match" */
    manuf_value = (hashmanuf_t*)wmem_map_lookup(manuf_hashtable, GUINT_TO_POINTER(manuf_key));
    if (manuf_value != NULL) {
        return manuf_value;
    }

    /* Mask out the broadcast/multicast flag but not the locally
     * administered flag as locally administered means: not assigned
     * by the IEEE but the local administrator instead.
     * 0x01 multicast / broadcast bit
     * 0x02 locally administered bit */
    if ((manuf_key & 0x00010000) != 0) {
        manuf_key &= 0x00FEFFFF;
        manuf_value = (hashmanuf_t*)wmem_map_lookup(manuf_hashtable, GUINT_TO_POINTER(manuf_key));
        if (manuf_value != NULL) {
            return manuf_value;
        }
    }

    /* Add the address as a hex string */
    return manuf_hash_new_entry(addr, NULL, NULL);

} /* manuf_name_lookup */

static gchar *
wka_name_lookup(const guint8 *addr, const unsigned int mask)
{
    guint8     masked_addr[6];
    guint      num;
    gint       i;
    gchar     *name;

    if (wka_hashtable == NULL) {
        return NULL;
    }
    /* Get the part of the address covered by the mask. */
    for (i = 0, num = mask; num >= 8; i++, num -= 8)
        masked_addr[i] = addr[i];   /* copy octets entirely covered by the mask */
    /* Mask out the first masked octet */
    masked_addr[i] = addr[i] & (0xFF << (8 - num));
    i++;
    /* Zero out completely-masked-out octets */
    for (; i < 6; i++)
        masked_addr[i] = 0;

    name = (gchar *)wmem_map_lookup(wka_hashtable, masked_addr);

    return name;

} /* wka_name_lookup */


guint get_hash_ether_status(hashether_t* ether)
{
    return ether->status;
}

char* get_hash_ether_hexaddr(hashether_t* ether)
{
    return ether->hexaddr;
}

char* get_hash_ether_resolved_name(hashether_t* ether)
{
    return ether->resolved_name;
}

static guint
eth_addr_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, 6);
}

static gboolean
eth_addr_cmp(gconstpointer a, gconstpointer b)
{
    return (memcmp(a, b, 6) == 0);
}

static void
initialize_ethers(void)
{
    ether_t *eth;
    guint    mask = 0;

    /* hash table initialization */
    wka_hashtable   = wmem_map_new(wmem_epan_scope(), eth_addr_hash, eth_addr_cmp);
    manuf_hashtable = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    eth_hashtable   = wmem_map_new(wmem_epan_scope(), eth_addr_hash, eth_addr_cmp);

    /* Compute the pathname of the ethers file. */
    if (g_ethers_path == NULL) {
        g_ethers_path = g_build_filename(get_systemfile_dir(), ENAME_ETHERS, NULL);
    }

    /* Set g_pethers_path here, but don't actually do anything
     * with it. It's used in get_ethbyaddr().
     */
    if (g_pethers_path == NULL) {
        /* Check profile directory before personal configuration */
        g_pethers_path = get_persconffile_path(ENAME_ETHERS, TRUE);
        if (!file_exists(g_pethers_path)) {
            g_free(g_pethers_path);
            g_pethers_path = get_persconffile_path(ENAME_ETHERS, FALSE);
        }
    }

    /* Compute the pathname of the manuf file */
    if (g_manuf_path == NULL)
        g_manuf_path = get_datafile_path(ENAME_MANUF);

    /* Read it and initialize the hash table */
    set_ethent(g_manuf_path);
    while ((eth = get_ethent(&mask, TRUE))) {
        add_manuf_name(eth->addr, mask, eth->name, eth->longname);
    }
    end_ethent();

    /* Compute the pathname of the wka file */
    if (g_wka_path == NULL)
        g_wka_path = get_datafile_path(ENAME_WKA);

    /* Read it and initialize the hash table */
    set_ethent(g_wka_path);
    while ((eth = get_ethent(&mask, TRUE))) {
        add_manuf_name(eth->addr, mask, eth->name, eth->longname);
    }
    end_ethent();

} /* initialize_ethers */

static void
ethers_cleanup(void)
{
    g_free(g_ethers_path);
    g_ethers_path = NULL;
    g_free(g_pethers_path);
    g_pethers_path = NULL;
    g_free(g_manuf_path);
    g_manuf_path = NULL;
    g_free(g_wka_path);
    g_wka_path = NULL;
}

/* Resolve ethernet address */
static hashether_t *
eth_addr_resolve(hashether_t *tp) {
    ether_t      *eth;
    hashmanuf_t *manuf_value;
    const guint8 *addr = tp->addr;

    if ( (eth = get_ethbyaddr(addr)) != NULL) {
        (void) g_strlcpy(tp->resolved_name, eth->name, MAXNAMELEN);
        tp->status = HASHETHER_STATUS_RESOLVED_NAME;
        return tp;
    } else {
        guint         mask;
        gchar        *name;
        address       ether_addr;

        /* Unknown name.  Try looking for it in the well-known-address
           tables for well-known address ranges smaller than 2^24. */
        mask = 7;
        do {
            /* Only the topmost 5 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+40)) != NULL) {
                snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x",
                        name, addr[5] & (0xFF >> mask));
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        } while (mask--);

        mask = 7;
        do {
            /* Only the topmost 4 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+32)) != NULL) {
                snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x",
                        name, addr[4] & (0xFF >> mask), addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        } while (mask--);

        mask = 7;
        do {
            /* Only the topmost 3 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+24)) != NULL) {
                snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x",
                        name, addr[3] & (0xFF >> mask), addr[4], addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        } while (mask--);

        /* Now try looking in the manufacturer table. */
        manuf_value = manuf_name_lookup(addr);
        if ((manuf_value != NULL) && (manuf_value->status != HASHETHER_STATUS_UNRESOLVED)) {
            snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x",
                    manuf_value->resolved_name, addr[3], addr[4], addr[5]);
            tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
            return tp;
        }

        /* Now try looking for it in the well-known-address
           tables for well-known address ranges larger than 2^24. */
        mask = 7;
        do {
            /* Only the topmost 2 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+16)) != NULL) {
                snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x",
                        name, addr[2] & (0xFF >> mask), addr[3], addr[4],
                        addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        } while (mask--);

        mask = 7;
        do {
            /* Only the topmost byte participates fully */
            if ((name = wka_name_lookup(addr, mask+8)) != NULL) {
                snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x",
                        name, addr[1] & (0xFF >> mask), addr[2], addr[3],
                        addr[4], addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        } while (mask--);

        mask = 7;
        do {
            /* Not even the topmost byte participates fully */
            if ((name = wka_name_lookup(addr, mask)) != NULL) {
                snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x:%02x",
                        name, addr[0] & (0xFF >> mask), addr[1], addr[2],
                        addr[3], addr[4], addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        } while (--mask); /* Work down to the last bit */

        /* No match whatsoever. */
        set_address(&ether_addr, AT_ETHER, 6, addr);
        address_to_str_buf(&ether_addr, tp->resolved_name, MAXNAMELEN);
        tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
        return tp;
    }
    ws_assert_not_reached();
} /* eth_addr_resolve */

static hashether_t *
eth_hash_new_entry(const guint8 *addr, const gboolean resolve)
{
    hashether_t *tp;
    char *endp;

    tp = wmem_new(wmem_epan_scope(), hashether_t);
    memcpy(tp->addr, addr, sizeof(tp->addr));
    tp->status = HASHETHER_STATUS_UNRESOLVED;
    /* Values returned by bytes_to_hexstr_punct() are *not* null-terminated */
    endp = bytes_to_hexstr_punct(tp->hexaddr, addr, sizeof(tp->addr), ':');
    *endp = '\0';
    tp->resolved_name[0] = '\0';

    if (resolve)
        eth_addr_resolve(tp);

    wmem_map_insert(eth_hashtable, tp->addr, tp);

    return tp;
} /* eth_hash_new_entry */

static hashether_t *
add_eth_name(const guint8 *addr, const gchar *name)
{
    hashether_t *tp;

    tp = (hashether_t *)wmem_map_lookup(eth_hashtable, addr);

    if (tp == NULL) {
        tp = eth_hash_new_entry(addr, FALSE);
    }

    if (strcmp(tp->resolved_name, name) != 0) {
        (void) g_strlcpy(tp->resolved_name, name, MAXNAMELEN);
        tp->status = HASHETHER_STATUS_RESOLVED_NAME;
        new_resolved_objects = TRUE;
    }

    return tp;
} /* add_eth_name */

static hashether_t *
eth_name_lookup(const guint8 *addr, const gboolean resolve)
{
    hashether_t  *tp;

    tp = (hashether_t *)wmem_map_lookup(eth_hashtable, addr);

    if (tp == NULL) {
        tp = eth_hash_new_entry(addr, resolve);
    } else {
        if (resolve && (tp->status == HASHETHER_STATUS_UNRESOLVED)) {
            eth_addr_resolve(tp); /* Found but needs to be resolved */
        }
    }

    return tp;

} /* eth_name_lookup */


/* IPXNETS */
static int
parse_ipxnets_line(char *line, ipxnet_t *ipxnet)
{
    /*
     *  We allow three address separators (':', '-', and '.'),
     *  as well as no separators
     */

    gchar     *cp;
    guint32   a, a0, a1, a2, a3;
    gboolean  found_single_number = FALSE;

    if ((cp = strchr(line, '#')))
        *cp = '\0';

    if ((cp = strtok(line, " \t\n")) == NULL)
        return -1;

    /* Either fill a0,a1,a2,a3 and found_single_number is FALSE,
     * fill a and found_single_number is TRUE,
     * or return -1
     */
    if (sscanf(cp, "%x:%x:%x:%x", &a0, &a1, &a2, &a3) != 4) {
        if (sscanf(cp, "%x-%x-%x-%x", &a0, &a1, &a2, &a3) != 4) {
            if (sscanf(cp, "%x.%x.%x.%x", &a0, &a1, &a2, &a3) != 4) {
                if (sscanf(cp, "%x", &a) == 1) {
                    found_single_number = TRUE;
                }
                else {
                    return -1;
                }
            }
        }
    }

    if ((cp = strtok(NULL, " \t\n")) == NULL)
        return -1;

    if (found_single_number) {
        ipxnet->addr = a;
    }
    else {
        ipxnet->addr = (a0 << 24) | (a1 << 16) | (a2 << 8) | a3;
    }

    (void) g_strlcpy(ipxnet->name, cp, MAXNAMELEN);

    return 0;

} /* parse_ipxnets_line */

static FILE *ipxnet_p = NULL;

static void
set_ipxnetent(char *path)
{
    if (ipxnet_p)
        rewind(ipxnet_p);
    else
        ipxnet_p = ws_fopen(path, "r");
}

static void
end_ipxnetent(void)
{
    if (ipxnet_p) {
        fclose(ipxnet_p);
        ipxnet_p = NULL;
    }
}

static ipxnet_t *
get_ipxnetent(void)
{

    static ipxnet_t ipxnet;
    char    buf[MAX_LINELEN];

    if (ipxnet_p == NULL)
        return NULL;

    while (fgetline(buf, sizeof(buf), ipxnet_p) >= 0) {
        if (parse_ipxnets_line(buf, &ipxnet) == 0) {
            return &ipxnet;
        }
    }

    return NULL;

} /* get_ipxnetent */

static ipxnet_t *
get_ipxnetbyaddr(guint32 addr)
{
    ipxnet_t *ipxnet;

    set_ipxnetent(g_ipxnets_path);

    while (((ipxnet = get_ipxnetent()) != NULL) && (addr != ipxnet->addr) ) ;

    if (ipxnet == NULL) {
        end_ipxnetent();

        set_ipxnetent(g_pipxnets_path);

        while (((ipxnet = get_ipxnetent()) != NULL) && (addr != ipxnet->addr) )
            ;

        end_ipxnetent();
    }

    return ipxnet;

} /* get_ipxnetbyaddr */

static void
initialize_ipxnets(void)
{
    /* Compute the pathname of the ipxnets file.
     *
     * XXX - is there a notion of an "ipxnets file" in any flavor of
     * UNIX, or with any add-on Netware package for UNIX?  If not,
     * should the UNIX version of the ipxnets file be in the datafile
     * directory as well?
     */
    if (g_ipxnets_path == NULL) {
        g_ipxnets_path = wmem_strdup_printf(wmem_epan_scope(), "%s" G_DIR_SEPARATOR_S "%s",
                get_systemfile_dir(), ENAME_IPXNETS);
    }

    /* Set g_pipxnets_path here, but don't actually do anything
     * with it. It's used in get_ipxnetbyaddr().
     */
    if (g_pipxnets_path == NULL) {
        /* Check profile directory before personal configuration */
        g_pipxnets_path = get_persconffile_path(ENAME_IPXNETS, TRUE);
        if (!file_exists(g_pipxnets_path)) {
            g_free(g_pipxnets_path);
            g_pipxnets_path = get_persconffile_path(ENAME_IPXNETS, FALSE);
        }
    }

} /* initialize_ipxnets */

static void
ipx_name_lookup_cleanup(void)
{
    g_free(g_pipxnets_path);
    g_pipxnets_path = NULL;
}

static gchar *
ipxnet_name_lookup(wmem_allocator_t *allocator, const guint addr)
{
    hashipxnet_t *tp;
    ipxnet_t *ipxnet;

    tp = (hashipxnet_t *)wmem_map_lookup(ipxnet_hash_table, GUINT_TO_POINTER(addr));
    if (tp == NULL) {
        tp = wmem_new(wmem_epan_scope(), hashipxnet_t);
        wmem_map_insert(ipxnet_hash_table, GUINT_TO_POINTER(addr), tp);
    } else {
        return wmem_strdup(allocator, tp->name);
    }

    /* fill in a new entry */

    tp->addr = addr;

    if ( (ipxnet = get_ipxnetbyaddr(addr)) == NULL) {
        /* unknown name */
        snprintf(tp->name, MAXNAMELEN, "%X", addr);

    } else {
        (void) g_strlcpy(tp->name, ipxnet->name, MAXNAMELEN);
    }

    return wmem_strdup(allocator, tp->name);

} /* ipxnet_name_lookup */

/* VLANS */
static int
parse_vlan_line(char *line, vlan_t *vlan)
{
    gchar     *cp;
    guint16   id;

    if ((cp = strchr(line, '#')))
        *cp = '\0';

    if ((cp = strtok(line, " \t\n")) == NULL)
        return -1;

    if (sscanf(cp, "%" SCNu16, &id) == 1) {
        vlan->id = id;
    }
    else {
        return -1;
    }

    if ((cp = strtok(NULL, "\t\n")) == NULL)
        return -1;

    (void) g_strlcpy(vlan->name, cp, MAXVLANNAMELEN);

    return 0;

} /* parse_vlan_line */

static FILE *vlan_p = NULL;

static void
set_vlanent(char *path)
{
    if (vlan_p)
        rewind(vlan_p);
    else
        vlan_p = ws_fopen(path, "r");
}

static void
end_vlanent(void)
{
    if (vlan_p) {
        fclose(vlan_p);
        vlan_p = NULL;
    }
}

static vlan_t *
get_vlanent(void)
{

    static vlan_t vlan;
    char    buf[MAX_LINELEN];

    if (vlan_p == NULL)
        return NULL;

    while (fgetline(buf, sizeof(buf), vlan_p) >= 0) {
        if (parse_vlan_line(buf, &vlan) == 0) {
            return &vlan;
        }
    }

    return NULL;

} /* get_vlanent */

static vlan_t *
get_vlannamebyid(guint16 id)
{
    vlan_t *vlan;

    set_vlanent(g_pvlan_path);

    while (((vlan = get_vlanent()) != NULL) && (id != vlan->id) ) ;

    if (vlan == NULL) {
        end_vlanent();

    }

    return vlan;

} /* get_vlannamebyid */

static void
initialize_vlans(void)
{
    ws_assert(vlan_hash_table == NULL);
    vlan_hash_table = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    /* Set g_pvlan_path here, but don't actually do anything
     * with it. It's used in get_vlannamebyid()
     */
    if (g_pvlan_path == NULL) {
        /* Check profile directory before personal configuration */
        g_pvlan_path = get_persconffile_path(ENAME_VLANS, TRUE);
        if (!file_exists(g_pvlan_path)) {
            g_free(g_pvlan_path);
            g_pvlan_path = get_persconffile_path(ENAME_VLANS, FALSE);
        }
    }
} /* initialize_vlans */

static void
vlan_name_lookup_cleanup(void)
{
    end_vlanent();
    vlan_hash_table = NULL;
    g_free(g_pvlan_path);
    g_pvlan_path = NULL;
}

static const gchar *
vlan_name_lookup(const guint id)
{
    hashvlan_t *tp;
    vlan_t *vlan;

    tp = (hashvlan_t *)wmem_map_lookup(vlan_hash_table, GUINT_TO_POINTER(id));
    if (tp == NULL) {
        tp = wmem_new(wmem_epan_scope(), hashvlan_t);
        wmem_map_insert(vlan_hash_table, GUINT_TO_POINTER(id), tp);
    } else {
        return tp->name;
    }

    /* fill in a new entry */

    tp->id = id;

    if ( (vlan = get_vlannamebyid(id)) == NULL) {
        /* unknown name */
        snprintf(tp->name, MAXVLANNAMELEN, "<%u>", id);

    } else {
        (void) g_strlcpy(tp->name, vlan->name, MAXVLANNAMELEN);
    }

    return tp->name;

} /* vlan_name_lookup */
/* VLAN END */

static gboolean
read_hosts_file (const char *hostspath, gboolean store_entries)
{
    FILE *hf;
    char line[MAX_LINELEN];
    gchar *cp;
    union {
        guint32 ip4_addr;
        ws_in6_addr ip6_addr;
    } host_addr;
    gboolean is_ipv6, entry_found = FALSE;

    /*
     *  See the hosts(4) or hosts(5) man page for hosts file format
     *  (not available on all systems).
     */
    if ((hf = ws_fopen(hostspath, "r")) == NULL)
        return FALSE;

    while (fgetline(line, sizeof(line), hf) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        if ((cp = strtok(line, " \t")) == NULL)
            continue; /* no tokens in the line */

        if (ws_inet_pton6(cp, &host_addr.ip6_addr)) {
            /* Valid IPv6 */
            is_ipv6 = TRUE;
        } else if (ws_inet_pton4(cp, &host_addr.ip4_addr)) {
            /* Valid IPv4 */
            is_ipv6 = FALSE;
        } else {
            continue;
        }

        if ((cp = strtok(NULL, " \t")) == NULL)
            continue; /* no host name */

        entry_found = TRUE;
        if (store_entries) {
            if (is_ipv6) {
                add_ipv6_name(&host_addr.ip6_addr, cp);
            } else {
                add_ipv4_name(host_addr.ip4_addr, cp);
            }
        }
    }

    fclose(hf);
    return entry_found ? TRUE : FALSE;
} /* read_hosts_file */

gboolean
add_hosts_file (const char *hosts_file)
{
    gboolean found = FALSE;
    guint i;

    if (!hosts_file)
        return FALSE;

    if (!extra_hosts_files)
        extra_hosts_files = g_ptr_array_new();

    for (i = 0; i < extra_hosts_files->len; i++) {
        if (strcmp(hosts_file, (const char *) g_ptr_array_index(extra_hosts_files, i)) == 0)
            found = TRUE;
    }

    if (!found) {
        g_ptr_array_add(extra_hosts_files, wmem_strdup(wmem_epan_scope(), hosts_file));
        return read_hosts_file (hosts_file, FALSE);
    }
    return TRUE;
}

gboolean
add_ip_name_from_string (const char *addr, const char *name)
{
    union {
        guint32 ip4_addr;
        ws_in6_addr ip6_addr;
    } host_addr;
    gboolean is_ipv6;
    resolved_name_t *resolved_entry;

    if (ws_inet_pton6(addr, &host_addr.ip6_addr)) {
        is_ipv6 = TRUE;
    } else if (ws_inet_pton4(addr, &host_addr.ip4_addr)) {
        is_ipv6 = FALSE;
    } else {
        return FALSE;
    }

    if (is_ipv6) {
        resolved_entry = (resolved_name_t*)wmem_map_lookup(manually_resolved_ipv6_list, &host_addr.ip6_addr);
        if (resolved_entry)
        {
            // If we found a previous matching key (IP address), then just update the value (custom hostname);
            (void) g_strlcpy(resolved_entry->name, name, MAXNAMELEN);
        }
        else
        {
            // Add a new mapping entry, if this IP address isn't already in the list.
            ws_in6_addr* addr_key = wmem_new(wmem_epan_scope(), ws_in6_addr);
            memcpy(addr_key, &host_addr.ip6_addr, sizeof(ws_in6_addr));

            resolved_entry = wmem_new(wmem_epan_scope(), resolved_name_t);
            (void) g_strlcpy(resolved_entry->name, name, MAXNAMELEN);

            wmem_map_insert(manually_resolved_ipv6_list, addr_key, resolved_entry);
        }
    } else {
        resolved_entry = (resolved_name_t*)wmem_map_lookup(manually_resolved_ipv4_list, GUINT_TO_POINTER(host_addr.ip4_addr));
        if (resolved_entry)
        {
            // If we found a previous matching key (IP address), then just update the value (custom hostname);
            (void) g_strlcpy(resolved_entry->name, name, MAXNAMELEN);
        }
        else
        {
            // Add a new mapping entry, if this IP address isn't already in the list.
            resolved_entry = wmem_new(wmem_epan_scope(), resolved_name_t);
            (void) g_strlcpy(resolved_entry->name, name, MAXNAMELEN);

            wmem_map_insert(manually_resolved_ipv4_list, GUINT_TO_POINTER(host_addr.ip4_addr), resolved_entry);
        }
    }

    return TRUE;
} /* add_ip_name_from_string */

extern resolved_name_t* get_edited_resolved_name(const char* addr)
{
    guint32 ip4_addr;
    ws_in6_addr ip6_addr;
    resolved_name_t* resolved_entry = NULL;

    if (ws_inet_pton6(addr, &ip6_addr)) {
        resolved_entry = (resolved_name_t*)wmem_map_lookup(manually_resolved_ipv6_list, &ip6_addr);
    }
    else if (ws_inet_pton4(addr, &ip4_addr)) {
        resolved_entry = (resolved_name_t*)wmem_map_lookup(manually_resolved_ipv4_list, GUINT_TO_POINTER(ip4_addr));
    }

    return resolved_entry;
}

/*
 * Add the resolved addresses that are in use to the list used to create the NRB
 */
static void
ipv4_hash_table_resolved_to_list(gpointer key _U_, gpointer value, gpointer user_data)
{
    addrinfo_lists_t *lists = (addrinfo_lists_t*)user_data;
    hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *)value;

    if ((ipv4_hash_table_entry->flags & USED_AND_RESOLVED_MASK) == USED_AND_RESOLVED_MASK) {
        lists->ipv4_addr_list = g_list_prepend(lists->ipv4_addr_list, ipv4_hash_table_entry);
    }

}

/*
 * Add the resolved addresses that are in use to the list used to create the NRB
 */

static void
ipv6_hash_table_resolved_to_list(gpointer key _U_, gpointer value, gpointer user_data)
{
    addrinfo_lists_t *lists = (addrinfo_lists_t*)user_data;
    hashipv6_t *ipv6_hash_table_entry = (hashipv6_t *)value;

    if ((ipv6_hash_table_entry->flags & USED_AND_RESOLVED_MASK) == USED_AND_RESOLVED_MASK) {
        lists->ipv6_addr_list = g_list_prepend (lists->ipv6_addr_list, ipv6_hash_table_entry);
    }

}

addrinfo_lists_t *
get_addrinfo_list(void)
{
    if (ipv4_hash_table) {
        wmem_map_foreach(ipv4_hash_table, ipv4_hash_table_resolved_to_list, &addrinfo_lists);
    }

    if (ipv6_hash_table) {
        wmem_map_foreach(ipv6_hash_table, ipv6_hash_table_resolved_to_list, &addrinfo_lists);
    }

    return &addrinfo_lists;
}

/* Read in a list of subnet definition - name pairs.
 * <line> = <comment> | <entry> | <whitespace>
 * <comment> = <whitespace>#<any>
 * <entry> = <subnet_definition> <whitespace> <subnet_name> [<comment>|<whitespace><any>]
 * <subnet_definition> = <ipv4_address> / <subnet_mask_length>
 * <ipv4_address> is a full address; it will be masked to get the subnet-ID.
 * <subnet_mask_length> is a decimal 1-31
 * <subnet_name> is a string containing no whitespace.
 * <whitespace> = (space | tab)+
 * Any malformed entries are ignored.
 * Any trailing data after the subnet_name is ignored.
 *
 * XXX Support IPv6
 */
static gboolean
read_subnets_file (const char *subnetspath)
{
    FILE *hf;
    char line[MAX_LINELEN];
    gchar *cp, *cp2;
    guint32 host_addr; /* IPv4 ONLY */
    guint8 mask_length;

    if ((hf = ws_fopen(subnetspath, "r")) == NULL)
        return FALSE;

    while (fgetline(line, sizeof(line), hf) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        if ((cp = strtok(line, " \t")) == NULL)
            continue; /* no tokens in the line */


        /* Expected format is <IP4 address>/<subnet length> */
        cp2 = strchr(cp, '/');
        if (NULL == cp2) {
            /* No length */
            continue;
        }
        *cp2 = '\0'; /* Cut token */
        ++cp2    ;

        /* Check if this is a valid IPv4 address */
        if (!str_to_ip(cp, &host_addr)) {
            continue; /* no */
        }

        if (!ws_strtou8(cp2, NULL, &mask_length) || mask_length == 0 || mask_length > 32) {
            continue; /* invalid mask length */
        }

        if ((cp = strtok(NULL, " \t")) == NULL)
            continue; /* no subnet name */

        subnet_entry_set(host_addr, mask_length, cp);
    }

    fclose(hf);
    return TRUE;
} /* read_subnets_file */

static subnet_entry_t
subnet_lookup(const guint32 addr)
{
    subnet_entry_t subnet_entry;
    guint32 i;

    /* Search mask lengths linearly, longest first */

    i = SUBNETLENGTHSIZE;
    while(have_subnet_entry && i > 0) {
        guint32 masked_addr;
        subnet_length_entry_t* length_entry;

        /* Note that we run from 31 (length 32)  to 0 (length 1)  */
        --i;
        ws_assert(i < SUBNETLENGTHSIZE);


        length_entry = &subnet_length_entries[i];

        if (NULL != length_entry->subnet_addresses) {
            sub_net_hashipv4_t * tp;
            guint32 hash_idx;

            masked_addr = addr & length_entry->mask;
            hash_idx = HASH_IPV4_ADDRESS(masked_addr);

            tp = length_entry->subnet_addresses[hash_idx];
            while(tp != NULL && tp->addr != masked_addr) {
                tp = tp->next;
            }

            if (NULL != tp) {
                subnet_entry.mask = length_entry->mask;
                subnet_entry.mask_length = i + 1; /* Length is offset + 1 */
                subnet_entry.name = tp->name;
                return subnet_entry;
            }
        }
    }

    subnet_entry.mask = 0;
    subnet_entry.mask_length = 0;
    subnet_entry.name = NULL;

    return subnet_entry;
}

/* Add a subnet-definition - name pair to the set.
 * The definition is taken by masking the address passed in with the mask of the
 * given length.
 */
static void
subnet_entry_set(guint32 subnet_addr, const guint8 mask_length, const gchar* name)
{
    subnet_length_entry_t* entry;
    sub_net_hashipv4_t * tp;
    gsize hash_idx;

    ws_assert(mask_length > 0 && mask_length <= 32);

    entry = &subnet_length_entries[mask_length - 1];

    subnet_addr &= entry->mask;

    hash_idx = HASH_IPV4_ADDRESS(subnet_addr);

    if (NULL == entry->subnet_addresses) {
        entry->subnet_addresses = (sub_net_hashipv4_t**)wmem_alloc0(wmem_epan_scope(), sizeof(sub_net_hashipv4_t*) * HASHHOSTSIZE);
    }

    if (NULL != (tp = entry->subnet_addresses[hash_idx])) {
        sub_net_hashipv4_t * new_tp;

        while (tp->next) {
            if (tp->addr == subnet_addr) {
                return; /* XXX provide warning that an address was repeated? */
            } else {
                tp = tp->next;
            }
        }

        new_tp = wmem_new(wmem_epan_scope(), sub_net_hashipv4_t);
        tp->next = new_tp;
        tp = new_tp;
    } else {
        tp = entry->subnet_addresses[hash_idx] = wmem_new(wmem_epan_scope(), sub_net_hashipv4_t);
    }

    tp->next = NULL;
    tp->addr = subnet_addr;
    (void) g_strlcpy(tp->name, name, MAXNAMELEN); /* This is longer than subnet names can actually be */
    have_subnet_entry = TRUE;
}

static void
subnet_name_lookup_init(void)
{
    gchar* subnetspath;
    guint32 i;

    for(i = 0; i < SUBNETLENGTHSIZE; ++i) {
        guint32 length = i + 1;

        subnet_length_entries[i].subnet_addresses  = NULL;
        subnet_length_entries[i].mask_length  = length;
        subnet_length_entries[i].mask = g_htonl(ip_get_subnet_mask(length));
    }

    /* Check profile directory before personal configuration */
    subnetspath = get_persconffile_path(ENAME_SUBNETS, TRUE);
    if (!read_subnets_file(subnetspath)) {
        if (errno != ENOENT) {
            report_open_failure(subnetspath, errno, FALSE);
        }

        g_free(subnetspath);
        subnetspath = get_persconffile_path(ENAME_SUBNETS, FALSE);
        if (!read_subnets_file(subnetspath) && errno != ENOENT) {
            report_open_failure(subnetspath, errno, FALSE);
        }
    }
    g_free(subnetspath);

    /*
     * Load the global subnets file, if we have one.
     */
    subnetspath = get_datafile_path(ENAME_SUBNETS);
    if (!read_subnets_file(subnetspath) && errno != ENOENT) {
        report_open_failure(subnetspath, errno, FALSE);
    }
    g_free(subnetspath);
}

/* SS7 PC Name Resolution Portion */
static hashss7pc_t *
new_ss7pc(const guint8 ni, const guint32 pc)
{
    hashss7pc_t *tp = wmem_new(wmem_epan_scope(), hashss7pc_t);
    tp->id = (ni<<24) + (pc&0xffffff);
    tp->pc_addr[0] = '\0';
    tp->name[0] = '\0';

    return tp;
}

static hashss7pc_t *
host_lookup_ss7pc(const guint8 ni, const guint32 pc)
{
    hashss7pc_t * volatile tp;
    guint32 id;

    id = (ni<<24) + (pc&0xffffff);

    tp = (hashss7pc_t *)wmem_map_lookup(ss7pc_hash_table, GUINT_TO_POINTER(id));
    if (tp == NULL) {
        tp = new_ss7pc(ni, pc);
        wmem_map_insert(ss7pc_hash_table, GUINT_TO_POINTER(id), tp);
    }

    return tp;
}

void fill_unresolved_ss7pc(const gchar * pc_addr, const guint8 ni, const guint32 pc)
{
    hashss7pc_t *tp = host_lookup_ss7pc(ni, pc);

    (void) g_strlcpy(tp->pc_addr, pc_addr, MAXNAMELEN);
}

const gchar *
get_hostname_ss7pc(const guint8 ni, const guint32 pc)
{
    hashss7pc_t *tp = host_lookup_ss7pc(ni, pc);

    /* never resolved yet*/
    if (tp->pc_addr[0] == '\0')
        return tp->pc_addr;

    /* Don't have name in file */
    if (tp->name[0] == '\0')
        return tp->pc_addr;

    if (!gbl_resolv_flags.ss7pc_name)
        return tp->pc_addr;

    return tp->name;
}

static void
add_ss7pc_name(const guint8 ni, guint32 pc, const gchar *name)
{
    hashss7pc_t *tp;
    guint32 id;

    if (!name || name[0] == '\0')
        return;

    id = (ni<<24) + (pc&0xffffff);
    tp = (hashss7pc_t *)wmem_map_lookup(ss7pc_hash_table, GUINT_TO_POINTER(id));
    if (!tp) {
        tp = new_ss7pc(ni, pc);
        wmem_map_insert(ss7pc_hash_table, GUINT_TO_POINTER(id), tp);
    }

    if (g_ascii_strcasecmp(tp->name, name)) {
        (void) g_strlcpy(tp->name, name, MAXNAMELEN);
    }
}

static gboolean
read_ss7pcs_file(const char *ss7pcspath)
{
    FILE *hf;
    char line[MAX_LINELEN];
    gchar *cp;
    guint8 ni;
    guint32 pc;
    gboolean entry_found = FALSE;

    /*
    *  File format is Network Indicator (decimal)<dash>Point Code (Decimal)<tab/space>Hostname
    */
    if ((hf = ws_fopen(ss7pcspath, "r")) == NULL)
        return FALSE;

    while (fgetline(line, sizeof(line), hf) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        if ((cp = strtok(line, "-")) == NULL)
            continue; /*no ni-pc separator*/
        if (!ws_strtou8(cp, NULL, &ni))
            continue;
        if (ni > 3)
             continue;

        if ((cp = strtok(NULL, " \t")) == NULL)
            continue; /* no tokens for pc and name */
        if (!ws_strtou32(cp, NULL, &pc))
            continue;
        if (pc >> 24 > 0)
            continue;

        if ((cp = strtok(NULL, " \t")) == NULL)
            continue; /* no host name */

        entry_found = TRUE;
        add_ss7pc_name(ni, pc, cp);
    }

    fclose(hf);
    return entry_found ? TRUE : FALSE;
}

static void
ss7pc_name_lookup_init(void)
{
    char *ss7pcspath;

    ws_assert(ss7pc_hash_table == NULL);

    ss7pc_hash_table = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    /*
     * Load the user's ss7pcs file
     */
    ss7pcspath = get_persconffile_path(ENAME_SS7PCS, TRUE);
    if (!read_ss7pcs_file(ss7pcspath) && errno != ENOENT) {
        report_open_failure(ss7pcspath, errno, FALSE);
    }
    g_free(ss7pcspath);
}

/* SS7PC Name Resolution End*/


/*
 *  External Functions
 */

void
addr_resolve_pref_init(module_t *nameres)
{
    prefs_register_bool_preference(nameres, "mac_name",
            "Resolve MAC addresses",
            "Resolve Ethernet MAC addresses to host names from the preferences"
            " or system's Ethers file, or to a manufacturer based name.",
            &gbl_resolv_flags.mac_name);

    prefs_register_bool_preference(nameres, "transport_name",
            "Resolve transport names",
            "Resolve TCP/UDP ports into service names",
            &gbl_resolv_flags.transport_name);

    prefs_register_bool_preference(nameres, "network_name",
            "Resolve network (IP) addresses",
            "Resolve IPv4, IPv6, and IPX addresses into host names."
            " The next set of check boxes determines how name resolution should be performed."
            " If no other options are checked name resolution is made from Wireshark's host file"
            " and capture file name resolution blocks.",
            &gbl_resolv_flags.network_name);

    prefs_register_bool_preference(nameres, "dns_pkt_addr_resolution",
            "Use captured DNS packet data for name resolution",
            "Use address/name pairs found in captured DNS packets for name resolution.",
            &gbl_resolv_flags.dns_pkt_addr_resolution);

    prefs_register_bool_preference(nameres, "use_external_name_resolver",
            "Use your system's DNS settings for name resolution",
            "Use your system's configured name resolver"
            " (usually DNS) to resolve network names."
            " Only applies when network name resolution"
            " is enabled.",
            &gbl_resolv_flags.use_external_net_name_resolver);

    prefs_register_bool_preference(nameres, "use_custom_dns_servers",
            "Use a custom list of DNS servers for name resolution",
            "Use a DNS Servers list to resolve network names if TRUE.  If FALSE, default information is used",
            &use_custom_dns_server_list);

    static uat_field_t dns_server_uats_flds[] = {
        UAT_FLD_CSTRING_OTHER(dnsserverlist_uats, ipaddr, "IP address", dnsserver_uat_fld_ip_chk_cb, "IPv4 or IPv6 address"),
        UAT_FLD_CSTRING_OTHER(dnsserverlist_uats, tcp_port, "TCP Port", dnsserver_uat_fld_port_chk_cb, "Port Number (TCP)"),
        UAT_FLD_CSTRING_OTHER(dnsserverlist_uats, udp_port, "UDP Port", dnsserver_uat_fld_port_chk_cb, "Port Number (UDP)"),
        UAT_END_FIELDS
    };

    dnsserver_uat = uat_new("DNS Servers",
        sizeof(struct dns_server_data),
        "addr_resolve_dns_servers",        /* filename */
        TRUE,                       /* from_profile */
        &dnsserverlist_uats,        /* data_ptr */
        &ndnsservers,               /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,
        NULL,
        dns_server_copy_cb,
        NULL,
        dns_server_free_cb,
        c_ares_set_dns_servers,
        NULL,
        dns_server_uats_flds);
    prefs_register_uat_preference(nameres, "dns_servers",
        "DNS Servers",
        "A table of IPv4 and IPv6 addresses of DNS servers to be used to resolve IP names and addresses",
        dnsserver_uat);

    prefs_register_obsolete_preference(nameres, "concurrent_dns");

    prefs_register_uint_preference(nameres, "name_resolve_concurrency",
            "Maximum concurrent requests",
            "The maximum number of DNS requests that may"
            " be active at any time. A large value (many"
            " thousands) might overload the network or make"
            " your DNS server behave badly.",
            10,
            &name_resolve_concurrency);

    prefs_register_bool_preference(nameres, "hosts_file_handling",
            "Only use the profile \"hosts\" file",
            "By default \"hosts\" files will be loaded from multiple sources."
            " Checking this box only loads the \"hosts\" in the current profile.",
            &gbl_resolv_flags.load_hosts_file_from_profile_only);

    prefs_register_bool_preference(nameres, "vlan_name",
            "Resolve VLAN IDs",
            "Resolve VLAN IDs to network names from the preferences \"vlans\" file."
            " Format of the file is: \"ID<Tab>Name\"."
            " One line per VLAN, e.g.: 1 Management",
            &gbl_resolv_flags.vlan_name);

    prefs_register_bool_preference(nameres, "ss7_pc_name",
            "Resolve SS7 PCs",
            "Resolve SS7 Point Codes to node names from the profiles \"ss7pcs\" file."
            " Format of the file is: \"Network_Indicator<Dash>PC_Decimal<Tab>Name\"."
            " One line per Point Code, e.g.: 2-1234 MyPointCode1",
            &gbl_resolv_flags.ss7pc_name);

}

void addr_resolve_pref_apply(void)
{
    c_ares_set_dns_servers();
}

void
disable_name_resolution(void) {
    gbl_resolv_flags.mac_name                           = FALSE;
    gbl_resolv_flags.network_name                       = FALSE;
    gbl_resolv_flags.transport_name                     = FALSE;
    gbl_resolv_flags.dns_pkt_addr_resolution            = FALSE;
    gbl_resolv_flags.use_external_net_name_resolver     = FALSE;
    gbl_resolv_flags.vlan_name                          = FALSE;
    gbl_resolv_flags.ss7pc_name                         = FALSE;
}

gboolean
host_name_lookup_process(void) {
    async_dns_queue_msg_t *caqm;
    struct timeval tv = { 0, 0 };
    int nfds;
    fd_set rfds, wfds;
    gboolean nro = new_resolved_objects;
    wmem_list_frame_t* head;

    new_resolved_objects = FALSE;
    nro |= maxmind_db_lookup_process();

    if (!async_dns_initialized)
        /* c-ares not initialized. Bail out and cancel timers. */
        return nro;

    head = wmem_list_head(async_dns_queue_head);

    while (head != NULL && async_dns_in_flight <= name_resolve_concurrency) {
        caqm = (async_dns_queue_msg_t *)wmem_list_frame_data(head);
        wmem_list_remove_frame(async_dns_queue_head, head);
        if (caqm->family == AF_INET) {
            ares_gethostbyaddr(ghba_chan, &caqm->addr.ip4, sizeof(guint32), AF_INET,
                    c_ares_ghba_cb, caqm);
            async_dns_in_flight++;
        } else if (caqm->family == AF_INET6) {
            ares_gethostbyaddr(ghba_chan, &caqm->addr.ip6, sizeof(ws_in6_addr),
                    AF_INET6, c_ares_ghba_cb, caqm);
            async_dns_in_flight++;
        }

        head = wmem_list_head(async_dns_queue_head);
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    nfds = ares_fds(ghba_chan, &rfds, &wfds);
    if (nfds > 0) {
        if (select(nfds, &rfds, &wfds, NULL, &tv) == -1) { /* call to select() failed */
            /* If it's interrupted by a signal, no need to put out a message */
            if (errno != EINTR)
                fprintf(stderr, "Warning: call to select() failed, error is %s\n", g_strerror(errno));
            return nro;
        }
        ares_process(ghba_chan, &rfds, &wfds);
    }

    /* Any new entries? */
    return nro;
}

static void
_host_name_lookup_cleanup(void) {
    async_dns_queue_head = NULL;

    if (async_dns_initialized) {
        ares_destroy(ghba_chan);
        ares_destroy(ghbn_chan);
    }
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
    ares_library_cleanup();
#endif
    async_dns_initialized = FALSE;
}

const gchar *
get_hostname(const guint addr)
{
    /* XXX why do we call this if we're not resolving? To create hash entries?
     * Why?
     */
    hashipv4_t *tp = host_lookup(addr);

    if (!gbl_resolv_flags.network_name)
        return tp->ip;

    tp->flags |= RESOLVED_ADDRESS_USED;

    return tp->name;
}

/* -------------------------- */

const gchar *
get_hostname6(const ws_in6_addr *addr)
{
    /* XXX why do we call this if we're not resolving? To create hash entries?
     * Why?
     */
    hashipv6_t *tp = host_lookup6(addr);

    if (!gbl_resolv_flags.network_name)
        return tp->ip6;

    tp->flags |= RESOLVED_ADDRESS_USED;

    return tp->name;
}

/* -------------------------- */
void
add_ipv4_name(const guint addr, const gchar *name)
{
    hashipv4_t *tp;

    /*
     * Don't add zero-length names; apparently, some resolvers will return
     * them if they get them from DNS.
     */
    if (!name || name[0] == '\0')
        return;

    tp = (hashipv4_t *)wmem_map_lookup(ipv4_hash_table, GUINT_TO_POINTER(addr));
    if (!tp) {
        tp = new_ipv4(addr);
        wmem_map_insert(ipv4_hash_table, GUINT_TO_POINTER(addr), tp);
    }

    if (g_ascii_strcasecmp(tp->name, name)) {
        (void) g_strlcpy(tp->name, name, MAXNAMELEN);
        new_resolved_objects = TRUE;
    }
    tp->flags |= TRIED_RESOLVE_ADDRESS|NAME_RESOLVED;
} /* add_ipv4_name */

/* -------------------------- */
void
add_ipv6_name(const ws_in6_addr *addrp, const gchar *name)
{
    hashipv6_t *tp;

    /*
     * Don't add zero-length names; apparently, some resolvers will return
     * them if they get them from DNS.
     */
    if (!name || name[0] == '\0')
        return;

    tp = (hashipv6_t *)wmem_map_lookup(ipv6_hash_table, addrp);
    if (!tp) {
        ws_in6_addr *addr_key;

        addr_key = wmem_new(wmem_epan_scope(), ws_in6_addr);
        tp = new_ipv6(addrp);
        memcpy(addr_key, addrp, 16);
        wmem_map_insert(ipv6_hash_table, addr_key, tp);
    }

    if (g_ascii_strcasecmp(tp->name, name)) {
        (void) g_strlcpy(tp->name, name, MAXNAMELEN);
        new_resolved_objects = TRUE;
    }
    tp->flags |= TRIED_RESOLVE_ADDRESS|NAME_RESOLVED;
} /* add_ipv6_name */

static void
add_manually_resolved_ipv4(gpointer key, gpointer value, gpointer user_data _U_)
{
    resolved_name_t *resolved_ipv4_entry = (resolved_name_t*)value;
    add_ipv4_name(GPOINTER_TO_UINT(key), resolved_ipv4_entry->name);
}

static void
add_manually_resolved_ipv6(gpointer key, gpointer value, gpointer user_data _U_)
{
    resolved_name_t *resolved_ipv6_entry = (resolved_name_t*)value;
    add_ipv6_name((ws_in6_addr*)key, resolved_ipv6_entry->name);
}

static void
add_manually_resolved(void)
{
    if (manually_resolved_ipv4_list) {
        wmem_map_foreach(manually_resolved_ipv4_list, add_manually_resolved_ipv4, NULL);
    }

    if (manually_resolved_ipv6_list) {
        wmem_map_foreach(manually_resolved_ipv6_list, add_manually_resolved_ipv6, NULL);
    }
}

static void
host_name_lookup_init(void)
{
    char *hostspath;
    guint i;

    ws_assert(ipxnet_hash_table == NULL);
    ipxnet_hash_table = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    ws_assert(ipv4_hash_table == NULL);
    ipv4_hash_table = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    ws_assert(ipv6_hash_table == NULL);
    ipv6_hash_table = wmem_map_new(wmem_epan_scope(), ipv6_oat_hash, ipv6_equal);

    ws_assert(async_dns_queue_head == NULL);
    async_dns_queue_head = wmem_list_new(wmem_epan_scope());

    if (manually_resolved_ipv4_list == NULL)
        manually_resolved_ipv4_list = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);

    if (manually_resolved_ipv6_list == NULL)
        manually_resolved_ipv6_list = wmem_map_new(wmem_epan_scope(), ipv6_oat_hash, ipv6_equal);

    /*
     * Load the global hosts file, if we have one.
     */
    if (!gbl_resolv_flags.load_hosts_file_from_profile_only) {
        hostspath = get_datafile_path(ENAME_HOSTS);
        if (!read_hosts_file(hostspath, TRUE) && errno != ENOENT) {
            report_open_failure(hostspath, errno, FALSE);
        }
        g_free(hostspath);
    }
    /*
     * Load the user's hosts file no matter what, if they have one.
     */
    hostspath = get_persconffile_path(ENAME_HOSTS, TRUE);
    if (!read_hosts_file(hostspath, TRUE) && errno != ENOENT) {
        report_open_failure(hostspath, errno, FALSE);
    }
    g_free(hostspath);
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
    if (ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS) {
#endif
        if (ares_init(&ghba_chan) == ARES_SUCCESS && ares_init(&ghbn_chan) == ARES_SUCCESS) {
            async_dns_initialized = TRUE;
            c_ares_set_dns_servers();
        }
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
    }
#endif

    if (extra_hosts_files && !gbl_resolv_flags.load_hosts_file_from_profile_only) {
        for (i = 0; i < extra_hosts_files->len; i++) {
            read_hosts_file((const char *) g_ptr_array_index(extra_hosts_files, i), TRUE);
        }
    }

    subnet_name_lookup_init();

    add_manually_resolved();

    ss7pc_name_lookup_init();
}

static void
host_name_lookup_cleanup(void)
{
    guint32 i, j;
    sub_net_hashipv4_t *entry, *next_entry;

    _host_name_lookup_cleanup();

    ipxnet_hash_table = NULL;
    ipv4_hash_table = NULL;
    ipv6_hash_table = NULL;
    ss7pc_hash_table = NULL;

    for(i = 0; i < SUBNETLENGTHSIZE; ++i) {
        if (subnet_length_entries[i].subnet_addresses != NULL) {
            for (j = 0; j < HASHHOSTSIZE; j++) {
                for (entry = subnet_length_entries[i].subnet_addresses[j];
                     entry != NULL; entry = next_entry) {
                    next_entry = entry->next;
                    wmem_free(wmem_epan_scope(), entry);
                }
            }
            wmem_free(wmem_epan_scope(), subnet_length_entries[i].subnet_addresses);
            subnet_length_entries[i].subnet_addresses = NULL;
        }
    }

    have_subnet_entry = FALSE;
    new_resolved_objects = FALSE;
}


void host_name_lookup_reset(void)
{
    host_name_lookup_cleanup();
    host_name_lookup_init();
    vlan_name_lookup_cleanup();
    initialize_vlans();
    ethers_cleanup();
    initialize_ethers();
    service_name_lookup_cleanup();
    initialize_services();
    ipx_name_lookup_cleanup();
    initialize_ipxnets();
    enterprises_cleanup();
    initialize_enterprises();
}

gchar *
udp_port_to_display(wmem_allocator_t *allocator, guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return wmem_utoa(allocator, port);
    }

    return wmem_strdup(allocator, serv_name_lookup(PT_UDP, port));

} /* udp_port_to_display */

gchar *
dccp_port_to_display(wmem_allocator_t *allocator, guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return wmem_utoa(allocator, port);
    }

    return wmem_strdup(allocator, serv_name_lookup(PT_DCCP, port));

} /* dccp_port_to_display */

gchar *
tcp_port_to_display(wmem_allocator_t *allocator, guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return wmem_utoa(allocator, port);
    }

    return wmem_strdup(allocator, serv_name_lookup(PT_TCP, port));

} /* tcp_port_to_display */

gchar *
sctp_port_to_display(wmem_allocator_t *allocator, guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return wmem_utoa(allocator, port);
    }

    return wmem_strdup(allocator, serv_name_lookup(PT_SCTP, port));

} /* sctp_port_to_display */

gchar *
port_with_resolution_to_str(wmem_allocator_t *scope, port_type proto, guint port)
{
    const gchar *port_str;

    if (!gbl_resolv_flags.transport_name || (proto == PT_NONE)) {
        /* No name resolution support, just return port string */
        return wmem_strdup_printf(scope, "%u", port);
    }
    port_str = serv_name_lookup(proto, port);
    ws_assert(port_str);
    return wmem_strdup_printf(scope, "%s (%u)", port_str, port);
}

int
port_with_resolution_to_str_buf(gchar *buf, gulong buf_size, port_type proto, guint port)
{
    const gchar *port_str;

    if (!gbl_resolv_flags.transport_name || (proto == PT_NONE)) {
        /* No name resolution support, just return port string */
        return snprintf(buf, buf_size, "%u", port);
    }
    port_str = serv_name_lookup(proto, port);
    ws_assert(port_str);
    return snprintf(buf, buf_size, "%s (%u)", port_str, port);
}

const gchar *
get_ether_name(const guint8 *addr)
{
    hashether_t *tp;
    gboolean resolve = gbl_resolv_flags.mac_name;

    tp = eth_name_lookup(addr, resolve);

    return resolve ? tp->resolved_name : tp->hexaddr;

} /* get_ether_name */

const gchar *
tvb_get_ether_name(tvbuff_t *tvb, gint offset)
{
    return get_ether_name(tvb_get_ptr(tvb, offset, 6));
}

/* Look for a (non-dummy) ether name in the hash, and return it if found.
 * If it's not found, simply return NULL.
 */
const gchar *
get_ether_name_if_known(const guint8 *addr)
{
    hashether_t *tp;

    /* Initialize ether structs if we're the first
     * ether-related function called */
    if (!gbl_resolv_flags.mac_name)
        return NULL;

    /* eth_name_lookup will create a (resolved) hash entry
     * if it doesn't exist, so it never returns NULL */
    tp = eth_name_lookup(addr, TRUE);

    if (tp->status == HASHETHER_STATUS_RESOLVED_NAME) {
        /* Name is from an ethers file */
        return tp->resolved_name;
    }
    else {
        /* Name was created */
        return NULL;
    }
}

void
add_ether_byip(const guint ip, const guint8 *eth)
{
    hashipv4_t *tp;

    /* first check that IP address can be resolved */
    if (!gbl_resolv_flags.network_name)
        return;

    tp = host_lookup(ip);

    /*
     * Was this IP address resolved to a host name?
     */
    if (tp->flags & NAME_RESOLVED) {
        /*
         * Yes, so add an entry in the ethers hashtable resolving
         * the MAC address to that name.
         */
        add_eth_name(eth, tp->name);
    }

} /* add_ether_byip */

gchar *
get_ipxnet_name(wmem_allocator_t *allocator, const guint32 addr)
{

    if (!gbl_resolv_flags.network_name) {
        return ipxnet_to_str_punct(allocator, addr, '\0');
    }

    return ipxnet_name_lookup(allocator, addr);

} /* get_ipxnet_name */

gchar *
get_vlan_name(wmem_allocator_t *allocator, const guint16 id)
{

    if (!gbl_resolv_flags.vlan_name) {
        return NULL;
    }

    return wmem_strdup(allocator, vlan_name_lookup(id));

} /* get_vlan_name */

const gchar *
get_manuf_name(const guint8 *addr)
{
    hashmanuf_t *manuf_value;

    manuf_value = manuf_name_lookup(addr);
    if (gbl_resolv_flags.mac_name && manuf_value->status != HASHETHER_STATUS_UNRESOLVED)
        return manuf_value->resolved_name;

    return manuf_value->hexaddr;

} /* get_manuf_name */

const gchar *
tvb_get_manuf_name(tvbuff_t *tvb, gint offset)
{
    return get_manuf_name(tvb_get_ptr(tvb, offset, 3));
}

const gchar *
get_manuf_name_if_known(const guint8 *addr)
{
    hashmanuf_t *manuf_value;
    guint manuf_key;
    guint8 oct;

    /* manuf needs only the 3 most significant octets of the ethernet address */
    manuf_key = addr[0];
    manuf_key = manuf_key<<8;
    oct = addr[1];
    manuf_key = manuf_key | oct;
    manuf_key = manuf_key<<8;
    oct = addr[2];
    manuf_key = manuf_key | oct;

    manuf_value = (hashmanuf_t *)wmem_map_lookup(manuf_hashtable, GUINT_TO_POINTER(manuf_key));
    if ((manuf_value == NULL) || (manuf_value->status == HASHETHER_STATUS_UNRESOLVED)) {
        return NULL;
    }

    return manuf_value->resolved_longname;

} /* get_manuf_name_if_known */

const gchar *
uint_get_manuf_name_if_known(const guint manuf_key)
{
    hashmanuf_t *manuf_value;

    manuf_value = (hashmanuf_t *)wmem_map_lookup(manuf_hashtable, GUINT_TO_POINTER(manuf_key));
    if ((manuf_value == NULL) || (manuf_value->status == HASHETHER_STATUS_UNRESOLVED)) {
        return NULL;
    }

    return manuf_value->resolved_longname;
}

const gchar *
tvb_get_manuf_name_if_known(tvbuff_t *tvb, gint offset)
{
    return get_manuf_name_if_known(tvb_get_ptr(tvb, offset, 3));
}

char* get_hash_manuf_resolved_name(hashmanuf_t* manuf)
{
    return manuf->resolved_longname;
}

gchar *
eui64_to_display(wmem_allocator_t *allocator, const guint64 addr_eui64)
{
    guint8 *addr = (guint8 *)wmem_alloc(NULL, 8);
    hashmanuf_t *manuf_value;
    gchar *ret;

    /* Copy and convert the address to network byte order. */
    *(guint64 *)(void *)(addr) = pntoh64(&(addr_eui64));

    manuf_value = manuf_name_lookup(addr);
    if (!gbl_resolv_flags.mac_name || (manuf_value->status == HASHETHER_STATUS_UNRESOLVED)) {
        ret = wmem_strdup_printf(allocator, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
    } else {
        ret = wmem_strdup_printf(allocator, "%s_%02x:%02x:%02x:%02x:%02x", manuf_value->resolved_name, addr[3], addr[4], addr[5], addr[6], addr[7]);
    }

    wmem_free(NULL, addr);
    return ret;
} /* eui64_to_display */

#define GHI_TIMEOUT (250 * 1000)
static void
c_ares_ghi_cb(void *arg, int status, int timeouts _U_, struct hostent *hp) {
    /*
     * XXX - If we wanted to be really fancy we could cache results here and
     * look them up in get_host_ipaddr* below.
     */
    async_hostent_t *ahp = (async_hostent_t *)arg;
    if (status == ARES_SUCCESS && hp && ahp && hp->h_length == ahp->addr_size) {
        memcpy(ahp->addrp, hp->h_addr, hp->h_length);
        ahp->copied = hp->h_length;
    }
}

/* Translate a string, assumed either to be a dotted-quad IPv4 address or
 * a host name, to a numeric IPv4 address.  Return TRUE if we succeed and
 * set "*addrp" to that numeric IPv4 address; return FALSE if we fail. */
gboolean
get_host_ipaddr(const char *host, guint32 *addrp)
{
    struct timeval tv = { 0, GHI_TIMEOUT }, *tvp;
    int nfds;
    fd_set rfds, wfds;
    async_hostent_t ahe;

    /*
     * XXX - are there places where this is used to translate something
     * that's *only* supposed to be an IPv4 address, and where it
     * *shouldn't* translate host names?
     */
    if (!ws_inet_pton4(host, addrp)) {

        /* It's not a valid dotted-quad IP address; is it a valid
         * host name?
         */

        /* If we're not allowed to do name resolution, don't do name
         * resolution...
         */
        if (!gbl_resolv_flags.network_name ||
                !gbl_resolv_flags.use_external_net_name_resolver) {
            return FALSE;
        }

        if (!async_dns_initialized || name_resolve_concurrency < 1) {
            return FALSE;
        }
        ahe.addr_size = (int) sizeof (struct in_addr);
        ahe.copied = 0;
        ahe.addrp = addrp;
        ares_gethostbyname(ghbn_chan, host, AF_INET, c_ares_ghi_cb, &ahe);
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        nfds = ares_fds(ghbn_chan, &rfds, &wfds);
        if (nfds > 0) {
            tvp = ares_timeout(ghbn_chan, &tv, &tv);
            if (select(nfds, &rfds, &wfds, NULL, tvp) == -1) { /* call to select() failed */
                /* If it's interrupted by a signal, no need to put out a message */
                if (errno != EINTR)
                    fprintf(stderr, "Warning: call to select() failed, error is %s\n", g_strerror(errno));
                return FALSE;
            }
            ares_process(ghbn_chan, &rfds, &wfds);
        }
        ares_cancel(ghbn_chan);
        if (ahe.addr_size == ahe.copied) {
            return TRUE;
        }
        return FALSE;
    }

    return TRUE;
}

/*
 * Translate IPv6 numeric address or FQDN hostname into binary IPv6 address.
 * Return TRUE if we succeed and set "*addrp" to that numeric IPv6 address;
 * return FALSE if we fail.
 */
gboolean
get_host_ipaddr6(const char *host, ws_in6_addr *addrp)
{
    struct timeval tv = { 0, GHI_TIMEOUT }, *tvp;
    int nfds;
    fd_set rfds, wfds;
    async_hostent_t ahe;

    if (str_to_ip6(host, addrp))
        return TRUE;

    /* It's not a valid dotted-quad IP address; is it a valid
     * host name?
     *
     * XXX - are there places where this is used to translate something
     * that's *only* supposed to be an IPv6 address, and where it
     * *shouldn't* translate host names?
     */

    /* If we're not allowed to do name resolution, don't do name
     * resolution...
     */
    if (!gbl_resolv_flags.network_name ||
            !gbl_resolv_flags.use_external_net_name_resolver) {
        return FALSE;
    }

    /* try FQDN */
    if (!async_dns_initialized || name_resolve_concurrency < 1) {
        return FALSE;
    }
    ahe.addr_size = (int) sizeof (ws_in6_addr);
    ahe.copied = 0;
    ahe.addrp = addrp;
    ares_gethostbyname(ghbn_chan, host, AF_INET6, c_ares_ghi_cb, &ahe);
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    nfds = ares_fds(ghbn_chan, &rfds, &wfds);
    if (nfds > 0) {
        tvp = ares_timeout(ghbn_chan, &tv, &tv);
        if (select(nfds, &rfds, &wfds, NULL, tvp) == -1) { /* call to select() failed */
            /* If it's interrupted by a signal, no need to put out a message */
            if (errno != EINTR)
                fprintf(stderr, "Warning: call to select() failed, error is %s\n", g_strerror(errno));
            return FALSE;
        }
        ares_process(ghbn_chan, &rfds, &wfds);
    }
    ares_cancel(ghbn_chan);
    if (ahe.addr_size == ahe.copied) {
        return TRUE;
    }

    return FALSE;
}

wmem_map_t *
get_manuf_hashtable(void)
{
    return manuf_hashtable;
}

wmem_map_t *
get_wka_hashtable(void)
{
    return wka_hashtable;
}

wmem_map_t *
get_eth_hashtable(void)
{
    return eth_hashtable;
}

wmem_map_t *
get_serv_port_hashtable(void)
{
    return serv_port_hashtable;
}

wmem_map_t *
get_ipxnet_hash_table(void)
{
        return ipxnet_hash_table;
}

wmem_map_t *
get_vlan_hash_table(void)
{
        return vlan_hash_table;
}

wmem_map_t *
get_ipv4_hash_table(void)
{
        return ipv4_hash_table;
}

wmem_map_t *
get_ipv6_hash_table(void)
{
        return ipv6_hash_table;
}
/* Initialize all the address resolution subsystems in this file */
void
addr_resolv_init(void)
{
    initialize_services();
    initialize_ethers();
    initialize_ipxnets();
    initialize_vlans();
    initialize_enterprises();
    host_name_lookup_init();
}

/* Clean up all the address resolution subsystems in this file */
void
addr_resolv_cleanup(void)
{
    vlan_name_lookup_cleanup();
    service_name_lookup_cleanup();
    ethers_cleanup();
    ipx_name_lookup_cleanup();
    enterprises_cleanup();
    host_name_lookup_cleanup();
}

gboolean
str_to_ip(const char *str, void *dst)
{
    return ws_inet_pton4(str, (guint32 *)dst);
}

gboolean
str_to_ip6(const char *str, void *dst)
{
    return ws_inet_pton6(str, (ws_in6_addr *)dst);
}

/*
 * convert a 0-terminated string that contains an ethernet address into
 * the corresponding sequence of 6 bytes
 * eth_bytes is a buffer >= 6 bytes that was allocated by the caller
 */
gboolean
str_to_eth(const char *str, char *eth_bytes)
{
    ether_t eth;

    if (!parse_ether_address(str, &eth, NULL, FALSE))
        return FALSE;

    memcpy(eth_bytes, eth.addr, sizeof(eth.addr));
    return TRUE;
}

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
