/* addr_resolv.c
 * Routines for network object lookup
 *
 * Laurent Deniel <laurent.deniel@free.fr>
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

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * Win32 doesn't have SIGALRM (and it's the OS where name lookup calls
 * are most likely to take a long time, given the way address-to-name
 * lookups are done over NBNS).
 *
 * Mac OS X does have SIGALRM, but if you longjmp() out of a name resolution
 * call in a signal handler, you might crash, because the state of the
 * resolution code that sends messages to lookupd might be inconsistent
 * if you jump out of it in middle of a call.
 *
 * In at least some Linux distributions (e.g., RedHat Linux 9), if ADNS
 * is used, we appear to hang in host_name_lookup6() in a gethostbyaddr()
 * call (and possibly in other gethostbyaddr() calls), because there's
 * a mutex lock held in gethostbyaddr() and it doesn't get released
 * if we longjmp out of it.
 *
 * There's no guarantee that longjmp()ing out of name resolution calls
 * will work on *any* platform; OpenBSD got rid of the alarm/longjmp
 * code in tcpdump, to avoid those sorts of problems, and that was
 * picked up by tcpdump.org tcpdump.
 *
 * So, for now, we do not define AVOID_DNS_TIMEOUT.  If we get a
 * significantly more complaints about lookups taking a long time,
 * we can reconsider that decision.  (Note that tcpdump originally
 * added that for the benefit of systems using NIS to look up host
 * names; that might now be fixed in NIS implementations, for those
 * sites still using NIS rather than DNS for that....)
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <signal.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>     /* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>       /* needed to define AF_ values on Windows */
#endif

#ifndef HAVE_INET_ATON_H
# include "wsutil/inet_aton.h"
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#if defined(_WIN32) && defined(INET6)
# include <ws2tcpip.h>
#endif

#ifdef HAVE_C_ARES
# if defined(_WIN32) && !defined(INET6)
#  define socklen_t unsigned int
# endif
# include <ares.h>
# include <ares_version.h>
#else
# ifdef HAVE_GNU_ADNS
#  include <errno.h>
#  include <adns.h>
#  if defined(inet_aton) && defined(_WIN32)
#   undef inet_aton
#  endif
# endif /* HAVE_GNU_ADNS */
#endif  /* HAVE_C_ARES */


#include <glib.h>

#include "packet.h"
#include "addr_and_mask.h"
#include "ipv6-utils.h"
#include "addr_resolv.h"
#include "wsutil/filesystem.h"

#include <wsutil/report_err.h>
#include <wsutil/file_util.h>
#include <wsutil/pint.h>

#include <epan/strutil.h>
#include <epan/to_str-int.h>
#include <epan/prefs.h>
#include <epan/emem.h>

#define ENAME_HOSTS     "hosts"
#define ENAME_SUBNETS   "subnets"
#define ENAME_ETHERS    "ethers"
#define ENAME_IPXNETS   "ipxnets"
#define ENAME_MANUF     "manuf"
#define ENAME_SERVICES  "services"

#define HASHETHSIZE      2048
#define HASHHOSTSIZE     2048
#define HASHIPXNETSIZE    256
#define SUBNETLENGTHSIZE   32  /*1-32 inc.*/

/* hash table used for IPv4 lookup */

#define HASH_IPV4_ADDRESS(addr) (g_htonl(addr) & (HASHHOSTSIZE - 1))


typedef struct sub_net_hashipv4 {
    guint             addr;
    guint8            flags;          /* B0 dummy_entry, B1 resolve, B2 If the address is used in the trace */
    struct sub_net_hashipv4   *next;
    gchar             ip[16];
    gchar             name[MAXNAMELEN];
} sub_net_hashipv4_t;

/* Array of entries of subnets of different lengths */
typedef struct {
    gsize        mask_length;      /*1-32*/
    guint32      mask;             /* e.g. 255.255.255.*/
    sub_net_hashipv4_t** subnet_addresses; /* Hash table of subnet addresses */
} subnet_length_entry_t;


#if 0
typedef struct serv_port {
    gchar            *udp_name;
    gchar            *tcp_name;
    gchar            *sctp_name;
    gchar            *dccp_name;
} serv_port_t;
#endif
/* hash table used for IPX network lookup */

/* XXX - check goodness of hash function */

#define HASH_IPX_NET(net)   ((net) & (HASHIPXNETSIZE - 1))

typedef struct hashipxnet {
    guint               addr;
    struct hashipxnet  *next;
    gchar               name[MAXNAMELEN];
} hashipxnet_t;

/* hash tables used for ethernet and manufacturer lookup */
#define HASHETHER_STATUS_UNRESOLVED     1
#define HASHETHER_STATUS_RESOLVED_DUMMY 2
#define HASHETHER_STATUS_RESOLVED_NAME  3

#if 0
typedef struct hashether {
    struct hashether *next;
    guint             status;  /* (See above) */
    guint8            addr[6];
    char              hexaddr[6*3];
    char              resolved_name[MAXNAMELEN];
} hashether_t;
#endif
/* internal ethernet type */

typedef struct _ether
{
    guint8            addr[6];
    char              name[MAXNAMELEN];
} ether_t;

/* internal ipxnet type */

typedef struct _ipxnet
{
    guint             addr;
    char              name[MAXNAMELEN];
} ipxnet_t;

static GHashTable   *ipxnet_hash_table = NULL;
static GHashTable   *ipv4_hash_table = NULL;
static GHashTable   *ipv6_hash_table = NULL;

static GSList *manually_resolved_ipv4_list = NULL;
static GSList *manually_resolved_ipv6_list = NULL;

typedef struct _resolved_ipv4
{
    guint32          host_addr;
    char             name[MAXNAMELEN];
} resolved_ipv4_t;

typedef struct _resolved_ipv6
{
    struct e_in6_addr  ip6_addr;
    char               name[MAXNAMELEN];
} resolved_ipv6_t;

static addrinfo_lists_t addrinfo_lists = { NULL, NULL};

static gchar        *cb_service;
static port_type    cb_proto = PT_NONE;


static GHashTable *manuf_hashtable = NULL;
static GHashTable *wka_hashtable = NULL;
static GHashTable *eth_hashtable = NULL;
static GHashTable *serv_port_hashtable = NULL;

static subnet_length_entry_t subnet_length_entries[SUBNETLENGTHSIZE]; /* Ordered array of entries */
static gboolean have_subnet_entry = FALSE;

static gboolean new_resolved_objects = FALSE;

static GPtrArray* extra_hosts_files = NULL;

static hashether_t *add_eth_name(const guint8 *addr, const gchar *name);
static void add_serv_port_cb(const guint32 port);


/* http://eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx#existing
 * One-at-a-Time hash
 */
static guint32
ipv6_oat_hash(gconstpointer key)
{
    int len = 16;
    const unsigned char *p = (const unsigned char *)key;
    guint32 h = 0;
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

static gboolean
ipv6_equal(gconstpointer v1, gconstpointer v2)
{

    if( memcmp(v1, v2, sizeof (struct e_in6_addr)) == 0 ) {
        return TRUE;
    }

    return FALSE;
}

/*
 * Flag controlling what names to resolve.
 */
e_addr_resolve gbl_resolv_flags = {TRUE, FALSE, FALSE, TRUE, TRUE, FALSE};
#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
static guint name_resolve_concurrency = 500;
#endif

/*
 *  Global variables (can be changed in GUI sections)
 *  XXX - they could be changed in GUI code, but there's currently no
 *  GUI code to change them.
 */

gchar *g_ethers_path    = NULL;     /* global ethers file     */
gchar *g_pethers_path   = NULL;     /* personal ethers file   */
gchar *g_ipxnets_path   = NULL;     /* global ipxnets file    */
gchar *g_pipxnets_path  = NULL;     /* personal ipxnets file  */
gchar *g_services_path  = NULL;     /* global services file   */
gchar *g_pservices_path = NULL;     /* personal services file */
                                    /* first resolving call   */

/* c-ares */
#ifdef HAVE_C_ARES
/*
 * Submitted queries trigger a callback (c_ares_ghba_cb()).
 * Queries are added to c_ares_queue_head. During processing, queries are
 * popped off the front of c_ares_queue_head and submitted using
 * ares_gethostbyaddr().
 * The callback processes the response, then frees the request.
 */
#define ASYNC_DNS
typedef struct _async_dns_queue_msg
{
    union {
        guint32           ip4;
        struct e_in6_addr ip6;
    } addr;
    int                 family;
} async_dns_queue_msg_t;

typedef struct _async_hostent {
    int addr_size;
    int   copied;
    void *addrp;
} async_hostent_t;

#if ( ( ARES_VERSION_MAJOR < 1 )                                     \
        || ( 1 == ARES_VERSION_MAJOR && ARES_VERSION_MINOR < 5 ) )
static void c_ares_ghba_cb(void *arg, int status, struct hostent *hostent);
#else
static void c_ares_ghba_cb(void *arg, int status, int timeouts _U_, struct hostent *hostent);
#endif

ares_channel ghba_chan; /* ares_gethostbyaddr -- Usually non-interactive, no timeout */
ares_channel ghbn_chan; /* ares_gethostbyname -- Usually interactive, timeout */

#else
/* GNU ADNS */
#ifdef HAVE_GNU_ADNS
#define ASYNC_DNS
/*
 * Submitted queries have to be checked individually using adns_check().
 * Queries are added to adns_queue_head. During processing, the list is
 * iterated twice: once to request queries up to the concurrency limit,
 * and once to check the status of each query.
 */

adns_state ads;

typedef struct _async_dns_queue_msg
{
    gboolean    submitted;
    guint32     ip4_addr;
    int         type;
    adns_query  query;
} async_dns_queue_msg_t;

#endif /* HAVE_GNU_ADNS */
#endif /* HAVE_C_ARES */
#ifdef ASYNC_DNS
static  gboolean  async_dns_initialized = FALSE;
static  guint       async_dns_in_flight = 0;
static  GList    *async_dns_queue_head = NULL;

/* push a dns request */
static void
add_async_dns_ipv4(int type, guint32 addr)
{
    async_dns_queue_msg_t *msg;

    msg = g_new(async_dns_queue_msg_t,1);
#ifdef HAVE_C_ARES
    msg->family = type;
    msg->addr.ip4 = addr;
#else
    msg->type = type;
    msg->ip4_addr = addr;
    msg->submitted = FALSE;
#endif
    async_dns_queue_head = g_list_append(async_dns_queue_head, (gpointer) msg);
}

#endif

typedef struct {
    guint32      mask;
    gsize        mask_length;
    const gchar* name; /* Shallow copy */
} subnet_entry_t;

/*
 *  Miscellaneous functions
 */

static int
fgetline(char **buf, int *size, FILE *fp)
{
    int len;
    int c;

    if (fp == NULL || buf == NULL)
        return -1;

    if (*buf == NULL) {
        if (*size == 0)
            *size = BUFSIZ;

        *buf = (char *)g_malloc(*size);
    }

    g_assert(*buf);
    g_assert(*size > 0);

    if (feof(fp))
        return -1;

    len = 0;
    while ((c = getc(fp)) != EOF && c != '\r' && c != '\n') {
        if (len+1 >= *size) {
            *buf = (char *)g_realloc(*buf, *size += BUFSIZ);
        }
        (*buf)[len++] = c;
    }

    if (len == 0 && c == EOF)
        return -1;

    (*buf)[len] = '\0';

    return len;

} /* fgetline */


/*
 *  Local function definitions
 */
static subnet_entry_t subnet_lookup(const guint32 addr);
static void subnet_entry_set(guint32 subnet_addr, const guint32 mask_length, const gchar* name);


static void
add_service_name(port_type proto, const guint port, const char *service_name)
{
    serv_port_t *serv_port_table;
    int *key;

    key = (int *)g_new(int, 1);
    *key = port;

    serv_port_table = (serv_port_t *)g_hash_table_lookup(serv_port_hashtable, &port);
    if (serv_port_table == NULL) {
        serv_port_table = g_new0(serv_port_t,1);
        g_hash_table_insert(serv_port_hashtable, key, serv_port_table);
    }
    else {
        g_free(key);
    }

    switch(proto){
        case PT_TCP:
            g_free(serv_port_table->tcp_name);
            serv_port_table->tcp_name = g_strdup(service_name);
            break;
        case PT_UDP:
            g_free(serv_port_table->udp_name);
            serv_port_table->udp_name = g_strdup(service_name);
            break;
        case PT_SCTP:
            g_free(serv_port_table->sctp_name);
            serv_port_table->sctp_name = g_strdup(service_name);
            break;
        case PT_DCCP:
            g_free(serv_port_table->dccp_name);
            serv_port_table->dccp_name = g_strdup(service_name);
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
    /*
     *  See the services(4) or services(5) man page for services file format
     *  (not available on all systems).
     */

    gchar *cp;
    gchar *service;
    gchar *port;
    port_type proto;

    range_t *port_rng = NULL;
    guint32 max_port = MAX_UDP_PORT;

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

    if ((cp = strtok(NULL, "/")) == NULL)
        return;

    /* seems we got all interesting things from the file */
    if(strcmp(cp, "tcp") == 0) {
        max_port = MAX_TCP_PORT;
        proto = PT_TCP;
    }
    else if(strcmp(cp, "udp") == 0) {
        max_port = MAX_UDP_PORT;
        proto = PT_UDP;
    }
    else if(strcmp(cp, "sctp") == 0) {
        max_port = MAX_SCTP_PORT;
        proto = PT_SCTP;
    }
    else if(strcmp(cp, "dccp") == 0) {
        max_port = MAX_DCCP_PORT;
        proto = PT_DCCP;
    } else {
        return;
    }

    if(CVT_NO_ERROR != range_convert_str(&port_rng, port, max_port) ) {
        /* some assertion here? */
        return;
    }

    cb_service = service;
    cb_proto = proto;
    range_foreach(port_rng, add_serv_port_cb);
    g_free (port_rng);
    cb_proto = PT_NONE;
} /* parse_service_line */


static void
add_serv_port_cb(const guint32 port)
{
    if ( port ) {
        add_service_name(cb_proto, port, cb_service);
    }
}


static void
parse_services_file(const char * path)
{
    FILE *serv_p;
    static int     size = 0;
    static char   *buf = NULL;

    /* services hash table initialization */
    serv_p = ws_fopen(path, "r");

    if (serv_p == NULL)
        return;

    while (fgetline(&buf, &size, serv_p) >= 0) {
        parse_service_line (buf);
    }

    fclose(serv_p);
}

/* -----------------
 * unsigned integer to ascii
 */
static gchar *
ep_utoa(guint port)
{
    gchar *bp = (gchar *)ep_alloc(MAXNAMELEN);

    /* XXX, guint32_to_str() ? */
    guint32_to_str_buf(port, bp, MAXNAMELEN);
    return bp;
}


static gchar
*serv_name_lookup(const guint port, const port_type proto)
{
    serv_port_t *serv_port_table;
    gchar *name;

    serv_port_table = (serv_port_t *)g_hash_table_lookup(serv_port_hashtable, &port);

    if(serv_port_table){
        /* Set which table we should look up port in */
        switch(proto) {
            case PT_UDP:
                if(serv_port_table->udp_name){
                    return serv_port_table->udp_name;
                }
                break;
            case PT_TCP:
                if(serv_port_table->tcp_name){
                    return serv_port_table->tcp_name;
                }
                break;
            case PT_SCTP:
                if(serv_port_table->sctp_name){
                    return serv_port_table->sctp_name;
                }
                break;
            case PT_DCCP:
                if(serv_port_table->dccp_name){
                    return serv_port_table->dccp_name;
                }
                break;
            default:
                /* not yet implemented */
                return NULL;
                /*NOTREACHED*/
        } /* proto */
    }

    /* getservbyport() was used here but it was to expensive, if the functionality is desired
     * it would be better to pre parse etc/services or C:\Windows\System32\drivers\etc at
     * startup
     */
    name = (gchar*)g_malloc(16);
    guint32_to_str_buf(port, name, 16);

    if(serv_port_table == NULL){
        int *key;

        key = (int *)g_new(int, 1);
        *key = port;
        serv_port_table = g_new0(serv_port_t,1);
        g_hash_table_insert(serv_port_hashtable, key, serv_port_table);
    }
    switch(proto) {
        case PT_UDP:
            serv_port_table->udp_name = name;
            break;
        case PT_TCP:
            serv_port_table->tcp_name = name;
            break;
        case PT_SCTP:
            serv_port_table->sctp_name = name;
            break;
        case PT_DCCP:
            serv_port_table->dccp_name = name;
            break;
        default:
            return NULL;
            /*NOTREACHED*/
    }
    return name;

} /* serv_name_lookup */

static void
destroy_serv_port(gpointer data)
{
    serv_port_t *table = (serv_port_t*)data;
    g_free(table->udp_name);
    g_free(table->tcp_name);
    g_free(table->sctp_name);
    g_free(table->dccp_name);
    g_free(table);
}

static void
initialize_services(void)
{
#ifdef _WIN32
    char *hostspath;
    char *sysroot;
    static char rootpath_nt[] = "\\system32\\drivers\\etc\\services";
#endif /* _WIN32 */

    /* the hash table won't ignore duplicates, so use the personal path first */
    g_assert(serv_port_hashtable == NULL);
    serv_port_hashtable = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, destroy_serv_port);

/* Read the system services file first */
#ifdef _WIN32

    sysroot = getenv_utf8("WINDIR");
    if (sysroot != NULL) {
        /*
         * The file should be under WINDIR.
         * If this is Windows NT (NT 4.0,2K,XP,Server2K3), it's in
         * %WINDIR%\system32\drivers\etc\services.
         */
        hostspath = g_strconcat(sysroot, rootpath_nt, NULL);
        parse_services_file(hostspath);
        g_free(hostspath);
    }
#else
        parse_services_file("/etc/services");

#endif /*  _WIN32 */

    /* set personal services path */
    if (g_pservices_path == NULL)
        g_pservices_path = get_persconffile_path(ENAME_SERVICES, FALSE);

    parse_services_file(g_pservices_path);

    /* Compute the pathname of the services file. */
    if (g_services_path == NULL) {
        g_services_path = get_datafile_path(ENAME_SERVICES);
    }

    parse_services_file(g_services_path);

} /* initialize_services */

static void
service_name_lookup_cleanup(void)
{
    if(serv_port_hashtable){
        g_hash_table_destroy(serv_port_hashtable);
        serv_port_hashtable = NULL;
    }
}

/* Fill in an IP4 structure with info from subnets file or just with the
 * string form of the address.
 */
static void
fill_dummy_ip4(const guint addr, hashipv4_t* volatile tp)
{
    subnet_entry_t subnet_entry;

    if ((tp->flags & DUMMY_ADDRESS_ENTRY) == DUMMY_ADDRESS_ENTRY)
        return; /* already done */

    tp->flags = tp->flags | DUMMY_ADDRESS_ENTRY; /* Overwrite if we get async DNS reply */

    /* Do we have a subnet for this address? */
    subnet_entry = subnet_lookup(addr);
    if(0 != subnet_entry.mask) {
        /* Print name, then '.' then IP address after subnet mask */
        guint32 host_addr;
        gchar buffer[MAX_IP_STR_LEN];
        gchar* paddr;
        gsize i;

        host_addr = addr & (~(guint32)subnet_entry.mask);
        ip_to_str_buf((guint8 *)&host_addr, buffer, MAX_IP_STR_LEN);
        paddr = buffer;

        /* Skip to first octet that is not totally masked
         * If length of mask is 32, we chomp the whole address.
         * If the address string starts '.' (should not happen?),
         * we skip that '.'.
         */
        i = subnet_entry.mask_length / 8;
        while(*(paddr) != '\0' && i > 0) {
            if(*(++paddr) == '.') {
                --i;
            }
        }

        /* There are more efficient ways to do this, but this is safe if we
         * trust g_snprintf and MAXNAMELEN
         */
        g_snprintf(tp->name, MAXNAMELEN, "%s%s", subnet_entry.name, paddr);
    } else {
        ip_to_str_buf((const guint8 *)&addr, tp->name, MAXNAMELEN);
    }
}

#ifdef HAVE_C_ARES

static void
c_ares_ghba_cb(
        void *arg,
        int status,
#if ( ( ARES_VERSION_MAJOR < 1 )                                     \
        || ( 1 == ARES_VERSION_MAJOR && ARES_VERSION_MINOR < 5 ) )
        struct hostent *he
#else
        int timeouts _U_,
        struct hostent *he
#endif
        ) {

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
    g_free(caqm);
}
#endif /* HAVE_C_ARES */

/* --------------- */
static hashipv4_t *
new_ipv4(const guint addr)
{
    hashipv4_t *tp = g_new(hashipv4_t, 1);
    tp->addr = addr;
    tp->flags = 0;
    ip_to_str_buf((const guint8 *)&addr, tp->ip, sizeof(tp->ip));
    return tp;
}

static hashipv4_t *
host_lookup(const guint addr, gboolean *found)
{
    hashipv4_t * volatile tp;

    *found = TRUE;

    tp = (hashipv4_t *)g_hash_table_lookup(ipv4_hash_table, GUINT_TO_POINTER(addr));
    if(tp == NULL){
        tp = new_ipv4(addr);
        g_hash_table_insert(ipv4_hash_table, GUINT_TO_POINTER(addr), tp);
    }else{
        if ((tp->flags & DUMMY_AND_RESOLVE_FLGS) ==  DUMMY_ADDRESS_ENTRY){
            goto try_resolv;
        }
        if ((tp->flags & DUMMY_ADDRESS_ENTRY) == DUMMY_ADDRESS_ENTRY){
            *found = FALSE;
        }
        return tp;
    }

try_resolv:
    if (gbl_resolv_flags.network_name && gbl_resolv_flags.use_external_net_name_resolver) {
        tp->flags = tp->flags|TRIED_RESOLVE_ADDRESS;

#ifdef ASYNC_DNS
        if (gbl_resolv_flags.concurrent_dns &&
                name_resolve_concurrency > 0 &&
                async_dns_initialized) {
            add_async_dns_ipv4(AF_INET, addr);
            /* XXX found is set to TRUE, which seems a bit odd, but I'm not
             * going to risk changing the semantics.
             */
            fill_dummy_ip4(addr, tp);
            return tp;
        }
#endif /* ASYNC_DNS */

        /* unknown host or DNS timeout */

    }

    *found = FALSE;

    fill_dummy_ip4(addr, tp);
    return tp;

} /* host_lookup */

/* --------------- */
static hashipv6_t *
new_ipv6(const struct e_in6_addr *addr)
{
    hashipv6_t *tp = g_new(hashipv6_t,1);
    tp->addr = *addr;
    tp->flags = 0;
    ip6_to_str_buf(addr, tp->ip6);
    return tp;
}

/* ------------------------------------ */
static hashipv6_t *
host_lookup6(const struct e_in6_addr *addr, gboolean *found)
{
    hashipv6_t * volatile tp;
#ifdef INET6
#ifdef HAVE_C_ARES
    async_dns_queue_msg_t *caqm;
#endif /* HAVE_C_ARES */
#endif /* INET6 */

    *found = TRUE;

    tp = (hashipv6_t *)g_hash_table_lookup(ipv6_hash_table, addr);
    if(tp == NULL){
        struct e_in6_addr *addr_key;

        addr_key = g_new(struct e_in6_addr,1);
        tp = new_ipv6(addr);
        memcpy(addr_key, addr, 16);
        g_hash_table_insert(ipv6_hash_table, addr_key, tp);
    }else{
        if ((tp->flags & DUMMY_AND_RESOLVE_FLGS) ==  DUMMY_ADDRESS_ENTRY){
            goto try_resolv;
        }
        if ((tp->flags & DUMMY_ADDRESS_ENTRY) == DUMMY_ADDRESS_ENTRY){
            *found = FALSE;
        }
        return tp;
    }

try_resolv:
    if (gbl_resolv_flags.network_name &&
            gbl_resolv_flags.use_external_net_name_resolver) {
        tp->flags = tp->flags|TRIED_RESOLVE_ADDRESS;
#ifdef INET6

#ifdef HAVE_C_ARES
        if ((gbl_resolv_flags.concurrent_dns) &&
                name_resolve_concurrency > 0 &&
                async_dns_initialized) {
            caqm = g_new(async_dns_queue_msg_t,1);
            caqm->family = AF_INET6;
            memcpy(&caqm->addr.ip6, addr, sizeof(caqm->addr.ip6));
            async_dns_queue_head = g_list_append(async_dns_queue_head, (gpointer) caqm);

            /* XXX found is set to TRUE, which seems a bit odd, but I'm not
             * going to risk changing the semantics.
             */
            if ((tp->flags & DUMMY_ADDRESS_ENTRY) == 0){
                g_strlcpy(tp->name, tp->ip6, MAXNAMELEN);
                ip6_to_str_buf(addr, tp->name);
                tp->flags = tp->flags | DUMMY_ADDRESS_ENTRY;
            }
            return tp;
        }
#endif /* HAVE_C_ARES */

#endif /* INET6 */
    }

    /* unknown host or DNS timeout */
    if ((tp->flags & DUMMY_ADDRESS_ENTRY) == 0) {
        tp->flags = tp->flags | DUMMY_ADDRESS_ENTRY;
        g_strlcpy(tp->name, tp->ip6, MAXNAMELEN);
    }
    *found = FALSE;
    return tp;

} /* host_lookup6 */

static const gchar *
solve_address_to_name(const address *addr)
{
    switch (addr->type) {

        case AT_ETHER:
            return get_ether_name((const guint8 *)addr->data);

        case AT_IPv4: {
                          guint32 ip4_addr;
                          memcpy(&ip4_addr, addr->data, sizeof ip4_addr);
                          return get_hostname(ip4_addr);
                      }

        case AT_IPv6: {
                          struct e_in6_addr ip6_addr;
                          memcpy(&ip6_addr.bytes, addr->data, sizeof ip6_addr.bytes);
                          return get_hostname6(&ip6_addr);
                      }

        case AT_STRINGZ:
                      return (const gchar *)addr->data;

        default:
                      return NULL;
    }
}

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
 * If "manuf_file" is FALSE, parse a 6-byte MAC address.
 * If "manuf_file" is TRUE, parse an up-to-6-byte sequence with an optional
 * mask.
 */
static gboolean
parse_ether_address(const char *cp, ether_t *eth, unsigned int *mask,
        const gboolean manuf_file)
{
    int i;
    unsigned long num;
    char *p;
    char sep = '\0';

    for (i = 0; i < 6; i++) {
        /* Get a hex number, 1 or 2 digits, no sign characters allowed. */
        if (!isxdigit((unsigned char)*cp))
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
            if (!manuf_file) {
                /* Entries with masks are allowed only in the "manuf" files. */
                return FALSE;
            }
            cp++; /* skip past the '/' to get to the mask */
            if (!isdigit((unsigned char)*cp))
                return FALSE;   /* no sign allowed */
            num = strtoul(cp, &p, 10);
            if (p == cp)
                return FALSE;   /* failed */
            cp = p;   /* skip past the number */
            if (*cp != '\0' && !isspace((unsigned char)*cp))
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
                if (!manuf_file) {
                    /* Manufacturer IDs are only allowed in the "manuf"
                       files. */
                    return FALSE;
                }
                /* Indicate that this is a manufacturer ID (0 is not allowed
                   as a mask). */
                *mask = 0;
                return TRUE;
            }

            if (i == 5) {
                /* We got 6 bytes, so this is a MAC address.
                   If we're reading one of the "manuf" files, indicate that
                   this is a MAC address (48 is not allowed as a mask). */
                if (manuf_file)
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
        const gboolean manuf_file)
{
    /*
     *  See the ethers(4) or ethers(5) man page for ethers file format
     *  (not available on all systems).
     *  We allow both ethernet address separators (':' and '-'),
     *  as well as Wireshark's '.' separator.
     */

    gchar *cp;

    if ((cp = strchr(line, '#')))
        *cp = '\0';

    if ((cp = strtok(line, " \t")) == NULL)
        return -1;

    if (!parse_ether_address(cp, eth, mask, manuf_file))
        return -1;

    if ((cp = strtok(NULL, " \t")) == NULL)
        return -1;

    g_strlcpy(eth->name, cp, MAXNAMELEN);

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
get_ethent(unsigned int *mask, const gboolean manuf_file)
{

    static ether_t eth;
    static int     size = 0;
    static char   *buf = NULL;

    if (eth_p == NULL)
        return NULL;

    while (fgetline(&buf, &size, eth_p) >= 0) {
        if (parse_ether_line(buf, &eth, mask, manuf_file) == 0) {
            return &eth;
        }
    }

    return NULL;

} /* get_ethent */

#if 0
static ether_t *
get_ethbyname(const gchar *name)
{
    ether_t *eth;

    set_ethent(g_pethers_path);

    while (((eth = get_ethent(NULL, FALSE)) != NULL) && strncmp(name, eth->name, MAXNAMELEN) != 0)
        ;

    if (eth == NULL) {
        end_ethent();

        set_ethent(g_ethers_path);

        while (((eth = get_ethent(NULL, FALSE)) != NULL) && strncmp(name, eth->name, MAXNAMELEN) != 0)
            ;

        end_ethent();
    }

    return eth;

} /* get_ethbyname */
#endif

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


static void
add_manuf_name(const guint8 *addr, unsigned int mask, gchar *name)
{
    guint8 *wka_key;
    int    *manuf_key;

    /*
     * XXX - can we use Standard Annotation Language annotations to
     * note that mask, as returned by parse_ethe)r_address() (and thus
     * by the routines that call it, and thus passed to us) cannot be > 48,
     * or is SAL too weak to express that?
     */
    if (mask >= 48) {
        /* This is a well-known MAC address; just add this to the Ethernet
           hash table */
        add_eth_name(addr, name);
        return;
    }

    if (mask == 0) {
        /* This is a manufacturer ID; add it to the manufacturer ID hash table */

        /* manuf needs only the 3 most significant octets of the ethernet address */
        manuf_key = (int *)g_new(int, 1);
        *manuf_key = (int)((addr[2] << 16) + (addr[1] << 8) + addr[0]);

        g_hash_table_insert(manuf_hashtable, manuf_key, g_strdup(name));
        return;
    } /* mask == 0 */

    /* This is a range of well-known addresses; add it to the appropriate
       well-known-address table, creating that table if necessary. */

    wka_key = (guint8 *)g_malloc(6);
    memcpy(wka_key, addr, 6);

    g_hash_table_insert(wka_hashtable, wka_key, g_strdup(name));

} /* add_manuf_name */

static gchar *
manuf_name_lookup(const guint8 *addr)
{
    gint32       manuf_key = 0;
    guint8       oct;
    gchar        *name;

    /* manuf needs only the 3 most significant octets of the ethernet address */
    manuf_key = addr[0];
    manuf_key = manuf_key<<8;
    oct = addr[1];
    manuf_key = manuf_key | oct;
    manuf_key = manuf_key<<8;
    oct = addr[2];
    manuf_key = manuf_key | oct;


    /* first try to find a "perfect match" */
    name = (gchar *)g_hash_table_lookup(manuf_hashtable, &manuf_key);
    if(name != NULL){
        return name;
    }

    /* Mask out the broadcast/multicast flag but not the locally
     * administered flag as localy administered means: not assigend
     * by the IEEE but the local administrator instead.
     * 0x01 multicast / broadcast bit
     * 0x02 locally administered bit */
    if((manuf_key & 0x00010000) != 0){
        manuf_key &= 0x00FEFFFF;
        name = (gchar *)g_hash_table_lookup(manuf_hashtable, &manuf_key);
        if(name != NULL){
            return name;
        }
    }

    return NULL;

} /* manuf_name_lookup */

static gchar *
wka_name_lookup(const guint8 *addr, const unsigned int mask)
{
    guint8     masked_addr[6];
    guint      num;
    gint       i;
    gchar     *name;

    if(wka_hashtable == NULL){
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

    name = (gchar *)g_hash_table_lookup(wka_hashtable, masked_addr);

    return name;

} /* wka_name_lookup */

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
    char    *manuf_path;
    guint    mask;

    /* hash table initialization */
    wka_hashtable   = g_hash_table_new_full(eth_addr_hash, eth_addr_cmp, g_free, g_free);
    manuf_hashtable = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
    eth_hashtable   = g_hash_table_new_full(eth_addr_hash, eth_addr_cmp, NULL, g_free);

    /* Compute the pathname of the ethers file. */
    if (g_ethers_path == NULL) {
        g_ethers_path = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s",
                get_systemfile_dir(), ENAME_ETHERS);
    }

    /* Set g_pethers_path here, but don't actually do anything
     * with it. It's used in get_ethbyname() and get_ethbyaddr()
     */
    if (g_pethers_path == NULL)
        g_pethers_path = get_persconffile_path(ENAME_ETHERS, FALSE);

    /* Compute the pathname of the manuf file */
    manuf_path = get_datafile_path(ENAME_MANUF);

    /* Read it and initialize the hash table */
    set_ethent(manuf_path);

    while ((eth = get_ethent(&mask, TRUE))) {
        add_manuf_name(eth->addr, mask, eth->name);
    }

    end_ethent();

    g_free(manuf_path);

} /* initialize_ethers */

/* this is only needed when shuting down application (if at all) */
static void
eth_name_lookup_cleanup(void)
{

    if(manuf_hashtable) {
        g_hash_table_destroy(manuf_hashtable);
        manuf_hashtable = NULL;
    }
    if(wka_hashtable) {
        g_hash_table_destroy(wka_hashtable);
        wka_hashtable = NULL;
    }

    if(eth_hashtable) {
        g_hash_table_destroy(eth_hashtable);
        eth_hashtable = NULL;
    }

}

/* Resolve ethernet address */
static hashether_t *
eth_addr_resolve(hashether_t *tp) {
    ether_t      *eth;
    const guint8 *addr = tp->addr;

    if ( (eth = get_ethbyaddr(addr)) != NULL) {
        g_strlcpy(tp->resolved_name, eth->name, MAXNAMELEN);
        tp->status = HASHETHER_STATUS_RESOLVED_NAME;
        return tp;
    } else {
        guint         mask;
        gchar        *name;

        /* Unknown name.  Try looking for it in the well-known-address
           tables for well-known address ranges smaller than 2^24. */
        mask = 7;
        for (;;) {
            /* Only the topmost 5 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+40)) != NULL) {
                g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x",
                        name, addr[5] & (0xFF >> mask));
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
            if (mask == 0)
                break;
            mask--;
        }

        mask = 7;
        for (;;) {
            /* Only the topmost 4 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+32)) != NULL) {
                g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x",
                        name, addr[4] & (0xFF >> mask), addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
            if (mask == 0)
                break;
            mask--;
        }

        mask = 7;
        for (;;) {
            /* Only the topmost 3 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+24)) != NULL) {
                g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x",
                        name, addr[3] & (0xFF >> mask), addr[4], addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
            if (mask == 0)
                break;
            mask--;
        }

        /* Now try looking in the manufacturer table. */
        if ((name = manuf_name_lookup(addr)) != NULL) {
            g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x",
                    name, addr[3], addr[4], addr[5]);
            tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
            return tp;
        }

        /* Now try looking for it in the well-known-address
           tables for well-known address ranges larger than 2^24. */
        mask = 7;
        for (;;) {
            /* Only the topmost 2 bytes participate fully */
            if ((name = wka_name_lookup(addr, mask+16)) != NULL) {
                g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x",
                        name, addr[2] & (0xFF >> mask), addr[3], addr[4],
                        addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
            if (mask == 0)
                break;
            mask--;
        }

        mask = 7;
        for (;;) {
            /* Only the topmost byte participates fully */
            if ((name = wka_name_lookup(addr, mask+8)) != NULL) {
                g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x",
                        name, addr[1] & (0xFF >> mask), addr[2], addr[3],
                        addr[4], addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
            if (mask == 0)
                break;
            mask--;
        }

        for (mask = 7; mask > 0; mask--) {
            /* Not even the topmost byte participates fully */
            if ((name = wka_name_lookup(addr, mask)) != NULL) {
                g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x:%02x",
                        name, addr[0] & (0xFF >> mask), addr[1], addr[2],
                        addr[3], addr[4], addr[5]);
                tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
                return tp;
            }
        }

        /* No match whatsoever. */
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s", ether_to_str(addr));
        tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
        return tp;
    }
    g_assert_not_reached();
} /* eth_addr_resolve */

static hashether_t *
eth_hash_new_entry(const guint8 *addr, const gboolean resolve)
{
    hashether_t *tp;
    char *endp;

    tp = g_new(hashether_t, 1);
    memcpy(tp->addr, addr, sizeof(tp->addr));
    tp->status = HASHETHER_STATUS_UNRESOLVED;
    /* Values returned by bytes_to_hexstr_punct() are *not* null-terminated */
    endp = bytes_to_hexstr_punct(tp->hexaddr, addr, sizeof(tp->addr), ':');
    *endp = '\0';
    tp->resolved_name[0] = '\0';

    if (resolve)
        eth_addr_resolve(tp);

    g_hash_table_insert(eth_hashtable, tp->addr, tp);

    return tp;
} /* eth_hash_new_entry */

static hashether_t *
add_eth_name(const guint8 *addr, const gchar *name)
{
    hashether_t *tp;

    tp = (hashether_t *)g_hash_table_lookup(eth_hashtable, addr);

    if( tp == NULL ){
        tp = eth_hash_new_entry(addr, FALSE);
    }

    g_strlcpy(tp->resolved_name, name, MAXNAMELEN);
    tp->status = HASHETHER_STATUS_RESOLVED_NAME;
    new_resolved_objects = TRUE;

    return tp;
} /* add_eth_name */

static hashether_t *
eth_name_lookup(const guint8 *addr, const gboolean resolve)
{
    hashether_t  *tp;

    tp = (hashether_t *)g_hash_table_lookup(eth_hashtable, addr);
    if( tp == NULL ) {
        tp = eth_hash_new_entry(addr, resolve);
    } else {
        if (resolve && (tp->status == HASHETHER_STATUS_UNRESOLVED)){
            eth_addr_resolve(tp); /* Found but needs to be resolved */
        }
    }

    return tp;

} /* eth_name_lookup */

static guint8 *
eth_addr_lookup(const gchar *name _U_)
{
#if 0
    /* XXX Do we need reverse lookup??? */
    ether_t      *eth;
    hashether_t  *tp;
    hashether_t **table = eth_table;
    gint          i;

    /* to be optimized (hash table from name to addr) */
    for (i = 0; i < HASHETHSIZE; i++) {
        tp = table[i];
        while (tp) {
            if (strcmp(tp->resolved_name, name) == 0)
                return tp->addr;
            tp = tp->next;
        }
    }

    /* not in hash table : performs a file lookup */

    if ((eth = get_ethbyname(name)) == NULL)
        return NULL;

    /* add new entry in hash table */

    tp = add_eth_name(eth->addr, name);

    return tp->addr;
#endif
    return NULL;

} /* eth_addr_lookup */


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

    g_strlcpy(ipxnet->name, cp, MAXNAMELEN);

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
    static int     size = 0;
    static char   *buf = NULL;

    if (ipxnet_p == NULL)
        return NULL;

    while (fgetline(&buf, &size, ipxnet_p) >= 0) {
        if (parse_ipxnets_line(buf, &ipxnet) == 0) {
            return &ipxnet;
        }
    }

    return NULL;

} /* get_ipxnetent */

/* Unused ??? */
#if 0
static ipxnet_t *
get_ipxnetbyname(const gchar *name)
{
    ipxnet_t *ipxnet;

    set_ipxnetent(g_ipxnets_path);

    while (((ipxnet = get_ipxnetent()) != NULL) && strncmp(name, ipxnet->name, MAXNAMELEN) != 0)
        ;

    if (ipxnet == NULL) {
        end_ipxnetent();

        set_ipxnetent(g_pipxnets_path);

        while (((ipxnet = get_ipxnetent()) != NULL) && strncmp(name, ipxnet->name, MAXNAMELEN) != 0)
            ;

        end_ipxnetent();
    }

    return ipxnet;

} /* get_ipxnetbyname */
#endif

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
        g_ipxnets_path = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s",
                get_systemfile_dir(), ENAME_IPXNETS);
    }

    /* Set g_pipxnets_path here, but don't actually do anything
     * with it. It's used in get_ipxnetbyname() and get_ipxnetbyaddr()
     */
    if (g_pipxnets_path == NULL)
        g_pipxnets_path = get_persconffile_path(ENAME_IPXNETS, FALSE);

} /* initialize_ipxnets */

static void
ipx_name_lookup_cleanup(void)
{
    if(ipxnet_hash_table){
        g_hash_table_destroy(ipxnet_hash_table);
        ipxnet_hash_table = NULL;
    }

}

#if 0
static hashipxnet_t *
add_ipxnet_name(guint addr, const gchar *name)
{
    hashipxnet_t *tp;

    tp = (hashipxnet_t   *)g_hash_table_lookup(ipxnet_hash_table, &addr);
    if(tp){
        g_strlcpy(tp->name, name, MAXNAMELEN);
    }else{
        int *key;

        key = (int *)g_new(int, 1);
        *key = addr;
        tp = g_new(hashipxnet_t,1);
        g_strlcpy(tp->name, name, MAXNAMELEN);
        g_hash_table_insert(ipxnet_hash_table, key, tp);
    }

    tp->addr = addr;
    g_strlcpy(tp->name, name, MAXNAMELEN);
    tp->next = NULL;
    new_resolved_objects = TRUE;

    return tp;

} /* add_ipxnet_name */
#endif

static gchar *
ipxnet_name_lookup(const guint addr)
{
    hashipxnet_t *tp;
    ipxnet_t *ipxnet;

    tp = (hashipxnet_t *)g_hash_table_lookup(ipxnet_hash_table, &addr);
    if(tp == NULL){
        int *key;

        key = (int *)g_new(int, 1);
        *key = addr;
        tp = g_new(hashipxnet_t, 1);
        g_hash_table_insert(ipxnet_hash_table, key, tp);
    }else{
        return tp->name;
    }

    /* fill in a new entry */

    tp->addr = addr;

    if ( (ipxnet = get_ipxnetbyaddr(addr)) == NULL) {
        /* unknown name */
        g_snprintf(tp->name, MAXNAMELEN, "%X", addr);

    } else {
        g_strlcpy(tp->name, ipxnet->name, MAXNAMELEN);
    }

    return (tp->name);

} /* ipxnet_name_lookup */

static guint
ipxnet_addr_lookup(const gchar *name _U_, gboolean *success)
{
    *success = FALSE;
    return 0;
#if 0
    /* XXX Do we need reverse lookup??? */
    ipxnet_t *ipxnet;
    hashipxnet_t *tp;
    hashipxnet_t **table = ipxnet_table;
    int i;

    /* to be optimized (hash table from name to addr) */
    for (i = 0; i < HASHIPXNETSIZE; i++) {
        tp = table[i];
        while (tp) {
            if (strcmp(tp->name, name) == 0) {
                *success = TRUE;
                return tp->addr;
            }
            tp = tp->next;
        }
    }

    /* not in hash table : performs a file lookup */

    if ((ipxnet = get_ipxnetbyname(name)) == NULL) {
        *success = FALSE;
        return 0;
    }

    /* add new entry in hash table */

    tp = add_ipxnet_name(ipxnet->addr, name);

    *success = TRUE;
    return tp->addr;
#endif
} /* ipxnet_addr_lookup */

static gboolean
read_hosts_file (const char *hostspath)
{
    FILE *hf;
    char *line = NULL;
    int size = 0;
    gchar *cp;
    guint32 host_addr[4]; /* IPv4 or IPv6 */
    struct e_in6_addr ip6_addr;
    gboolean is_ipv6;
    int ret;

    /*
     *  See the hosts(4) or hosts(5) man page for hosts file format
     *  (not available on all systems).
     */
    if ((hf = ws_fopen(hostspath, "r")) == NULL)
        return FALSE;

    while (fgetline(&line, &size, hf) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        if ((cp = strtok(line, " \t")) == NULL)
            continue; /* no tokens in the line */

        ret = inet_pton(AF_INET6, cp, &host_addr);
        if (ret < 0)
            continue; /* error parsing */
        if (ret > 0) {
            /* Valid IPv6 */
            is_ipv6 = TRUE;
        } else {
            /* Not valid IPv6 - valid IPv4? */
            if (!str_to_ip(cp, &host_addr))
                continue; /* no */
            is_ipv6 = FALSE;
        }

        if ((cp = strtok(NULL, " \t")) == NULL)
            continue; /* no host name */

        if (is_ipv6) {
            memcpy(&ip6_addr, host_addr, sizeof ip6_addr);
            add_ipv6_name(&ip6_addr, cp);
        } else
            add_ipv4_name(host_addr[0], cp);

        /*
         * Add the aliases, too, if there are any.
         * XXX - host_lookup() only returns the first entry.
         */
        while ((cp = strtok(NULL, " \t")) != NULL) {
            if (is_ipv6) {
                memcpy(&ip6_addr, host_addr, sizeof ip6_addr);
                add_ipv6_name(&ip6_addr, cp);
            } else
                add_ipv4_name(host_addr[0], cp);
        }
    }
    g_free(line);

    fclose(hf);
    return TRUE;
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
        g_ptr_array_add(extra_hosts_files, g_strdup(hosts_file));
        return read_hosts_file (hosts_file);
    }
    return TRUE;
}

gboolean
add_ip_name_from_string (const char *addr, const char *name)
{
    guint32 host_addr[4]; /* IPv4 */
    struct e_in6_addr ip6_addr; /* IPv6 */
    gboolean is_ipv6;
    int ret;
    resolved_ipv4_t *resolved_ipv4_entry;
    resolved_ipv6_t *resolved_ipv6_entry;

    ret = inet_pton(AF_INET6, addr, &ip6_addr);
    if (ret < 0)
        /* Error parsing address */
        return FALSE;

    if (ret > 0) {
        /* Valid IPv6 */
        is_ipv6 = TRUE;
    } else {
        /* Not valid IPv6 - valid IPv4? */
        if (!str_to_ip(addr, &host_addr))
            return FALSE; /* no */
        is_ipv6 = FALSE;
    }

    if (is_ipv6) {
        resolved_ipv6_entry = g_new(resolved_ipv6_t, 1);
        memcpy(&(resolved_ipv6_entry->ip6_addr), &ip6_addr, 16);
        g_strlcpy(resolved_ipv6_entry->name, name, MAXNAMELEN);
        manually_resolved_ipv6_list = g_slist_prepend(manually_resolved_ipv6_list, resolved_ipv6_entry);
    } else {
        resolved_ipv4_entry = g_new(resolved_ipv4_t, 1);
        resolved_ipv4_entry->host_addr = host_addr[0];
        g_strlcpy(resolved_ipv4_entry->name, name, MAXNAMELEN);
        manually_resolved_ipv4_list = g_slist_prepend(manually_resolved_ipv4_list, resolved_ipv4_entry);
    }

    return TRUE;
} /* add_ip_name_from_string */

/*
 * Add the resolved addresses that are in use to the list used to create the NRB
 */
static void
ipv4_hash_table_resolved_to_list(gpointer key _U_, gpointer value, gpointer user_data)
{
    addrinfo_lists_t *lists = (addrinfo_lists_t*)user_data;
    hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *)value;

    if((ipv4_hash_table_entry->flags & USED_AND_RESOLVED_MASK) == RESOLVED_ADDRESS_USED){
        lists->ipv4_addr_list = g_list_prepend (lists->ipv4_addr_list, ipv4_hash_table_entry);
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

    if((ipv6_hash_table_entry->flags & USED_AND_RESOLVED_MASK) == RESOLVED_ADDRESS_USED){
        lists->ipv6_addr_list = g_list_prepend (lists->ipv6_addr_list, ipv6_hash_table_entry);
    }

}

addrinfo_lists_t *
get_addrinfo_list(void) {

    if(ipv4_hash_table){
        g_hash_table_foreach(ipv4_hash_table, ipv4_hash_table_resolved_to_list, &addrinfo_lists);
    }

    if(ipv6_hash_table){
        g_hash_table_foreach(ipv6_hash_table, ipv6_hash_table_resolved_to_list, &addrinfo_lists);
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
    char *line = NULL;
    int size = 0;
    gchar *cp, *cp2;
    guint32 host_addr; /* IPv4 ONLY */
    int mask_length;

    if ((hf = ws_fopen(subnetspath, "r")) == NULL)
        return FALSE;

    while (fgetline(&line, &size, hf) >= 0) {
        if ((cp = strchr(line, '#')))
            *cp = '\0';

        if ((cp = strtok(line, " \t")) == NULL)
            continue; /* no tokens in the line */


        /* Expected format is <IP4 address>/<subnet length> */
        cp2 = strchr(cp, '/');
        if(NULL == cp2) {
            /* No length */
            continue;
        }
        *cp2 = '\0'; /* Cut token */
        ++cp2    ;

        /* Check if this is a valid IPv4 address */
        if (!str_to_ip(cp, &host_addr)) {
            continue; /* no */
        }

        mask_length = atoi(cp2);
        if(0 >= mask_length || mask_length > 31) {
            continue; /* invalid mask length */
        }

        if ((cp = strtok(NULL, " \t")) == NULL)
            continue; /* no subnet name */

        subnet_entry_set(host_addr, (guint32)mask_length, cp);
    }
    g_free(line);

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
        g_assert(i < SUBNETLENGTHSIZE);


        length_entry = &subnet_length_entries[i];

        if(NULL != length_entry->subnet_addresses) {
            sub_net_hashipv4_t * tp;
            guint32 hash_idx;

            masked_addr = addr & length_entry->mask;
            hash_idx = HASH_IPV4_ADDRESS(masked_addr);

            tp = length_entry->subnet_addresses[hash_idx];
            while(tp != NULL && tp->addr != masked_addr) {
                tp = tp->next;
            }

            if(NULL != tp) {
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
subnet_entry_set(guint32 subnet_addr, const guint32 mask_length, const gchar* name)
{
    subnet_length_entry_t* entry;
    sub_net_hashipv4_t * tp;
    gsize hash_idx;

    g_assert(mask_length > 0 && mask_length <= 32);

    entry = &subnet_length_entries[mask_length - 1];

    subnet_addr &= entry->mask;

    hash_idx = HASH_IPV4_ADDRESS(subnet_addr);

    if(NULL == entry->subnet_addresses) {
        entry->subnet_addresses = (sub_net_hashipv4_t**) se_alloc0(sizeof(sub_net_hashipv4_t*) * HASHHOSTSIZE);
    }

    if(NULL != (tp = entry->subnet_addresses[hash_idx])) {
        if(tp->addr == subnet_addr) {
            return;    /* XXX provide warning that an address was repeated? */
        } else {
            sub_net_hashipv4_t * new_tp = se_new(sub_net_hashipv4_t);
            tp->next = new_tp;
            tp = new_tp;
        }
    } else {
        tp = entry->subnet_addresses[hash_idx] = se_new(sub_net_hashipv4_t);
    }

    tp->next = NULL;
    tp->addr = subnet_addr;
    /* Clear DUMMY_ADDRESS_ENTRY */
    tp->flags = tp->flags & 0xfe; /*Never used again...*/
    g_strlcpy(tp->name, name, MAXNAMELEN); /* This is longer than subnet names can actually be */
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

    subnetspath = get_persconffile_path(ENAME_SUBNETS, FALSE);
    if (!read_subnets_file(subnetspath) && errno != ENOENT) {
        report_open_failure(subnetspath, errno, FALSE);
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


/*
 *  External Functions
 */

void
addr_resolve_pref_init(module_t *nameres)
{
    prefs_register_bool_preference(nameres, "mac_name",
            "Resolve MAC addresses",
            "Resolve Ethernet MAC address to manufacturer names",
            &gbl_resolv_flags.mac_name);

    prefs_register_bool_preference(nameres, "transport_name",
            "Resolve transport names",
            "Resolve TCP/UDP ports into service names",
            &gbl_resolv_flags.transport_name);

    prefs_register_bool_preference(nameres, "network_name",
            "Resolve network (IP) addresses",
            "Resolve IPv4, IPv6, and IPX addresses into host names."
            " The next set of check boxes determines how name resolution should be performed."
            " If no other options are checked name resolution is made from Wireshark's host file,"
            " capture file name resolution blocks and DNS packets in the capture.",
            &gbl_resolv_flags.network_name);

    prefs_register_bool_preference(nameres, "use_external_name_resolver",
            "Use an external network name resolver",
            "Use your system's configured name resolver"
            " (usually DNS) to resolve network names."
            " Only applies when network name resolution"
            " is enabled.",
            &gbl_resolv_flags.use_external_net_name_resolver);

#if defined(HAVE_C_ARES) || defined(HAVE_GNU_ADNS)
    prefs_register_bool_preference(nameres, "concurrent_dns",
            "Enable concurrent DNS name resolution",
            "Enable concurrent DNS name resolution. Only"
            " applies when network name resolution is"
            " enabled. You probably want to enable this.",
            &gbl_resolv_flags.concurrent_dns);

    prefs_register_uint_preference(nameres, "name_resolve_concurrency",
            "Maximum concurrent requests",
            "The maximum number of DNS requests that may"
            " be active at any time. A large value (many"
            " thousands) might overload the network or make"
            " your DNS server behave badly.",
            10,
            &name_resolve_concurrency);
#else
    prefs_register_static_text_preference(nameres, "concurrent_dns",
            "Enable concurrent DNS name resolution: N/A",
            "Support for concurrent DNS name resolution was not"
            " compiled into this version of Wireshark");
#endif

    prefs_register_bool_preference(nameres, "hosts_file_handling",
            "Only use the profile \"hosts\" file",
            "By default \"hosts\" files will be loaded from multiple sources."
            " Checking this box only loads the \"hosts\" in the current profile.",
            &gbl_resolv_flags.load_hosts_file_from_profile_only);

}

#ifdef HAVE_C_ARES
gboolean
host_name_lookup_process(void) {
    async_dns_queue_msg_t *caqm;
    struct timeval tv = { 0, 0 };
    int nfds;
    fd_set rfds, wfds;
    gboolean nro = new_resolved_objects;

    new_resolved_objects = FALSE;

    if (!async_dns_initialized)
        /* c-ares not initialized. Bail out and cancel timers. */
        return nro;

    async_dns_queue_head = g_list_first(async_dns_queue_head);

    while (async_dns_queue_head != NULL && async_dns_in_flight <= name_resolve_concurrency) {
        caqm = (async_dns_queue_msg_t *) async_dns_queue_head->data;
        async_dns_queue_head = g_list_remove(async_dns_queue_head, (void *) caqm);
        if (caqm->family == AF_INET) {
            ares_gethostbyaddr(ghba_chan, &caqm->addr.ip4, sizeof(guint32), AF_INET,
                    c_ares_ghba_cb, caqm);
            async_dns_in_flight++;
        } else if (caqm->family == AF_INET6) {
            ares_gethostbyaddr(ghba_chan, &caqm->addr.ip6, sizeof(struct e_in6_addr),
                    AF_INET6, c_ares_ghba_cb, caqm);
            async_dns_in_flight++;
        }
    }

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    nfds = ares_fds(ghba_chan, &rfds, &wfds);
    if (nfds > 0) {
        if (select(nfds, &rfds, &wfds, NULL, &tv) == -1) { /* call to select() failed */
            fprintf(stderr, "Warning: call to select() failed, error is %s\n", strerror(errno));
            return nro;
        }
        ares_process(ghba_chan, &rfds, &wfds);
    }

    /* Any new entries? */
    return nro;
}

static void
_host_name_lookup_cleanup(void) {
    GList *cur;

    cur = g_list_first(async_dns_queue_head);
    while (cur) {
        g_free(cur->data);
        cur = g_list_next (cur);
    }

    g_list_free(async_dns_queue_head);
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

#elif defined(HAVE_GNU_ADNS)

/* XXX - The ADNS "documentation" isn't very clear:
 * - Do we need to keep our query structures around?
 */
gboolean
host_name_lookup_process(void) {
    async_dns_queue_msg_t *almsg;
    GList *cur;
    char addr_str[] = "111.222.333.444.in-addr.arpa.";
    guint8 *addr_bytes;
    adns_answer *ans;
    int ret;
    gboolean dequeue;
    gboolean nro = new_resolved_objects;

    new_resolved_objects = FALSE;
    async_dns_queue_head = g_list_first(async_dns_queue_head);

    cur = async_dns_queue_head;
    while (cur &&  async_dns_in_flight <= name_resolve_concurrency) {
        almsg = (async_dns_queue_msg_t *) cur->data;
        if (! almsg->submitted && almsg->type == AF_INET) {
            addr_bytes = (guint8 *) &almsg->ip4_addr;
            g_snprintf(addr_str, sizeof addr_str, "%u.%u.%u.%u.in-addr.arpa.", addr_bytes[3],
                    addr_bytes[2], addr_bytes[1], addr_bytes[0]);
            /* XXX - what if it fails? */
            adns_submit (ads, addr_str, adns_r_ptr, adns_qf_none, NULL, &almsg->query);
            almsg->submitted = TRUE;
            async_dns_in_flight++;
        }
        cur = cur->next;
    }

    cur = async_dns_queue_head;
    while (cur) {
        dequeue = FALSE;
        almsg = (async_dns_queue_msg_t *) cur->data;
        if (almsg->submitted) {
            ret = adns_check(ads, &almsg->query, &ans, NULL);
            if (ret == 0) {
                if (ans->status == adns_s_ok) {
                    add_ipv4_name(almsg->ip4_addr, *ans->rrs.str);
                }
                dequeue = TRUE;
            }
        }
        cur = cur->next;
        if (dequeue) {
            async_dns_queue_head = g_list_remove(async_dns_queue_head, (void *) almsg);
            g_free(almsg);
            /* XXX, what to do if async_dns_in_flight == 0? */
            async_dns_in_flight--;
        }
    }

    /* Keep the timeout in place */
    return nro;
}

static void
_host_name_lookup_cleanup(void) {
    void *qdata;

    async_dns_queue_head = g_list_first(async_dns_queue_head);
    while (async_dns_queue_head) {
        qdata = async_dns_queue_head->data;
        async_dns_queue_head = g_list_remove(async_dns_queue_head, qdata);
        g_free(qdata);
    }

    if (async_dns_initialized)
        adns_finish(ads);
    async_dns_initialized = FALSE;
}

#else /* HAVE_GNU_ADNS */

gboolean
host_name_lookup_process(void) {
    gboolean nro = new_resolved_objects;

    new_resolved_objects = FALSE;

    return nro;
}

static void
_host_name_lookup_cleanup(void) {
}

#endif /* HAVE_C_ARES */

const gchar *
get_hostname(const guint addr)
{
    gboolean found;

    /* XXX why do we call this if we're not resolving? To create hash entries?
     * Why?
     */
    hashipv4_t *tp = host_lookup(addr, &found);

    if (!gbl_resolv_flags.network_name)
        return tp->ip;

    tp->flags = tp->flags | RESOLVED_ADDRESS_USED;

    return tp->name;
}

/* -------------------------- */

const gchar *
get_hostname6(const struct e_in6_addr *addr)
{
    gboolean found;

    /* XXX why do we call this if we're not resolving? To create hash entries?
     * Why?
     */
    hashipv6_t *tp = host_lookup6(addr, &found);

    if (!gbl_resolv_flags.network_name)
        return tp->ip6;

    tp->flags = tp->flags | RESOLVED_ADDRESS_USED;

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
    if (name[0] == '\0')
        return;


    tp = (hashipv4_t *)g_hash_table_lookup(ipv4_hash_table, GUINT_TO_POINTER(addr));
    if(tp){
        g_strlcpy(tp->name, name, MAXNAMELEN);
    }else{
        tp = new_ipv4(addr);
        g_strlcpy(tp->name, name, MAXNAMELEN);
        g_hash_table_insert(ipv4_hash_table, GUINT_TO_POINTER(addr), tp);
    }

    g_strlcpy(tp->name, name, MAXNAMELEN);
    tp->flags = tp->flags | TRIED_RESOLVE_ADDRESS;
    new_resolved_objects = TRUE;

} /* add_ipv4_name */

/* -------------------------- */
void
add_ipv6_name(const struct e_in6_addr *addrp, const gchar *name)
{
    hashipv6_t *tp;

    /*
     * Don't add zero-length names; apparently, some resolvers will return
     * them if they get them from DNS.
     */
    if (name[0] == '\0')
        return;

    tp = (hashipv6_t *)g_hash_table_lookup(ipv6_hash_table, addrp);
    if(tp){
        g_strlcpy(tp->name, name, MAXNAMELEN);
    }else{
        struct e_in6_addr *addr_key;

        addr_key = g_new(struct e_in6_addr,1);
        tp = new_ipv6(addrp);
        memcpy(addr_key, addrp, 16);
        g_strlcpy(tp->name, name, MAXNAMELEN);
        g_hash_table_insert(ipv6_hash_table, addr_key, tp);
    }

    g_strlcpy(tp->name, name, MAXNAMELEN);
    tp->flags = tp->flags | TRIED_RESOLVE_ADDRESS;
    new_resolved_objects = TRUE;

} /* add_ipv6_name */

static void
add_manually_resolved_ipv4(gpointer data, gpointer user_data _U_)
{
    resolved_ipv4_t *resolved_ipv4_entry = (resolved_ipv4_t *)data;

    add_ipv4_name(resolved_ipv4_entry->host_addr, resolved_ipv4_entry->name);
}

static void
add_manually_resolved_ipv6(gpointer data, gpointer user_data _U_)
{
    resolved_ipv6_t *resolved_ipv6_entry = (resolved_ipv6_t *)data;

    add_ipv6_name(&(resolved_ipv6_entry->ip6_addr), resolved_ipv6_entry->name);
}

static void
add_manually_resolved(void)
{
    if(manually_resolved_ipv4_list){
        g_slist_foreach(manually_resolved_ipv4_list, add_manually_resolved_ipv4, NULL);
    }

    if(manually_resolved_ipv6_list){
        g_slist_foreach(manually_resolved_ipv6_list, add_manually_resolved_ipv6, NULL);
    }
}

void
host_name_lookup_init(void)
{
    char *hostspath;
    guint i;

#ifdef HAVE_GNU_ADNS
#ifdef _WIN32
    char *sysroot;
    static char rootpath_nt[] = "\\system32\\drivers\\etc\\hosts";
    static char rootpath_ot[] = "\\hosts";
#endif /* _WIN32 */
#endif /*GNU_ADNS */

    g_assert(ipxnet_hash_table == NULL);
    ipxnet_hash_table = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);

    g_assert(ipv4_hash_table == NULL);
    ipv4_hash_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    g_assert(ipv6_hash_table == NULL);
    ipv6_hash_table = g_hash_table_new_full(ipv6_oat_hash, ipv6_equal, g_free, g_free);

    /*
     * Load the global hosts file, if we have one.
     */
    if(!gbl_resolv_flags.load_hosts_file_from_profile_only){
        hostspath = get_datafile_path(ENAME_HOSTS);
        if (!read_hosts_file(hostspath) && errno != ENOENT) {
            report_open_failure(hostspath, errno, FALSE);
        }
        g_free(hostspath);
    }
    /*
     * Load the user's hosts file no matter what, if they have one.
     */
    hostspath = get_persconffile_path(ENAME_HOSTS, TRUE);
    if (!read_hosts_file(hostspath) && errno != ENOENT) {
        report_open_failure(hostspath, errno, FALSE);
    }
    g_free(hostspath);
#ifdef HAVE_C_ARES
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
    if (ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS) {
#endif
        if (ares_init(&ghba_chan) == ARES_SUCCESS && ares_init(&ghbn_chan) == ARES_SUCCESS) {
            async_dns_initialized = TRUE;
        }
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
    }
#endif
#else
#ifdef HAVE_GNU_ADNS
    /*
     * We're using GNU ADNS, which doesn't check the system hosts file;
     * we load that file ourselves.
     */
#ifdef _WIN32

    sysroot = getenv_utf8("WINDIR");
    if (sysroot != NULL) {
        /*
         * The file should be under WINDIR.
         * If this is Windows NT (NT 4.0,2K,XP,Server2K3), it's in
         * %WINDIR%\system32\drivers\etc\hosts.
         * If this is Windows OT (95,98,Me), it's in %WINDIR%\hosts.
         * Try both.
         * XXX - should we base it on the dwPlatformId value from
         * GetVersionEx()?
         */
        if(!gbl_resolv_flags.load_hosts_file_from_profile_only){
            hostspath = g_strconcat(sysroot, rootpath_nt, NULL);
            if (!read_hosts_file(hostspath)) {
                g_free(hostspath);
                hostspath = g_strconcat(sysroot, rootpath_ot, NULL);
                read_hosts_file(hostspath);
            }
            g_free(hostspath);
        }
    }
#else /* _WIN32 */
    if(!gbl_resolv_flags.load_hosts_file_from_profile_only){
        read_hosts_file("/etc/hosts");
    }
#endif /* _WIN32 */

    /* XXX - Any flags we should be using? */
    /* XXX - We could provide config settings for DNS servers, and
       pass them to ADNS with adns_init_strcfg */
    if (adns_init(&ads, adns_if_none, 0 /*0=>stderr*/) != 0) {
        /*
         * XXX - should we report the error?  I'm assuming that some crashes
         * reported on a Windows machine with TCP/IP not configured are due
         * to "adns_init()" failing (due to the lack of TCP/IP) and leaving
         * ADNS in a state where it crashes due to that.  We'll still try
         * doing name resolution anyway.
         */
        return;
    }
    async_dns_initialized = TRUE;
    async_dns_in_flight = 0;
#endif /* HAVE_GNU_ADNS */
#endif /* HAVE_C_ARES */

    if(extra_hosts_files && !gbl_resolv_flags.load_hosts_file_from_profile_only){
        for (i = 0; i < extra_hosts_files->len; i++) {
            read_hosts_file((const char *) g_ptr_array_index(extra_hosts_files, i));
        }
    }

    subnet_name_lookup_init();

    add_manually_resolved();
}

void
host_name_lookup_cleanup(void)
{
    _host_name_lookup_cleanup();

    if(ipxnet_hash_table){
        g_hash_table_destroy(ipxnet_hash_table);
        ipxnet_hash_table = NULL;
    }

    if(ipv4_hash_table){
        g_hash_table_destroy(ipv4_hash_table);
        ipv4_hash_table = NULL;
    }

    if(ipv6_hash_table){
        g_hash_table_destroy(ipv6_hash_table);
        ipv6_hash_table = NULL;
    }

    memset(subnet_length_entries, 0, sizeof(subnet_length_entries));

    have_subnet_entry = FALSE;
    new_resolved_objects = FALSE;
}

static void
free_manually_resolved_ipv4(gpointer data, gpointer user_data _U_)
{
    resolved_ipv4_t *resolved_ipv4_entry = (resolved_ipv4_t *)data;

    g_free(resolved_ipv4_entry);
}

static void
free_manually_resolved_ipv6(gpointer data, gpointer user_data _U_)
{
    resolved_ipv6_t *resolved_ipv6_entry = (resolved_ipv6_t *)data;

    g_free(resolved_ipv6_entry);
}

void
manually_resolve_cleanup(void)
{
    if(manually_resolved_ipv4_list){
        g_slist_foreach(manually_resolved_ipv4_list, free_manually_resolved_ipv4, NULL);
        g_slist_free(manually_resolved_ipv4_list);
        manually_resolved_ipv4_list = NULL;
    }

    if(manually_resolved_ipv6_list){
        g_slist_foreach(manually_resolved_ipv6_list, free_manually_resolved_ipv6, NULL);
        g_slist_free(manually_resolved_ipv6_list);
        manually_resolved_ipv6_list = NULL;
    }

}

gchar *
ep_udp_port_to_display(guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return ep_utoa(port);
    }

    return serv_name_lookup(port, PT_UDP);

} /* ep_udp_port_to_display */

gchar *
ep_dccp_port_to_display(guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return ep_utoa(port);
    }

    return serv_name_lookup(port, PT_DCCP);

} /* ep_dccp_port_to_display */

gchar *
ep_tcp_port_to_display(guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return ep_utoa(port);
    }

    return serv_name_lookup(port, PT_TCP);

} /* ep_tcp_port_to_display */

gchar *
ep_sctp_port_to_display(guint port)
{

    if (!gbl_resolv_flags.transport_name) {
        return ep_utoa(port);
    }

    return serv_name_lookup(port, PT_SCTP);

} /* ep_sctp_port_to_display */

const gchar *
ep_address_to_display(const address *addr)
{
    const gchar *result;

    result = solve_address_to_name(addr);

    if (result != NULL)
        return result;

    /* if it gets here, either it is of type AT_NONE, */
    /* or it should be solvable in address_to_str -unless addr->type is wrongly defined */

    if (addr->type == AT_NONE){
        return "NONE";
    }

    /* We need an ephemeral allocated string */
    return ep_address_to_str(addr);
}

const gchar *
get_addr_name(const address *addr)
{
    guint32 ip4_addr;
    struct e_in6_addr ip6_addr;

    /*
     * Try to look up a name for this address.
     * If it's not found, this might return a string corresponding to
     * the address, or it might return NULL.
     *
     * Whatever string is returned has at least session scope.
     */
    switch (addr->type) {

    case AT_ETHER:
        return get_ether_name((const guint8 *)addr->data);

    case AT_IPv4:
        memcpy(&ip4_addr, addr->data, sizeof ip4_addr);
        return get_hostname(ip4_addr);

    case AT_IPv6:
        memcpy(&ip6_addr.bytes, addr->data, sizeof ip6_addr.bytes);
        return get_hostname6(&ip6_addr);

    default:
        return NULL;
    }
}

void
get_addr_name_buf(const address *addr, gchar *buf, gsize size)
{
    const gchar *result = ep_address_to_display(addr);

    g_strlcpy(buf, result, size);
} /* get_addr_name_buf */


gchar *
get_ether_name(const guint8 *addr)
{
    hashether_t *tp;
    gboolean resolve = gbl_resolv_flags.mac_name;

    tp = eth_name_lookup(addr, resolve);

    return resolve ? tp->resolved_name : tp->hexaddr;

} /* get_ether_name */

/* Look for a (non-dummy) ether name in the hash, and return it if found.
 * If it's not found, simply return NULL.
 */
gchar *
get_ether_name_if_known(const guint8 *addr)
{
    hashether_t *tp;

    /* Initialize ether structs if we're the first
     * ether-related function called */
    if (!gbl_resolv_flags.mac_name)
        return NULL;

    /* eth_name_lookup will create a (resolved) hash entry if it doesn't exist */
    tp = eth_name_lookup(addr, TRUE);
    g_assert(tp != NULL);

    if (tp->status == HASHETHER_STATUS_RESOLVED_NAME) {
        /* Name is from an ethers file (or is a "well-known" MAC address name from the manuf file) */
        return tp->resolved_name;
    }
    else {
        /* Name was created */
        return NULL;
    }
}

guint8 *
get_ether_addr(const gchar *name)
{

    /* force resolution (do not check gbl_resolv_flags) */
    return eth_addr_lookup(name);

} /* get_ether_addr */

void
add_ether_byip(const guint ip, const guint8 *eth)
{
    gboolean found;
    hashipv4_t *tp;

    /* first check that IP address can be resolved */
    if (!gbl_resolv_flags.network_name)
        return;

    tp = host_lookup(ip, &found);
    if (found) {
        /* ok, we can add this entry in the ethers hashtable */
        add_eth_name(eth, tp->name);
    }

} /* add_ether_byip */

const gchar *
get_ipxnet_name(const guint32 addr)
{

    if (!gbl_resolv_flags.network_name) {
        return ipxnet_to_str_punct(addr, '\0');
    }

    return ipxnet_name_lookup(addr);

} /* get_ipxnet_name */

guint32
get_ipxnet_addr(const gchar *name, gboolean *known)
{
    guint32 addr;
    gboolean success;

    /* force resolution (do not check gbl_resolv_flags) */
    addr =  ipxnet_addr_lookup(name, &success);

    *known = success;
    return addr;

} /* get_ipxnet_addr */

const gchar *
get_manuf_name(const guint8 *addr)
{
    gchar *cur;
    int manuf_key;
    guint8 oct;

    /* manuf needs only the 3 most significant octets of the ethernet address */
    manuf_key = addr[0];
    manuf_key = manuf_key<<8;
    oct = addr[1];
    manuf_key = manuf_key | oct;
    manuf_key = manuf_key<<8;
    oct = addr[2];
    manuf_key = manuf_key | oct;

    if (!gbl_resolv_flags.mac_name || ((cur = (gchar *)g_hash_table_lookup(manuf_hashtable, &manuf_key)) == NULL)) {
        cur=ep_strdup_printf("%02x:%02x:%02x", addr[0], addr[1], addr[2]);
        return cur;
    }

    return cur;

} /* get_manuf_name */

const gchar *
uint_get_manuf_name(const guint oid)
{
    guint8 addr[3];

    addr[0] = (oid >> 16) & 0xFF;
    addr[1] = (oid >> 8) & 0xFF;
    addr[2] = (oid >> 0) & 0xFF;
    return get_manuf_name(addr);
}

const gchar *
tvb_get_manuf_name(tvbuff_t *tvb, gint offset)
{
    return get_manuf_name(tvb_get_ptr(tvb, offset, 3));
}

const gchar *
get_manuf_name_if_known(const guint8 *addr)
{
    gchar  *cur;
    int manuf_key;
    guint8 oct;

    /* manuf needs only the 3 most significant octets of the ethernet address */
    manuf_key = addr[0];
    manuf_key = manuf_key<<8;
    oct = addr[1];
    manuf_key = manuf_key | oct;
    manuf_key = manuf_key<<8;
    oct = addr[2];
    manuf_key = manuf_key | oct;

    if ((cur = (gchar *)g_hash_table_lookup(manuf_hashtable, &manuf_key)) == NULL) {
        return NULL;
    }

    return cur;

} /* get_manuf_name_if_known */

const gchar *
uint_get_manuf_name_if_known(const guint manuf_key)
{
    gchar  *cur;

    if ((cur = (gchar *)g_hash_table_lookup(manuf_hashtable, &manuf_key)) == NULL) {
        return NULL;
    }

    return cur;
}

const gchar *
tvb_get_manuf_name_if_known(tvbuff_t *tvb, gint offset)
{
    return get_manuf_name_if_known(tvb_get_ptr(tvb, offset, 3));
}

const gchar *
ep_eui64_to_display(const guint64 addr_eui64)
{
    gchar *cur, *name;
    guint8 *addr = (guint8 *)ep_alloc(8);

    /* Copy and convert the address to network byte order. */
    *(guint64 *)(void *)(addr) = pntoh64(&(addr_eui64));

    if (!gbl_resolv_flags.mac_name || ((name = manuf_name_lookup(addr)) == NULL)) {
        cur=ep_strdup_printf("%02x:%02x:%02x%02x:%02x:%02x%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
        return cur;
    }
    cur=ep_strdup_printf("%s_%02x:%02x:%02x:%02x:%02x", name, addr[3], addr[4], addr[5], addr[6], addr[7]);
    return cur;

} /* ep_eui64_to_display */


const gchar *
ep_eui64_to_display_if_known(const guint64 addr_eui64)
{
    gchar *cur, *name;
    guint8 *addr = (guint8 *)ep_alloc(8);

    /* Copy and convert the address to network byte order. */
    *(guint64 *)(void *)(addr) = pntoh64(&(addr_eui64));

    if ((name = manuf_name_lookup(addr)) == NULL) {
        return NULL;
    }

    cur=ep_strdup_printf("%s_%02x:%02x:%02x:%02x:%02x", name, addr[3], addr[4], addr[5], addr[6], addr[7]);
    return cur;

} /* ep_eui64_to_display_if_known */

#ifdef HAVE_C_ARES
#define GHI_TIMEOUT (250 * 1000)
static void
c_ares_ghi_cb(
        void *arg,
        int status,
#if ( ( ARES_VERSION_MAJOR < 1 )                                     \
    || ( 1 == ARES_VERSION_MAJOR && ARES_VERSION_MINOR < 5 ) )
        struct hostent *hp
#else
        int timeouts _U_,
        struct hostent *hp
#endif
        ) {

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
#endif /* HAVE_C_ARES */

/* Translate a string, assumed either to be a dotted-quad IP address or
 * a host name, to a numeric IP address.  Return TRUE if we succeed and
 * set "*addrp" to that numeric IP address; return FALSE if we fail.
 * Used more in the dfilter parser rather than in packet dissectors */
gboolean
get_host_ipaddr(const char *host, guint32 *addrp)
{
    struct in_addr      ipaddr;
#ifdef HAVE_C_ARES
    struct timeval tv = { 0, GHI_TIMEOUT }, *tvp;
    int nfds;
    fd_set rfds, wfds;
    async_hostent_t ahe;
#else /* HAVE_C_ARES */
    struct hostent      *hp;
#endif /* HAVE_C_ARES */

    /*
     * don't change it to inet_pton(AF_INET), they are not 100% compatible.
     * inet_pton(AF_INET) does not support hexadecimal notation nor
     * less-than-4 octet notation.
     */
    if (!inet_aton(host, &ipaddr)) {

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

#ifdef HAVE_C_ARES
        if (! (gbl_resolv_flags.concurrent_dns) ||
                name_resolve_concurrency < 1 ||
                ! async_dns_initialized) {
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
                fprintf(stderr, "Warning: call to select() failed, error is %s\n", strerror(errno));
                return FALSE;
            }
            ares_process(ghbn_chan, &rfds, &wfds);
        }
        ares_cancel(ghbn_chan);
        if (ahe.addr_size == ahe.copied) {
            return TRUE;
        }
        return FALSE;
#else /* ! HAVE_C_ARES */
        hp = gethostbyname(host);
        if (hp == NULL) {
            /* No. */
            return FALSE;
            /* Apparently, some versions of gethostbyaddr can
             * return IPv6 addresses. */
        } else if (hp->h_length <= (int) sizeof (struct in_addr)) {
            memcpy(&ipaddr, hp->h_addr, hp->h_length);
        } else {
            return FALSE;
        }
#endif /* HAVE_C_ARES */
    } else {
        /* Does the string really contain dotted-quad IP?
         * Check against inet_atons that accept strings such as
         * "130.230" as valid addresses and try to convert them
         * to some form of a classful (host.net) notation.
         */
        unsigned int a0, a1, a2, a3;
        if (sscanf(host, "%u.%u.%u.%u", &a0, &a1, &a2, &a3) != 4)
            return FALSE;
    }

    *addrp = ipaddr.s_addr;
    return TRUE;
}

/*
 * Translate IPv6 numeric address or FQDN hostname, into binary IPv6 address.
 * Return TRUE if we succeed and set "*addrp" to that numeric IP address;
 * return FALSE if we fail.
 */
gboolean
get_host_ipaddr6(const char *host, struct e_in6_addr *addrp)
{
#ifdef HAVE_C_ARES
    struct timeval tv = { 0, GHI_TIMEOUT }, *tvp;
    int nfds;
    fd_set rfds, wfds;
    async_hostent_t ahe;
#elif defined(HAVE_GETHOSTBYNAME2)
    struct hostent *hp;
#endif /* HAVE_C_ARES */

    if (str_to_ip6(host, addrp))
        return TRUE;

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

    /* try FQDN */
#ifdef HAVE_C_ARES
    if (! (gbl_resolv_flags.concurrent_dns) ||
            name_resolve_concurrency < 1 ||
            ! async_dns_initialized) {
        return FALSE;
    }
    ahe.addr_size = (int) sizeof (struct e_in6_addr);
    ahe.copied = 0;
    ahe.addrp = addrp;
    ares_gethostbyname(ghbn_chan, host, AF_INET6, c_ares_ghi_cb, &ahe);
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    nfds = ares_fds(ghbn_chan, &rfds, &wfds);
    if (nfds > 0) {
        tvp = ares_timeout(ghbn_chan, &tv, &tv);
        if (select(nfds, &rfds, &wfds, NULL, tvp) == -1) { /* call to select() failed */
            fprintf(stderr, "Warning: call to select() failed, error is %s\n", strerror(errno));
            return FALSE;
        }
        ares_process(ghbn_chan, &rfds, &wfds);
    }
    ares_cancel(ghbn_chan);
    if (ahe.addr_size == ahe.copied) {
        return TRUE;
    }
#elif defined(HAVE_GETHOSTBYNAME2)
    hp = gethostbyname2(host, AF_INET6);
    if (hp != NULL && hp->h_length == sizeof(struct e_in6_addr)) {
        memcpy(addrp, hp->h_addr, hp->h_length);
        return TRUE;
    }
#endif

    return FALSE;
}

/*
 * Find out whether a hostname resolves to an ip or ipv6 address
 * Return "ip6" if it is IPv6, "ip" otherwise (including the case
 * that we don't know)
 */
const char* host_ip_af(const char *host
#ifndef HAVE_GETHOSTBYNAME2
        _U_
#endif
        )
{
#ifdef HAVE_GETHOSTBYNAME2
    struct hostent *h;
    return (h = gethostbyname2(host, AF_INET6)) && h->h_addrtype == AF_INET6 ? "ip6" : "ip";
#else
    return "ip";
#endif
}

GHashTable *
get_manuf_hashtable(void)
{
    return manuf_hashtable;
}

GHashTable *
get_wka_hashtable(void)
{
    return wka_hashtable;
}

GHashTable *
get_eth_hashtable(void)
{
    return eth_hashtable;
}

GHashTable *
get_serv_port_hashtable(void)
{
    return serv_port_hashtable;
}

GHashTable *
get_ipxnet_hash_table(void)
{
        return ipxnet_hash_table;
}

GHashTable *
get_ipv4_hash_table(void)
{
        return ipv4_hash_table;
}

GHashTable *
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
    /* host name initialization is done on a per-capture-file basis */
    /*host_name_lookup_init();*/
}

/* Clean up all the address resolution subsystems in this file */
void
addr_resolv_cleanup(void)
{
    service_name_lookup_cleanup();
    eth_name_lookup_cleanup();
    ipx_name_lookup_cleanup();
    /* host name initialization is done on a per-capture-file basis */
    /*host_name_lookup_cleanup();*/
}

gboolean
str_to_ip(const char *str, void *dst)
{
    return inet_pton(AF_INET, str, dst) > 0;
}

gboolean
str_to_ip6(const char *str, void *dst)
{
    return inet_pton(AF_INET6, str, dst) > 0;
}

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
