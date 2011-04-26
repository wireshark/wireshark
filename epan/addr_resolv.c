/* addr_resolv.c
 * Routines for network object lookup
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

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

#ifdef NEED_INET_ATON_H
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

#include "report_err.h"
#include "packet.h"
#include "ipv6-utils.h"
#include "addr_resolv.h"
#include "filesystem.h"

#include <epan/strutil.h>
#include <wsutil/file_util.h>
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
#define HASHMANUFSIZE     256
#define HASHPORTSIZE      256
#define SUBNETLENGTHSIZE   32  /*1-32 inc.*/

/* hash table used for IPv4 lookup */

#define HASH_IPV4_ADDRESS(addr) (g_htonl(addr) & (HASHHOSTSIZE - 1))

/*
 * XXX Some of this is duplicated in addrinfo_list. We may want to replace the
 * addr and name parts with a struct addrinfo or create our own addrinfo-like
 * struct that simply points to the data below.
 */
typedef struct hashipv4 {
  guint             addr;
  gboolean          is_dummy_entry; /* name is IPv4 address in dot format */
  gboolean          resolve;        /* already tried to resolve it */
  struct hashipv4   *next;
  gchar             ip[16];
  gchar             name[MAXNAMELEN];
} hashipv4_t;

/* hash table used for IPv6 lookup */

#define HASH_IPV6_ADDRESS(addr) \
    ((((addr).bytes[14] << 8)|((addr).bytes[15])) & (HASHHOSTSIZE - 1))

typedef struct hashipv6 {
  struct e_in6_addr addr;
  gboolean          is_dummy_entry; /* name is IPv6 address in colon format */
  gboolean          resolve;        /* */
  struct hashipv6   *next;
  gchar             ip6[47];        /* XX */
  gchar             name[MAXNAMELEN];
} hashipv6_t;

/* Array of entries of subnets of different lengths */
typedef struct {
  gsize        mask_length;      /*1-32*/
  guint32      mask;             /* e.g. 255.255.255.*/
  hashipv4_t** subnet_addresses; /* Hash table of subnet addresses */
} subnet_length_entry_t;

/* hash table used for TCP/UDP/SCTP port lookup */

#define HASH_PORT(port) ((port) & (HASHPORTSIZE - 1))

typedef struct hashport {
  guint16          port;
  struct hashport *next;
  gchar            name[MAXNAMELEN];
} hashport_t;

/* hash table used for IPX network lookup */

/* XXX - check goodness of hash function */

#define HASH_IPX_NET(net)   ((net) & (HASHIPXNETSIZE - 1))

typedef struct hashipxnet {
  guint               addr;
  struct hashipxnet  *next;
  gchar               name[MAXNAMELEN];
} hashipxnet_t;

/* hash tables used for ethernet and manufacturer lookup */

#define HASH_ETH_ADDRESS(addr) \
    (((((addr)[2] << 8) | (addr)[3]) ^ (((addr)[4] << 8) | (addr)[5])) & \
     (HASHETHSIZE - 1))

#define HASH_ETH_MANUF(addr) (((int)(addr)[2]) & (HASHMANUFSIZE - 1))

typedef struct hashmanuf {
  struct hashmanuf *next;
  guint8            addr[3];
  char              *name;
} hashmanuf_t;

#define HASHETHER_STATUS_UNRESOLVED     1
#define HASHETHER_STATUS_RESOLVED_DUMMY 2
#define HASHETHER_STATUS_RESOLVED_NAME  3

typedef struct hashether {
  struct hashether *next;
  guint             status;  /* (See above) */
  guint8            addr[6];
  char              hexaddr[6*3];
  char              resolved_name[MAXNAMELEN];
} hashether_t;

typedef struct hashwka {
  struct hashwka   *next;
  guint8            addr[6];
  char              name[MAXNAMELEN];
} hashwka_t;

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

static hashipv4_t   *ipv4_table[HASHHOSTSIZE];
static hashipv6_t   *ipv6_table[HASHHOSTSIZE];

static hashport_t   **cb_port_table;
static gchar        *cb_service;

static hashport_t   *udp_port_table[HASHPORTSIZE];
static hashport_t   *tcp_port_table[HASHPORTSIZE];
static hashport_t   *sctp_port_table[HASHPORTSIZE];
static hashport_t   *dccp_port_table[HASHPORTSIZE];
static hashether_t  *eth_table[HASHETHSIZE];
static hashmanuf_t  *manuf_table[HASHMANUFSIZE];
static hashwka_t    *(*wka_table[48])[HASHETHSIZE];
static hashipxnet_t *ipxnet_table[HASHIPXNETSIZE];

static subnet_length_entry_t subnet_length_entries[SUBNETLENGTHSIZE]; /* Ordered array of entries */
static gboolean have_subnet_entry = FALSE;

static gboolean eth_resolution_initialized = FALSE;
static int      ipxnet_resolution_initialized = 0;
static int      service_resolution_initialized = 0;
static gboolean new_resolved_objects = FALSE;

static struct addrinfo *addrinfo_list = NULL; /* IPv4 and IPv6 */
static struct addrinfo *addrinfo_list_last = NULL;

static hashether_t *add_eth_name(const guint8 *addr, const gchar *name);
static void add_serv_port_cb(const guint32 port);

/*
 * Flag controlling what names to resolve.
 */
guint32 gbl_resolv_flags;

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
static  int       async_dns_in_flight = 0;
static  GList    *async_dns_queue_head = NULL;

/* push a dns request */
static void
add_async_dns_ipv4(int type, guint32 addr)
{
  async_dns_queue_msg_t *msg;

  msg = g_malloc(sizeof(async_dns_queue_msg_t));
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

    *buf = g_malloc(*size);
  }

  g_assert(*buf);
  g_assert(*size > 0);

  if (feof(fp))
    return -1;

  len = 0;
  while ((c = getc(fp)) != EOF && c != '\r' && c != '\n') {
    if (len+1 >= *size) {
       *buf = g_realloc(*buf, *size += BUFSIZ);
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
add_service_name(hashport_t **proto_table, const guint port, const char *service_name)
{
  int hash_idx;
  hashport_t *tp;


  hash_idx = HASH_PORT(port);
  tp = proto_table[hash_idx];

  if( tp == NULL ) {
    tp = proto_table[hash_idx] = (hashport_t *)g_malloc(sizeof(hashport_t));
  } else {
    while(1) {
      if( tp->port == port ) {
        return;
      }
      if (tp->next == NULL) {
        tp->next = (hashport_t *)g_malloc(sizeof(hashport_t));
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }

  /* fill in a new entry */
  tp->port = port;
  tp->next = NULL;

  g_strlcpy(tp->name, service_name, MAXNAMELEN);

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
    cb_port_table = tcp_port_table;
  }
  else if(strcmp(cp, "udp") == 0) {
    max_port = MAX_UDP_PORT;
    cb_port_table = udp_port_table;
  }
  else if(strcmp(cp, "sctp") == 0) {
    max_port = MAX_SCTP_PORT;
    cb_port_table = sctp_port_table;
  }
  else if(strcmp(cp, "dccp") == 0) {
    max_port = MAX_DCCP_PORT;
    cb_port_table = dccp_port_table;
  } else {
    return;
  }

  if(CVT_NO_ERROR != range_convert_str(&port_rng, port, max_port) ) {
    /* some assertion here? */
    return;
  }

  cb_service = service;
  range_foreach(port_rng, add_serv_port_cb);
  g_free (port_rng);
} /* parse_service_line */


static void
add_serv_port_cb(const guint32 port)
{
  if ( port ) {
    add_service_name(cb_port_table, port, cb_service);
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

static void
initialize_services(void)
{

  /* the hash table won't ignore duplicates, so use the personal path first */

  /* set personal services path */
  if (g_pservices_path == NULL)
    g_pservices_path = get_persconffile_path(ENAME_SERVICES, FALSE, FALSE);

  parse_services_file(g_pservices_path);

  /* Compute the pathname of the services file. */
  if (g_services_path == NULL) {
    g_services_path = get_datafile_path(ENAME_SERVICES);
  }

  parse_services_file(g_services_path);

} /* initialize_services */



static gchar
*serv_name_lookup(const guint port, const port_type proto)
{
  int hash_idx;
  hashport_t *tp;
  hashport_t **table;
  const char *serv_proto = NULL;
  struct servent *servp;


  if (!service_resolution_initialized) {
    initialize_services();
    service_resolution_initialized = 1;
  }

  switch(proto) {
  case PT_UDP:
    table = udp_port_table;
    serv_proto = "udp";
    break;
  case PT_TCP:
    table = tcp_port_table;
    serv_proto = "tcp";
    break;
  case PT_SCTP:
    table = sctp_port_table;
    serv_proto = "sctp";
    break;
  case PT_DCCP:
    table = dccp_port_table;
    serv_proto = "dcp";
    break;
  default:
    /* not yet implemented */
    return NULL;
    /*NOTREACHED*/
  } /* proto */

  hash_idx = HASH_PORT(port);
  tp = table[hash_idx];

  if( tp == NULL ) {
    tp = table[hash_idx] = (hashport_t *)g_malloc(sizeof(hashport_t));
  } else {
    while(1) {
      if( tp->port == port ) {
        return tp->name;
      }
      if (tp->next == NULL) {
        tp->next = (hashport_t *)g_malloc(sizeof(hashport_t));
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }

  /* fill in a new entry */
  tp->port = port;
  tp->next = NULL;

  if (!(gbl_resolv_flags & RESOLV_TRANSPORT) ||
      (servp = getservbyport(g_htons(port), serv_proto)) == NULL) {
    /* unknown port */
    guint32_to_str_buf(port, tp->name, MAXNAMELEN);
  } else {
    g_strlcpy(tp->name, servp->s_name, MAXNAMELEN);
  }

  return (tp->name);

} /* serv_name_lookup */


/* Fill in an IP4 structure with info from subnets file or just with the
 * string form of the address.
 */
static void
fill_dummy_ip4(const guint addr, hashipv4_t* volatile tp)
{
  subnet_entry_t subnet_entry;

  if (tp->is_dummy_entry)
      return; /* already done */

  tp->is_dummy_entry = TRUE; /* Overwrite if we get async DNS reply */

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
    ip_to_str_buf((guint8 *)&addr, tp->name, MAXNAMELEN);
  }
}

#ifdef HAVE_C_ARES

static void
#if ( ( ARES_VERSION_MAJOR < 1 )                                     \
 || ( 1 == ARES_VERSION_MAJOR && ARES_VERSION_MINOR < 5 ) )
c_ares_ghba_cb(void *arg, int status, struct hostent *he) {
#else
c_ares_ghba_cb(void *arg, int status, int timeouts _U_, struct hostent *he) {
#endif
  async_dns_queue_msg_t *caqm = arg;
  char **p;

  if (!caqm) return;
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
  hashipv4_t *tp = g_malloc(sizeof(hashipv4_t));
  tp->addr = addr;
  tp->next = NULL;
  tp->resolve = FALSE;
  tp->is_dummy_entry = FALSE;
  ip_to_str_buf((guint8 *)&addr, tp->ip, sizeof(tp->ip));
  return tp;
}

static hashipv4_t *
host_lookup(const guint addr, const gboolean resolve, gboolean *found)
{
  int hash_idx;
  hashipv4_t * volatile tp;
  struct hostent *hostp;

  *found = TRUE;

  hash_idx = HASH_IPV4_ADDRESS(addr);

  tp = ipv4_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv4_table[hash_idx] = new_ipv4(addr);
  } else {
    while(1) {
      if( tp->addr == addr ) {
        if (tp->is_dummy_entry && !tp->resolve)
          break;
        if (tp->is_dummy_entry)
          *found = FALSE;
        return tp;
      }
      if (tp->next == NULL) {
        tp->next = new_ipv4(addr);
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }

  if (resolve) {
    tp->resolve = TRUE;
#ifdef ASYNC_DNS
    if ((gbl_resolv_flags & RESOLV_CONCURRENT) &&
        prefs.name_resolve_concurrency > 0 &&
        async_dns_initialized) {
        add_async_dns_ipv4(AF_INET, addr);
      /* XXX found is set to TRUE, which seems a bit odd, but I'm not
       * going to risk changing the semantics.
       */
      fill_dummy_ip4(addr, tp);
      return tp;
    }
#endif /* ASYNC_DNS */

    /*
     * The Windows "gethostbyaddr()" insists on translating 0.0.0.0 to
     * the name of the host on which it's running; to work around that
     * botch, we don't try to translate an all-zero IP address to a host
     * name.
     */
    if (addr != 0 && (gbl_resolv_flags & RESOLV_NETWORK)) {
      /* Use async DNS if possible, else fall back to timeouts,
       * else call gethostbyaddr and hope for the best
       */

      hostp = gethostbyaddr((char *)&addr, 4, AF_INET);

      if (hostp != NULL) {
        g_strlcpy(tp->name, hostp->h_name, MAXNAMELEN);
        tp->is_dummy_entry = FALSE;
        return tp;
      }
    }

    /* unknown host or DNS timeout */

  }

  *found = FALSE;

  fill_dummy_ip4(addr, tp);
  return tp;

} /* host_name_lookup */

static gchar *
host_name_lookup(const guint addr, gboolean *found)
{
  hashipv4_t *tp;
  tp = host_lookup(addr, TRUE, found);
  return tp->name;
}


/* --------------- */
static hashipv6_t *
new_ipv6(const struct e_in6_addr *addr)
{
  hashipv6_t *tp = g_malloc(sizeof(hashipv6_t));
  tp->addr = *addr;
  tp->next = NULL;
  tp->resolve = FALSE;
  tp->is_dummy_entry = FALSE;
  ip6_to_str_buf(addr, tp->ip6);
  return tp;
}

/* ------------------------------------ */
static hashipv6_t *
host_lookup6(const struct e_in6_addr *addr, const gboolean resolve, gboolean *found)
{
  int hash_idx;
  hashipv6_t * volatile tp;
#ifdef INET6
#ifdef HAVE_C_ARES
  async_dns_queue_msg_t *caqm;
#endif /* HAVE_C_ARES */
  struct hostent *hostp;
#endif /* INET6 */

  *found = TRUE;

  hash_idx = HASH_IPV6_ADDRESS(*addr);

  tp = ipv6_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv6_table[hash_idx] = new_ipv6(addr);
  } else {
    while(1) {
      if( memcmp(&tp->addr, addr, sizeof (struct e_in6_addr)) == 0 ) {
        if (tp->is_dummy_entry && !tp->resolve)
          break;
        if (tp->is_dummy_entry)
          *found = FALSE;
        return tp;
      }
      if (tp->next == NULL) {
        tp->next = new_ipv6(addr);
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }

  if (resolve) {
    tp->resolve = TRUE;
#ifdef INET6

#ifdef HAVE_C_ARES
  if ((gbl_resolv_flags & RESOLV_CONCURRENT) &&
      prefs.name_resolve_concurrency > 0 &&
      async_dns_initialized) {
    caqm = g_malloc(sizeof(async_dns_queue_msg_t));
    caqm->family = AF_INET6;
    memcpy(&caqm->addr.ip6, addr, sizeof(caqm->addr.ip6));
    async_dns_queue_head = g_list_append(async_dns_queue_head, (gpointer) caqm);

    /* XXX found is set to TRUE, which seems a bit odd, but I'm not
     * going to risk changing the semantics.
     */
    if (!tp->is_dummy_entry) {
      g_strlcpy(tp->name, tp->ip6, MAXNAMELEN);
      ip6_to_str_buf(addr, tp->name);
      tp->is_dummy_entry = TRUE;
    }
    return tp;
  }
#endif /* HAVE_C_ARES */

  /* Quick hack to avoid DNS/YP timeout */
  hostp = gethostbyaddr((char *)addr, sizeof(*addr), AF_INET6);

  if (hostp != NULL) {
    g_strlcpy(tp->name, hostp->h_name, MAXNAMELEN);
    tp->is_dummy_entry = FALSE;
    return tp;
  }
#endif /* INET6 */
  }

  /* unknown host or DNS timeout */
  if (!tp->is_dummy_entry) {
    tp->is_dummy_entry = TRUE;
    g_strlcpy(tp->name, tp->ip6, MAXNAMELEN);
  }
  *found = FALSE;
  return tp;

} /* host_lookup6 */

#if 0
static gchar *
host_name_lookup6(struct e_in6_addr *addr, gboolean *found)
{
  hashipv6_t *tp;
  tp = host_lookup6(addr, TRUE, found);
  return tp->name;
}
#endif

static const gchar *
solve_address_to_name(const address *addr)
{
  switch (addr->type) {

  case AT_ETHER:
    return get_ether_name(addr->data);

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
    return addr->data;

  default:
    return NULL;
  }
}

static const gchar *
se_solve_address_to_name(const address *addr)
{
  switch (addr->type) {

  case AT_ETHER:
    return get_ether_name(addr->data);

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
    return se_strdup(addr->data);

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
      *mask = num;
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

static int
hash_eth_wka(const guint8 *addr, unsigned int mask)
{
  if (mask <= 8) {
    /* All but the topmost byte is masked out */
    return (addr[0] & (0xFF << (8 - mask))) & (HASHETHSIZE - 1);
  }
  mask -= 8;
  if (mask <= 8) {
    /* All but the topmost 2 bytes are masked out */
    return ((addr[0] << 8) | (addr[1] & (0xFF << (8 - mask)))) &
            (HASHETHSIZE - 1);
  }
  mask -= 8;
  if (mask <= 8) {
    /* All but the topmost 3 bytes are masked out */
    return ((addr[0] << 16) | (addr[1] << 8) | (addr[2] & (0xFF << (8 - mask))))
     & (HASHETHSIZE - 1);
  }
  mask -= 8;
  if (mask <= 8) {
    /* All but the topmost 4 bytes are masked out */
    return ((((addr[0] << 8) | addr[1]) ^
             ((addr[2] << 8) | (addr[3] & (0xFF << (8 - mask)))))) &
            (HASHETHSIZE - 1);
  }
  mask -= 8;
  if (mask <= 8) {
    /* All but the topmost 5 bytes are masked out */
    return ((((addr[1] << 8) | addr[2]) ^
             ((addr[3] << 8) | (addr[4] & (0xFF << (8 - mask)))))) &
            (HASHETHSIZE - 1);
  }
  mask -= 8;
  /* No bytes are fully masked out */
  return ((((addr[1] << 8) | addr[2]) ^
           ((addr[3] << 8) | (addr[4] & (0xFF << (8 - mask)))))) &
          (HASHETHSIZE - 1);
}

static hashmanuf_t *
manuf_hash_new_entry(const guint8 *addr, gchar *name)
{
  hashmanuf_t *mtp;

  mtp = (hashmanuf_t *)g_malloc(sizeof(hashmanuf_t));
  memcpy(mtp->addr, addr, sizeof(mtp->addr));
  /*  The length of this name is limited (in the number of UTF-8 characters,
   *  not bytes) in make-manuf.  That doesn't mean a user can't put a longer
   *  name in their personal manuf file, though...
   */
  mtp->name = g_strdup(name);
  mtp->next = NULL;
  return mtp;
} /* manuf_hash_new_entry */

static hashwka_t *
wka_hash_new_entry(const guint8 *addr, gchar *name)
{
  hashwka_t *wtp;

  wtp =  (hashwka_t *)g_malloc(sizeof(hashwka_t));
  memcpy(wtp->addr, addr, sizeof(wtp->addr));
  g_strlcpy(wtp->name, name, MAXNAMELEN);
  wtp->next = NULL;
  return wtp;
} /* wka_hash_new_entry */

static void
add_manuf_name(const guint8 *addr, unsigned int mask, gchar *name)
{
  gint         hash_idx;
  hashmanuf_t *mtp;
  hashwka_t   *(*wka_tp)[HASHETHSIZE], *wtp;

  /*
   * XXX - can we use Standard Annotation Language annotations to
   * note that mask, as returned by parse_ether_address() (and thus
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

    hash_idx = HASH_ETH_MANUF(addr);
    mtp = manuf_table[hash_idx];

    if( mtp == NULL ) {
      manuf_table[hash_idx] = manuf_hash_new_entry(addr, name);
      return;
    } else {
      while(TRUE) {
        if (mtp->next == NULL) {
          mtp->next = manuf_hash_new_entry(addr, name);
          return;
        }
        mtp = mtp->next;
      }
    }
  } /* mask == 0 */

  /* This is a range of well-known addresses; add it to the appropriate
     well-known-address table, creating that table if necessary. */
  wka_tp = wka_table[mask];
  if (wka_tp == NULL)
    wka_tp = wka_table[mask] = g_malloc0(sizeof *wka_table[mask]);

  hash_idx = hash_eth_wka(addr, mask);

  wtp = (*wka_tp)[hash_idx];

  if( wtp == NULL ) {
    (*wka_tp)[hash_idx] = wka_hash_new_entry(addr, name);
    return;
  } else {
    while(TRUE) {
      if (memcmp(wtp->addr, addr, sizeof(wtp->addr)) == 0) {
        /* address already known */
        return;
      }
      if (wtp->next == NULL) {
	wtp->next = wka_hash_new_entry(addr, name);
        return;
      }
      wtp = wtp->next;
    }
  }
} /* add_manuf_name */

static hashmanuf_t *
manuf_name_lookup(const guint8 *addr)
{
  gint         hash_idx;
  hashmanuf_t *mtp;
  guint8       stripped_addr[3];

  hash_idx = HASH_ETH_MANUF(addr);

  /* first try to find a "perfect match" */
  mtp = manuf_table[hash_idx];
  while(mtp != NULL) {
    if (memcmp(mtp->addr, addr, sizeof(mtp->addr)) == 0) {
      return mtp;
    }
    mtp = mtp->next;
  }

  /* Mask out the broadcast/multicast flag but not the locally
   * administered flag as localy administered means: not assigend
   * by the IEEE but the local administrator instead.
   * 0x01 multicast / broadcast bit
   * 0x02 locally administered bit */
  memcpy(stripped_addr, addr, 3);
  stripped_addr[0] &= 0xFE;

  mtp = manuf_table[hash_idx];
  while(mtp != NULL) {
    if (memcmp(mtp->addr, stripped_addr, sizeof(mtp->addr)) == 0) {
      return mtp;
    }
    mtp = mtp->next;
  }

  return NULL;

} /* manuf_name_lookup */

static hashwka_t *
wka_name_lookup(const guint8 *addr, const unsigned int mask)
{
  gint       hash_idx;
  hashwka_t *(*wka_tp)[HASHETHSIZE];
  hashwka_t *wtp;
  guint8     masked_addr[6];
  guint      num;
  gint       i;

  wka_tp = wka_table[mask];
  if (wka_tp == NULL) {
    /* There are no entries in the table for that mask value, as there is
       no table for that mask value. */
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

  hash_idx = hash_eth_wka(masked_addr, mask);

  wtp = (*wka_tp)[hash_idx];

  while(wtp != NULL) {
    if (memcmp(wtp->addr, masked_addr, sizeof(wtp->addr)) == 0) {
      return wtp;
    }
    wtp = wtp->next;
  }

  return NULL;

} /* wka_name_lookup */

static void
initialize_ethers(void)
{
  ether_t *eth;
  char    *manuf_path;
  guint    mask;

  /* Compute the pathname of the ethers file. */
  if (g_ethers_path == NULL) {
    g_ethers_path = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s",
                                    get_systemfile_dir(), ENAME_ETHERS);
  }

  /* Set g_pethers_path here, but don't actually do anything
   * with it. It's used in get_ethbyname() and get_ethbyaddr()
   */
  if (g_pethers_path == NULL)
    g_pethers_path = get_persconffile_path(ENAME_ETHERS, FALSE, FALSE);

  /* manuf hash table initialization */

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
    hashwka_t    *wtp;
    hashmanuf_t  *mtp;
    guint         mask;

    /* Unknown name.  Try looking for it in the well-known-address
       tables for well-known address ranges smaller than 2^24. */
    mask = 7;
    for (;;) {
      /* Only the topmost 5 bytes participate fully */
      if ((wtp = wka_name_lookup(addr, mask+40)) != NULL) {
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x",
                   wtp->name, addr[5] & (0xFF >> mask));
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
      if ((wtp = wka_name_lookup(addr, mask+32)) != NULL) {
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x",
                   wtp->name, addr[4] & (0xFF >> mask), addr[5]);
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
      if ((wtp = wka_name_lookup(addr, mask+24)) != NULL) {
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x",
                   wtp->name, addr[3] & (0xFF >> mask), addr[4], addr[5]);
        tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
        return tp;
      }
      if (mask == 0)
        break;
      mask--;
    }

    /* Now try looking in the manufacturer table. */
    if ((mtp = manuf_name_lookup(addr)) != NULL) {
      g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x",
                 mtp->name, addr[3], addr[4], addr[5]);
      tp->status = HASHETHER_STATUS_RESOLVED_DUMMY;
      return tp;
    }

    /* Now try looking for it in the well-known-address
       tables for well-known address ranges larger than 2^24. */
    mask = 7;
    for (;;) {
      /* Only the topmost 2 bytes participate fully */
      if ((wtp = wka_name_lookup(addr, mask+16)) != NULL) {
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x",
                   wtp->name, addr[2] & (0xFF >> mask), addr[3], addr[4],
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
      if ((wtp = wka_name_lookup(addr, mask+8)) != NULL) {
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x",
                   wtp->name, addr[1] & (0xFF >> mask), addr[2], addr[3],
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
      if ((wtp = wka_name_lookup(addr, mask)) != NULL) {
        g_snprintf(tp->resolved_name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x:%02x",
                   wtp->name, addr[0] & (0xFF >> mask), addr[1], addr[2],
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
eth_hash_new_entry(const guint8 *addr, const gboolean resolve) {
  hashether_t *tp;

  tp = (hashether_t *)g_malloc(sizeof(hashether_t));
  memcpy(tp->addr, addr, sizeof(tp->addr));
  tp->status = HASHETHER_STATUS_UNRESOLVED;
  g_strlcpy(tp->hexaddr, bytestring_to_str(addr, sizeof(tp->addr), ':'), sizeof(tp->hexaddr));
  tp->resolved_name[0] = '\0';
  tp->next = NULL;

  if (resolve)
    eth_addr_resolve(tp);

  return tp;
} /* eth_hash_new_entry */

static hashether_t *
add_eth_name(const guint8 *addr, const gchar *name)
{
  gint         hash_idx;
  hashether_t *tp;

  hash_idx = HASH_ETH_ADDRESS(addr);

  tp = eth_table[hash_idx];
  if( tp == NULL ) {
    tp = eth_table[hash_idx] = eth_hash_new_entry(addr, FALSE);
  } else {
    while(TRUE) {
      if (memcmp(tp->addr, addr, sizeof(tp->addr)) == 0) {
        /* address already known */
        if (tp->status == HASHETHER_STATUS_RESOLVED_NAME)
          return tp; /* Entry with a name already in table; ignore attempted replacement */
        break;       /* Update name of existing entry */
        }
      if (tp->next == NULL) {
        tp = tp->next = eth_hash_new_entry(addr, FALSE);
        break;
      }
      tp = tp->next;
    }
  }

  g_strlcpy(tp->resolved_name, name, MAXNAMELEN);
  tp->status = HASHETHER_STATUS_RESOLVED_NAME;
  new_resolved_objects = TRUE;

  return tp;
} /* add_eth_name */

static hashether_t *
eth_name_lookup(const guint8 *addr, const gboolean resolve) {
  gint          hash_idx;
  hashether_t  *tp;

  hash_idx = HASH_ETH_ADDRESS(addr);

  tp = eth_table[hash_idx];
  if( tp == NULL ) {
    tp = eth_table[hash_idx] = eth_hash_new_entry(addr, resolve);
    return tp;
  } else {
    while(TRUE) {
      if (memcmp(tp->addr, addr, sizeof(tp->addr)) == 0) {
        if (resolve && (tp->status == HASHETHER_STATUS_UNRESOLVED))
          eth_addr_resolve(tp); /* Found but needs to be resolved */
        return tp;
      }
      if (tp->next == NULL) {
        tp->next = eth_hash_new_entry(addr, resolve);
        return tp->next;
      }
      tp = tp->next;
    }
  }
} /* eth_name_lookup */

static guint8 *
eth_addr_lookup(const gchar *name)
{
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
    g_pipxnets_path = get_persconffile_path(ENAME_IPXNETS, FALSE, FALSE);

} /* initialize_ipxnets */

static hashipxnet_t *
add_ipxnet_name(guint addr, const gchar *name)
{
  int hash_idx;
  hashipxnet_t *tp;

  hash_idx = HASH_IPX_NET(addr);

  tp = ipxnet_table[hash_idx];

  if( tp == NULL ) {
    tp = ipxnet_table[hash_idx] = (hashipxnet_t *)g_malloc(sizeof(hashipxnet_t));
  } else {
    while(1) {
      if (tp->next == NULL) {
        tp->next = (hashipxnet_t *)g_malloc(sizeof(hashipxnet_t));
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }

  tp->addr = addr;
  g_strlcpy(tp->name, name, MAXNAMELEN);
  tp->next = NULL;
  new_resolved_objects = TRUE;

  return tp;

} /* add_ipxnet_name */

static gchar *
ipxnet_name_lookup(const guint addr)
{
  int hash_idx;
  hashipxnet_t *tp;
  ipxnet_t *ipxnet;

  hash_idx = HASH_IPX_NET(addr);

  tp = ipxnet_table[hash_idx];

  if( tp == NULL ) {
    tp = ipxnet_table[hash_idx] = (hashipxnet_t *)g_malloc(sizeof(hashipxnet_t));
  } else {
    while(1) {
      if (tp->addr == addr) {
        return tp->name;
      }
      if (tp->next == NULL) {
        tp->next = (hashipxnet_t *)g_malloc(sizeof(hashipxnet_t));
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }

  /* fill in a new entry */

  tp->addr = addr;
  tp->next = NULL;

  if ( (ipxnet = get_ipxnetbyaddr(addr)) == NULL) {
    /* unknown name */
    g_snprintf(tp->name, MAXNAMELEN, "%X", addr);

  } else {
    g_strlcpy(tp->name, ipxnet->name, MAXNAMELEN);
  }

  return (tp->name);

} /* ipxnet_name_lookup */

static guint
ipxnet_addr_lookup(const gchar *name, gboolean *success)
{
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

} /* ipxnet_addr_lookup */

gboolean
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
    if (ret == -1)
      continue; /* error parsing */
    if (ret == 1) {
      /* Valid IPv6 */
      is_ipv6 = TRUE;
    } else {
      /* Not valid IPv6 - valid IPv4? */
      if (inet_pton(AF_INET, cp, &host_addr) != 1)
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
add_ip_name_from_string (const char *addr, const char *name)
{
  guint32 host_addr[4]; /* IPv4 */
  struct e_in6_addr ip6_addr; /* IPv6 */
  gboolean is_ipv6;
  int ret;

  ret = inet_pton(AF_INET6, addr, &ip6_addr);
  if (ret == -1)
    /* Error parsing address */
    return FALSE;

  if (ret == 1) {
    /* Valid IPv6 */
    is_ipv6 = TRUE;
  } else {
    /* Not valid IPv6 - valid IPv4? */
    if (inet_pton(AF_INET, addr, &host_addr) != 1)
      return FALSE; /* no */
    is_ipv6 = FALSE;
  }

  if (is_ipv6) {
    add_ipv6_name(&ip6_addr, name);
  } else {
    add_ipv4_name(host_addr[0], name);
  }

  return TRUE;
} /* add_ip_name_from_string */

struct addrinfo *
get_addrinfo_list(void) {
  return addrinfo_list;
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
    if (inet_pton(AF_INET, cp, &host_addr) != 1) {
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
      hashipv4_t * tp;
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
  hashipv4_t * tp;
  gsize hash_idx;

  g_assert(mask_length > 0 && mask_length <= 32);

  entry = &subnet_length_entries[mask_length - 1];

  subnet_addr &= entry->mask;

  hash_idx = HASH_IPV4_ADDRESS(subnet_addr);

  if(NULL == entry->subnet_addresses) {
    entry->subnet_addresses = g_new0(hashipv4_t*,HASHHOSTSIZE);
  }

  if(NULL != (tp = entry->subnet_addresses[hash_idx])) {
    if(tp->addr == subnet_addr) {
      return;    /* XXX provide warning that an address was repeated? */
    } else {
      hashipv4_t * new_tp = g_new(hashipv4_t,1);
      tp->next = new_tp;
      tp = new_tp;
    }
  } else {
    tp = entry->subnet_addresses[hash_idx] = g_new(hashipv4_t,1);
  }

  tp->next = NULL;
  tp->addr = subnet_addr;
  tp->is_dummy_entry = FALSE; /*Never used again...*/
  g_strlcpy(tp->name, name, MAXNAMELEN); /* This is longer than subnet names can actually be */
  have_subnet_entry = TRUE;
}

static guint32
get_subnet_mask(const guint32 mask_length) {

  static guint32 masks[SUBNETLENGTHSIZE];
  static gboolean initialised = FALSE;

  if(!initialised) {
    memset(masks, 0, sizeof(masks));

    initialised = TRUE;

    /* XXX There must be a better way to do this than
     * hand-coding the values, but I can't seem to
     * come up with one!
     */

    inet_pton(AF_INET, "128.0.0.0", &masks[0]);
    inet_pton(AF_INET, "192.0.0.0", &masks[1]);
    inet_pton(AF_INET, "224.0.0.0", &masks[2]);
    inet_pton(AF_INET, "240.0.0.0", &masks[3]);
    inet_pton(AF_INET, "248.0.0.0", &masks[4]);
    inet_pton(AF_INET, "252.0.0.0", &masks[5]);
    inet_pton(AF_INET, "254.0.0.0", &masks[6]);
    inet_pton(AF_INET, "255.0.0.0", &masks[7]);

    inet_pton(AF_INET, "255.128.0.0", &masks[8]);
    inet_pton(AF_INET, "255.192.0.0", &masks[9]);
    inet_pton(AF_INET, "255.224.0.0", &masks[10]);
    inet_pton(AF_INET, "255.240.0.0", &masks[11]);
    inet_pton(AF_INET, "255.248.0.0", &masks[12]);
    inet_pton(AF_INET, "255.252.0.0", &masks[13]);
    inet_pton(AF_INET, "255.254.0.0", &masks[14]);
    inet_pton(AF_INET, "255.255.0.0", &masks[15]);

    inet_pton(AF_INET, "255.255.128.0", &masks[16]);
    inet_pton(AF_INET, "255.255.192.0", &masks[17]);
    inet_pton(AF_INET, "255.255.224.0", &masks[18]);
    inet_pton(AF_INET, "255.255.240.0", &masks[19]);
    inet_pton(AF_INET, "255.255.248.0", &masks[20]);
    inet_pton(AF_INET, "255.255.252.0", &masks[21]);
    inet_pton(AF_INET, "255.255.254.0", &masks[22]);
    inet_pton(AF_INET, "255.255.255.0", &masks[23]);

    inet_pton(AF_INET, "255.255.255.128", &masks[24]);
    inet_pton(AF_INET, "255.255.255.192", &masks[25]);
    inet_pton(AF_INET, "255.255.255.224", &masks[26]);
    inet_pton(AF_INET, "255.255.255.240", &masks[27]);
    inet_pton(AF_INET, "255.255.255.248", &masks[28]);
    inet_pton(AF_INET, "255.255.255.252", &masks[29]);
    inet_pton(AF_INET, "255.255.255.254", &masks[30]);
    inet_pton(AF_INET, "255.255.255.255", &masks[31]);
  }

  if(mask_length == 0 || mask_length > SUBNETLENGTHSIZE) {
    g_assert_not_reached();
    return 0;
  } else {
    return masks[mask_length - 1];
  }
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
    subnet_length_entries[i].mask = get_subnet_mask(length);
  }

  subnetspath = get_persconffile_path(ENAME_SUBNETS, FALSE, FALSE);
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
host_name_lookup_init(void) {
  char *hostspath;
  struct addrinfo *ai;

#ifdef HAVE_GNU_ADNS
#ifdef _WIN32
  char *sysroot;
  static char rootpath_nt[] = "\\system32\\drivers\\etc\\hosts";
  static char rootpath_ot[] = "\\hosts";
#endif /* _WIN32 */
#endif /*GNU_ADNS */

  if (!addrinfo_list) {
    ai = g_malloc0(sizeof(struct addrinfo));
    addrinfo_list = addrinfo_list_last = ai;
  }

  /*
   * Load the user's hosts file, if they have one.
   */
  hostspath = get_persconffile_path(ENAME_HOSTS, FALSE, FALSE);
  if (!read_hosts_file(hostspath) && errno != ENOENT) {
    report_open_failure(hostspath, errno, FALSE);
  }
  g_free(hostspath);

  /*
   * Load the global hosts file, if we have one.
   */
  hostspath = get_datafile_path(ENAME_HOSTS);
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
    hostspath = g_strconcat(sysroot, rootpath_nt, NULL);
    if (!read_hosts_file(hostspath)) {
      g_free(hostspath);
      hostspath = g_strconcat(sysroot, rootpath_ot, NULL);
      read_hosts_file(hostspath);
    }
    g_free(hostspath);
  }
#else /* _WIN32 */
  read_hosts_file("/etc/hosts");
#endif /* _WIN32 */

  /* XXX - Any flags we should be using? */
  /* XXX - We could provide config settings for DNS servers, and
           pass them to ADNS with adns_init_strcfg */
  if (adns_init(&ads, 0, 0 /*0=>stderr*/) != 0) {
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

  subnet_name_lookup_init();
}

#ifdef HAVE_C_ARES
gboolean
host_name_lookup_process(gpointer data _U_) {
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

  while (async_dns_queue_head != NULL && async_dns_in_flight <= prefs.name_resolve_concurrency) {
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
    select(nfds, &rfds, &wfds, NULL, &tv);
    ares_process(ghba_chan, &rfds, &wfds);
  }

  /* Any new entries? */
  return nro;
}

void
host_name_lookup_cleanup(void) {
  GList *cur;

  cur = g_list_first(async_dns_queue_head);
  while (cur) {
    g_free(cur->data);
    cur = g_list_next (cur);
  }

  g_list_free(async_dns_queue_head);

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
host_name_lookup_process(gpointer data _U_) {
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
  while (cur &&  async_dns_in_flight <= prefs.name_resolve_concurrency) {
    almsg = (async_dns_queue_msg_t *) cur->data;
    if (! almsg->submitted && almsg->type == AF_INET) {
      addr_bytes = (guint8 *) &almsg->ip4_addr;
      g_snprintf(addr_str, sizeof addr_str, "%u.%u.%u.%u.in-addr.arpa.", addr_bytes[3],
                 addr_bytes[2], addr_bytes[1], addr_bytes[0]);
      /* XXX - what if it fails? */
      adns_submit (ads, addr_str, adns_r_ptr, 0, NULL, &almsg->query);
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
      async_dns_in_flight--;
    }
  }

  /* Keep the timeout in place */
  return nro;
}

void
host_name_lookup_cleanup(void) {
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
host_name_lookup_process(gpointer data _U_) {
  gboolean nro = new_resolved_objects;

  new_resolved_objects = FALSE;

  return nro;
}

void
host_name_lookup_cleanup(void) {
}

#endif /* HAVE_C_ARES */

extern const gchar *
get_hostname(const guint addr)
{
  gboolean found;
  gboolean resolve = gbl_resolv_flags & RESOLV_NETWORK;
  hashipv4_t *tp = host_lookup(addr, resolve, &found);

  if (!resolve)
    return tp->ip;

  return tp->name;
}

/* -------------------------- */

extern const gchar *
get_hostname6(const struct e_in6_addr *addr)
{
  gboolean found;
  gboolean resolve = gbl_resolv_flags & RESOLV_NETWORK;
  hashipv6_t *tp = host_lookup6(addr, resolve, &found);

  if (!resolve)
    return tp->ip6;

  return tp->name;
}

/* -------------------------- */
extern void
add_ipv4_name(const guint addr, const gchar *name)
{
  int hash_idx;
  hashipv4_t *tp;
  struct addrinfo *ai;
  struct sockaddr_in *sa4;

  hash_idx = HASH_IPV4_ADDRESS(addr);

  tp = ipv4_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv4_table[hash_idx] = new_ipv4(addr);
  } else {
    while(1) {
      if (tp->addr == addr) {
        /* address already known */
        if (!tp->is_dummy_entry) {
          return;
        } else {
          /* replace this dummy entry with the new one */
          break;
        }
      }
      if (tp->next == NULL) {
        tp->next = new_ipv4(addr);
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }
  g_strlcpy(tp->name, name, MAXNAMELEN);
  tp->resolve = TRUE;
  new_resolved_objects = TRUE;

  if (!addrinfo_list) {
    ai = g_malloc0(sizeof(struct addrinfo));
    addrinfo_list = addrinfo_list_last = ai;
  }

  sa4 = g_malloc0(sizeof(struct sockaddr_in));
  sa4->sin_family = AF_INET;
  sa4->sin_addr.s_addr = addr;

  ai = g_malloc0(sizeof(struct addrinfo));
  ai->ai_family = AF_INET;
  ai->ai_addrlen = sizeof(struct sockaddr_in);
  ai->ai_canonname = (char *) tp->name;
  ai->ai_addr = (struct sockaddr*) sa4;

  addrinfo_list_last->ai_next = ai;
  addrinfo_list_last = ai;

} /* add_ipv4_name */

/* -------------------------- */
extern void
add_ipv6_name(const struct e_in6_addr *addrp, const gchar *name)
{
  int hash_idx;
  hashipv6_t *tp;
  struct addrinfo *ai;
  struct sockaddr_in6 *sa6;

  hash_idx = HASH_IPV6_ADDRESS(*addrp);

  tp = ipv6_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv6_table[hash_idx] = new_ipv6(addrp);
  } else {
    while(1) {
      if (memcmp(&tp->addr, addrp, sizeof (struct e_in6_addr)) == 0) {
        /* address already known */
        if (!tp->is_dummy_entry) {
          return;
        } else {
          /* replace this dummy entry with the new one */
          break;
        }
      }
      if (tp->next == NULL) {
        tp->next = new_ipv6(addrp);
        tp = tp->next;
        break;
      }
      tp = tp->next;
    }
  }
  g_strlcpy(tp->name, name, MAXNAMELEN);
  tp->resolve = TRUE;
  new_resolved_objects = TRUE;

  if (!addrinfo_list) {
    ai = g_malloc0(sizeof(struct addrinfo));
    addrinfo_list = addrinfo_list_last = ai;
  }

  sa6 = g_malloc0(sizeof(struct sockaddr_in6));
  sa6->sin6_family = AF_INET;
  memcpy(sa6->sin6_addr.s6_addr, addrp, 16);

  ai = g_malloc0(sizeof(struct addrinfo));
  ai->ai_family = AF_INET6;
  ai->ai_addrlen = sizeof(struct sockaddr_in);
  ai->ai_canonname = (char *) tp->name;
  ai->ai_addr = (struct sockaddr *) sa6;

  addrinfo_list_last->ai_next = ai;
  addrinfo_list_last = ai;

} /* add_ipv6_name */

/* -----------------
 * unsigned integer to ascii
*/
static gchar *
ep_utoa(guint port)
{
  gchar *bp = ep_alloc(MAXNAMELEN);

  /* XXX, guint32_to_str() ? */
  guint32_to_str_buf(port, bp, MAXNAMELEN);
  return bp;
}


extern gchar *
get_udp_port(guint port)
{

  if (!(gbl_resolv_flags & RESOLV_TRANSPORT)) {
    return ep_utoa(port);
  }

  return serv_name_lookup(port, PT_UDP);

} /* get_udp_port */

extern gchar *
get_dccp_port(guint port)
{

  if (!(gbl_resolv_flags & RESOLV_TRANSPORT)) {
    return ep_utoa(port);
  }

  return serv_name_lookup(port, PT_DCCP);

} /* get_dccp_port */


extern gchar *
get_tcp_port(guint port)
{

  if (!(gbl_resolv_flags & RESOLV_TRANSPORT)) {
    return ep_utoa(port);
  }

  return serv_name_lookup(port, PT_TCP);

} /* get_tcp_port */

extern gchar *
get_sctp_port(guint port)
{

  if (!(gbl_resolv_flags & RESOLV_TRANSPORT)) {
    return ep_utoa(port);
  }

  return serv_name_lookup(port, PT_SCTP);

} /* get_sctp_port */

const gchar *
get_addr_name(const address *addr)
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
se_get_addr_name(const address *addr)
{
  const gchar *result;

  result = se_solve_address_to_name(addr);

  if (result != NULL)
    return result;

  /* if it gets here, either it is of type AT_NONE, */
  /* or it should be solvable in se_address_to_str -unless addr->type is wrongly defined */

  if (addr->type == AT_NONE){
    return "NONE";
  }

  /* We need a "permanently" allocated string */
  return se_address_to_str(addr);
}

void
get_addr_name_buf(const address *addr, gchar *buf, gsize size)
{
  const gchar *result = get_addr_name(addr);

  g_strlcpy(buf, result, size);
} /* get_addr_name_buf */


gchar *
get_ether_name(const guint8 *addr)
{
  hashether_t *tp;
  gboolean resolve = (gbl_resolv_flags & RESOLV_MAC) != 0;

  if (resolve && !eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = TRUE;
  }

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
  if (!(gbl_resolv_flags & RESOLV_MAC))
    return NULL;

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = TRUE;
  }

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

extern guint8 *
get_ether_addr(const gchar *name)
{

  /* force resolution (do not check gbl_resolv_flags) */

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = TRUE;
  }

  return eth_addr_lookup(name);

} /* get_ether_addr */

extern void
add_ether_byip(const guint ip, const guint8 *eth)
{

  gchar *host;
  gboolean found;

  /* first check that IP address can be resolved */
  if (!(gbl_resolv_flags & RESOLV_NETWORK))
    return;

  if ((host = host_name_lookup(ip, &found)) == NULL)
    return;

  /* ok, we can add this entry in the ethers hashtable */

  if (found)
    add_eth_name(eth, host);

} /* add_ether_byip */

extern const gchar *
get_ipxnet_name(const guint32 addr)
{

  if (!(gbl_resolv_flags & RESOLV_NETWORK)) {
    return ipxnet_to_str_punct(addr, '\0');
  }

  if (!ipxnet_resolution_initialized) {
    initialize_ipxnets();
    ipxnet_resolution_initialized = 1;
  }

  return ipxnet_name_lookup(addr);

} /* get_ipxnet_name */

extern guint32
get_ipxnet_addr(const gchar *name, gboolean *known)
{
  guint32 addr;
  gboolean success;

  /* force resolution (do not check gbl_resolv_flags) */

  if (!ipxnet_resolution_initialized) {
    initialize_ipxnets();
    ipxnet_resolution_initialized = 1;
  }

  addr =  ipxnet_addr_lookup(name, &success);

  *known = success;
  return addr;

} /* get_ipxnet_addr */

extern const gchar *
get_manuf_name(const guint8 *addr)
{
  gchar *cur;
  hashmanuf_t  *mtp;

  if ((gbl_resolv_flags & RESOLV_MAC) && !eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = TRUE;
  }

  if (!(gbl_resolv_flags & RESOLV_MAC) || ((mtp = manuf_name_lookup(addr)) == NULL)) {
    cur=ep_strdup_printf("%02x:%02x:%02x", addr[0], addr[1], addr[2]);
    return cur;
  }

  return mtp->name;

} /* get_manuf_name */


const gchar *
get_manuf_name_if_known(const guint8 *addr)
{
  hashmanuf_t  *mtp;

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = TRUE;
  }

  if ((mtp = manuf_name_lookup(addr)) == NULL) {
    return NULL;
  }

  return mtp->name;

} /* get_manuf_name_if_known */


#ifdef HAVE_C_ARES
#define GHI_TIMEOUT (250 * 1000)
static void
#if ( ( ARES_VERSION_MAJOR < 1 )                                     \
 || ( 1 == ARES_VERSION_MAJOR && ARES_VERSION_MINOR < 5 ) )
c_ares_ghi_cb(void *arg, int status, struct hostent *hp) {
#else
c_ares_ghi_cb(void *arg, int status, int timeouts _U_, struct hostent *hp) {
#endif
  /*
   * XXX - If we wanted to be really fancy we could cache results here and
   * look them up in get_host_ipaddr* below.
   */
  async_hostent_t *ahp = arg;
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
    if (! (gbl_resolv_flags & RESOLV_NETWORK)) {
      return FALSE;
    }
    /* It's not a valid dotted-quad IP address; is it a valid
     * host name? */
#ifdef HAVE_C_ARES
    if (! (gbl_resolv_flags & RESOLV_CONCURRENT) ||
        prefs.name_resolve_concurrency < 1 ||
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
      select(nfds, &rfds, &wfds, NULL, tvp);
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

  if (inet_pton(AF_INET6, host, addrp) == 1)
    return TRUE;

  if (! (gbl_resolv_flags & RESOLV_NETWORK)) {
    return FALSE;
  }

  /* try FQDN */
#ifdef HAVE_C_ARES
  if (! (gbl_resolv_flags & RESOLV_CONCURRENT) ||
      prefs.name_resolve_concurrency < 1 ||
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
    select(nfds, &rfds, &wfds, NULL, tvp);
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
