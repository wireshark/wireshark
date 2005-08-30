/* addr_resolv.c
 * Routines for network object lookup
 *
 * $Id$
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <sys/socket.h>		/* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>		/* needed to define AF_ values on Windows */
#endif

#ifdef AVOID_DNS_TIMEOUT
# include <setjmp.h>
#endif

#ifdef NEED_INET_ATON_H
# include "inet_aton.h"
#endif

#ifdef NEED_INET_V6DEFS_H
# include "inet_v6defs.h"
#endif

#ifdef HAVE_GNU_ADNS
# include <errno.h>
# include <adns.h>
#endif

#if defined(_WIN32) && defined(INET6)
# include <ws2tcpip.h>
#endif

#include <glib.h>

#include "report_err.h"
#include "packet.h"
#include "ipv6-utils.h"
#include "addr_resolv.h"
#include "filesystem.h"
#include <epan/prefs.h>
#include <epan/emem.h>

#define ENAME_HOSTS		"hosts"
#define ENAME_ETHERS 		"ethers"
#define ENAME_IPXNETS 		"ipxnets"
#define ENAME_MANUF		"manuf"

#define MAXMANUFLEN	9	/* max vendor name length with ending '\0' */
#define HASHETHSIZE	1024
#define HASHHOSTSIZE	1024
#define HASHIPXNETSIZE	256
#define HASHMANUFSIZE   256
#define HASHPORTSIZE	256

/* hash table used for IPv4 lookup */

#define HASH_IPV4_ADDRESS(addr)	((addr) & (HASHHOSTSIZE - 1))

typedef struct hashipv4 {
  guint			addr;
  gchar   		name[MAXNAMELEN];
  gboolean              is_dummy_entry;	/* name is IPv4 address in dot format */
  struct hashipv4 	*next;
} hashipv4_t;

/* hash table used for IPv6 lookup */

#define HASH_IPV6_ADDRESS(addr)	\
	((((addr).s6_addr8[14] << 8)|((addr).s6_addr8[15])) & (HASHHOSTSIZE - 1))

typedef struct hashipv6 {
  struct e_in6_addr	addr;
  gchar   		name[MAXNAMELEN];
  gboolean              is_dummy_entry;	/* name is IPv6 address in colon format */
  struct hashipv6 	*next;
} hashipv6_t;

/* hash table used for TCP/UDP/SCTP port lookup */

#define HASH_PORT(port)	((port) & (HASHPORTSIZE - 1))

typedef struct hashport {
  guint16		port;
  gchar   		name[MAXNAMELEN];
  struct hashport 	*next;
} hashport_t;

/* hash table used for IPX network lookup */

/* XXX - check goodness of hash function */

#define HASH_IPX_NET(net)	((net) & (HASHIPXNETSIZE - 1))

typedef struct hashipxnet {
  guint			addr;
  gchar   		name[MAXNAMELEN];
  struct hashipxnet 	*next;
} hashipxnet_t;

/* hash tables used for ethernet and manufacturer lookup */

#define HASH_ETH_ADDRESS(addr) \
	(((((addr)[2] << 8) | (addr)[3]) ^ (((addr)[4] << 8) | (addr)[5])) & \
	 (HASHETHSIZE - 1))

#define HASH_ETH_MANUF(addr) (((int)(addr)[2]) & (HASHMANUFSIZE - 1))

typedef struct hashmanuf {
  guint8 		addr[3];
  char 			name[MAXMANUFLEN];
  struct hashmanuf     	*next;
} hashmanuf_t;

typedef struct hashether {
  guint8 		addr[6];
  char 			name[MAXNAMELEN];
  gboolean		is_dummy_entry;		/* not a complete entry */
  struct hashether     	*next;
} hashether_t;

/* internal ethernet type */

typedef struct _ether
{
  guint8		addr[6];
  char 			name[MAXNAMELEN];
} ether_t;

/* internal ipxnet type */

typedef struct _ipxnet
{
  guint			addr;
  char 			name[MAXNAMELEN];
} ipxnet_t;

static hashipv4_t	*ipv4_table[HASHHOSTSIZE];
static hashipv6_t	*ipv6_table[HASHHOSTSIZE];
static hashport_t	*udp_port_table[HASHPORTSIZE];
static hashport_t	*tcp_port_table[HASHPORTSIZE];
static hashport_t	*sctp_port_table[HASHPORTSIZE];
static hashether_t	*eth_table[HASHETHSIZE];
static hashmanuf_t	*manuf_table[HASHMANUFSIZE];
static hashether_t	*(*wka_table[48])[HASHETHSIZE];
static hashipxnet_t	*ipxnet_table[HASHIPXNETSIZE];

static int 		eth_resolution_initialized = 0;
static int 		ipxnet_resolution_initialized = 0;

static hashether_t *add_eth_name(const guint8 *addr, const gchar *name);

/*
 * Flag controlling what names to resolve.
 */
guint32 g_resolv_flags;

/*
 *  Global variables (can be changed in GUI sections)
 *  XXX - they could be changed in GUI code, but there's currently no
 *  GUI code to change them.
 */

gchar *g_ethers_path  = NULL;		/* global ethers file    */
gchar *g_pethers_path = NULL; 		/* personal ethers file  */
gchar *g_ipxnets_path  = NULL;		/* global ipxnets file   */
gchar *g_pipxnets_path = NULL;		/* personal ipxnets file */
					/* first resolving call  */

/* GNU ADNS */

#ifdef HAVE_GNU_ADNS

static gboolean gnu_adns_initialized = FALSE;

adns_state ads;

int adns_currently_queued = 0;

typedef struct _adns_queue_msg
{
  gboolean          submitted;
  guint32           ip4_addr;
  struct e_in6_addr ip6_addr;
  int               type;
  adns_query        query;
} adns_queue_msg_t;

GList *adns_queue_head = NULL;

#endif /* HAVE_GNU_ADNS */

/*
 *  Local function definitions
 */

static gchar *serv_name_lookup(guint port, port_type proto)
{
  int hash_idx;
  hashport_t *tp;
  hashport_t **table;
  const char *serv_proto = NULL;
  struct servent *servp;

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
  default:
    /* not yet implemented */
    return NULL;
    /*NOTREACHED*/
    break;
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

  if (!(g_resolv_flags & RESOLV_TRANSPORT) ||
      (servp = getservbyport(g_htons(port), serv_proto)) == NULL) {
    /* unknown port */
    g_snprintf(tp->name, MAXNAMELEN, "%d", port);
  } else {
    strncpy(tp->name, servp->s_name, MAXNAMELEN);
    tp->name[MAXNAMELEN-1] = '\0';
  }

  return (tp->name);

} /* serv_name_lookup */


#ifdef AVOID_DNS_TIMEOUT

#define DNS_TIMEOUT 	2 	/* max sec per call */

jmp_buf hostname_env;

static void abort_network_query(int sig _U_)
{
  longjmp(hostname_env, 1);
}
#endif /* AVOID_DNS_TIMEOUT */

static gchar *host_name_lookup(guint addr, gboolean *found)
{
  int hash_idx;
  hashipv4_t * volatile tp;
  struct hostent *hostp;
#ifdef HAVE_GNU_ADNS
  adns_queue_msg_t *qmsg;
#endif

  *found = TRUE;

  hash_idx = HASH_IPV4_ADDRESS(addr);

  tp = ipv4_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv4_table[hash_idx] = (hashipv4_t *)g_malloc(sizeof(hashipv4_t));
  } else {
    while(1) {
      if( tp->addr == addr ) {
	if (tp->is_dummy_entry)
	  *found = FALSE;
	return tp->name;
      }
      if (tp->next == NULL) {
	tp->next = (hashipv4_t *)g_malloc(sizeof(hashipv4_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }

  /* fill in a new entry */
  tp->addr = addr;
  tp->next = NULL;

#ifdef HAVE_GNU_ADNS
  if ((g_resolv_flags & RESOLV_CONCURRENT) && 
      prefs.name_resolve_concurrency > 0 &&
      gnu_adns_initialized) {
    qmsg = g_malloc(sizeof(adns_queue_msg_t));
    qmsg->type = AF_INET;
    qmsg->ip4_addr = addr;
    qmsg->submitted = FALSE;
    adns_queue_head = g_list_append(adns_queue_head, (gpointer) qmsg);

    tp->is_dummy_entry = TRUE;
    ip_to_str_buf((guint8 *)&addr, tp->name);
    return tp->name;
  }
#endif /* HAVE_GNU_ADNS */

  /*
   * The Windows "gethostbyaddr()" insists on translating 0.0.0.0 to
   * the name of the host on which it's running; to work around that
   * botch, we don't try to translate an all-zero IP address to a host
   * name.
   */
  if (addr != 0 && (g_resolv_flags & RESOLV_NETWORK)) {
  /* Use async DNS if possible, else fall back to timeouts,
   * else call gethostbyaddr and hope for the best
   */

# ifdef AVOID_DNS_TIMEOUT

    /* Quick hack to avoid DNS/YP timeout */

    if (!setjmp(hostname_env)) {
      signal(SIGALRM, abort_network_query);
      alarm(DNS_TIMEOUT);
# endif /* AVOID_DNS_TIMEOUT */

      hostp = gethostbyaddr((char *)&addr, 4, AF_INET);

# ifdef AVOID_DNS_TIMEOUT
      alarm(0);
# endif /* AVOID_DNS_TIMEOUT */

      if (hostp != NULL) {
	strncpy(tp->name, hostp->h_name, MAXNAMELEN);
	tp->name[MAXNAMELEN-1] = '\0';
	tp->is_dummy_entry = FALSE;
	return tp->name;
      }

# ifdef AVOID_DNS_TIMEOUT
    }
# endif /* AVOID_DNS_TIMEOUT */

  }

  /* unknown host or DNS timeout */

  ip_to_str_buf((guint8 *)&addr, tp->name);
  tp->is_dummy_entry = TRUE;
  *found = FALSE;

  return (tp->name);

} /* host_name_lookup */

static gchar *host_name_lookup6(struct e_in6_addr *addr, gboolean *found)
{
  int hash_idx;
  hashipv6_t * volatile tp;
#ifdef INET6
  struct hostent *hostp;
#endif

  *found = TRUE;

  hash_idx = HASH_IPV6_ADDRESS(*addr);

  tp = ipv6_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv6_table[hash_idx] = (hashipv6_t *)g_malloc(sizeof(hashipv6_t));
  } else {
    while(1) {
      if( memcmp(&tp->addr, addr, sizeof (struct e_in6_addr)) == 0 ) {
	if (tp->is_dummy_entry)
	  *found = FALSE;
	return tp->name;
      }
      if (tp->next == NULL) {
	tp->next = (hashipv6_t *)g_malloc(sizeof(hashipv6_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }

  /* fill in a new entry */
  tp->addr = *addr;
  tp->next = NULL;

#ifdef INET6
  if (g_resolv_flags & RESOLV_NETWORK) {
#ifdef AVOID_DNS_TIMEOUT

    /* Quick hack to avoid DNS/YP timeout */

    if (!setjmp(hostname_env)) {
      signal(SIGALRM, abort_network_query);
      alarm(DNS_TIMEOUT);
#endif /* AVOID_DNS_TIMEOUT */
      hostp = gethostbyaddr((char *)addr, sizeof(*addr), AF_INET6);
#ifdef AVOID_DNS_TIMEOUT
      alarm(0);
# endif /* AVOID_DNS_TIMEOUT */

      if (hostp != NULL) {
	strncpy(tp->name, hostp->h_name, MAXNAMELEN);
	tp->name[MAXNAMELEN-1] = '\0';
	tp->is_dummy_entry = FALSE;
	return tp->name;
      }

#ifdef AVOID_DNS_TIMEOUT
    }
# endif /* AVOID_DNS_TIMEOUT */

  }

  /* unknown host or DNS timeout */
#endif /* INET6 */
  ip6_to_str_buf(addr, tp->name);
  tp->is_dummy_entry = TRUE;
  *found = FALSE;
  return (tp->name);

} /* host_name_lookup6 */

static const gchar *solve_address_to_name(address *addr)
{
  guint32 ipv4_addr;
  struct e_in6_addr ipv6_addr;

  switch (addr->type) {

  case AT_ETHER:
    return get_ether_name(addr->data);

  case AT_IPv4:
    memcpy(&ipv4_addr, addr->data, sizeof ipv4_addr);
    return get_hostname(ipv4_addr);

  case AT_IPv6:
    memcpy(&ipv6_addr.s6_addr, addr->data, sizeof ipv6_addr.s6_addr);
    return get_hostname6(&ipv6_addr);

  case AT_STRINGZ:
    return addr->data;

  default:
    return NULL;
  }
} /* solve_address_to_name */


/*
 *  Miscellaneous functions
 */

static int fgetline(char **buf, int *size, FILE *fp)
{
  int len;
  int c;

  if (fp == NULL)
    return -1;

  if (*buf == NULL) {
    if (*size == 0)
      *size = BUFSIZ;

    if ((*buf = g_malloc(*size)) == NULL)
      return -1;
  }

  if (feof(fp))
    return -1;

  len = 0;
  while ((c = getc(fp)) != EOF && c != '\n') {
    if (len+1 >= *size) {
      if ((*buf = g_realloc(*buf, *size += BUFSIZ)) == NULL)
	return -1;
    }
    (*buf)[len++] = c;
  }

  if (len == 0 && c == EOF)
    return -1;

  (*buf)[len] = '\0';

  return len;

} /* fgetline */


/*
 * Ethernet / manufacturer resolution
 *
 * The following functions implement ethernet address resolution and
 * ethers files parsing (see ethers(4)).
 *
 * The manuf file has the same format as ethers(4) except that names are
 * truncated to MAXMANUFLEN-1 characters and that an address contains
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
                    gboolean manuf_file)
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
      return FALSE;	/* failed */
    if (num > 0xFF)
      return FALSE;	/* not a valid octet */
    eth->addr[i] = (guint8) num;
    cp = p;		/* skip past the number */

    /* OK, what character terminated the octet? */
    if (*cp == '/') {
      /* "/" - this has a mask. */
      if (!manuf_file) {
      	/* Entries with masks are allowed only in the "manuf" files. */
	return FALSE;
      }
      cp++;	/* skip past the '/' to get to the mask */
      if (!isdigit((unsigned char)*cp))
	return FALSE;	/* no sign allowed */
      num = strtoul(cp, &p, 10);
      if (p == cp)
	return FALSE;	/* failed */
      cp = p;	/* skip past the number */
      if (*cp != '\0' && !isspace((unsigned char)*cp))
	return FALSE;	/* bogus terminator */
      if (num == 0 || num >= 48)
	return FALSE;	/* bogus mask */
      /* Mask out the bits not covered by the mask */
      *mask = num;
      for (i = 0; num >= 8; i++, num -= 8)
	;	/* skip octets entirely covered by the mask */
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
	sep = *cp;	/* subsequent separators must be the same */
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

static int parse_ether_line(char *line, ether_t *eth, unsigned int *mask,
			    gboolean manuf_file)
{
  /*
   *  See the ethers(4) or ethers(5) man page for ethers file format
   *  (not available on all systems).
   *  We allow both ethernet address separators (':' and '-'),
   *  as well as Ethereal's '.' separator.
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

  strncpy(eth->name, cp, MAXNAMELEN);
  eth->name[MAXNAMELEN-1] = '\0';

  return 0;

} /* parse_ether_line */

static FILE *eth_p = NULL;

static void set_ethent(char *path)
{
  if (eth_p)
    rewind(eth_p);
  else
    eth_p = fopen(path, "r");
}

static void end_ethent(void)
{
  if (eth_p) {
    fclose(eth_p);
    eth_p = NULL;
  }
}

static ether_t *get_ethent(unsigned int *mask, gboolean manuf_file)
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

static ether_t *get_ethbyname(const gchar *name)
{
  ether_t *eth;

  set_ethent(g_pethers_path);

  while ((eth = get_ethent(NULL, FALSE)) && strncmp(name, eth->name, MAXNAMELEN) != 0)
    ;

  if (eth == NULL) {
    end_ethent();

    set_ethent(g_ethers_path);

    while ((eth = get_ethent(NULL, FALSE)) && strncmp(name, eth->name, MAXNAMELEN) != 0)
      ;

    end_ethent();
  }

  return eth;

} /* get_ethbyname */

static ether_t *get_ethbyaddr(const guint8 *addr)
{

  ether_t *eth;

  set_ethent(g_pethers_path);

  while ((eth = get_ethent(NULL, FALSE)) && memcmp(addr, eth->addr, 6) != 0)
    ;

  if (eth == NULL) {
    end_ethent();

    set_ethent(g_ethers_path);

    while ((eth = get_ethent(NULL, FALSE)) && memcmp(addr, eth->addr, 6) != 0)
      ;

    end_ethent();
  }

  return eth;

} /* get_ethbyaddr */

static int hash_eth_wka(const guint8 *addr, unsigned int mask)
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

static void add_manuf_name(guint8 *addr, unsigned int mask, gchar *name)
{
  int hash_idx;
  hashmanuf_t *tp;
  hashether_t *(*wka_tp)[HASHETHSIZE], *etp;

  if (mask == 48) {
    /* This is a well-known MAC address; just add this to the Ethernet
       hash table */
    add_eth_name(addr, name);
    return;
  }

  if (mask == 0) {
    /* This is a manufacturer ID; add it to the manufacturer ID hash table */

    hash_idx = HASH_ETH_MANUF(addr);

    tp = manuf_table[hash_idx];

    if( tp == NULL ) {
      tp = manuf_table[hash_idx] = (hashmanuf_t *)g_malloc(sizeof(hashmanuf_t));
    } else {
      while(1) {
	if (tp->next == NULL) {
	  tp->next = (hashmanuf_t *)g_malloc(sizeof(hashmanuf_t));
	  tp = tp->next;
	  break;
	}
	tp = tp->next;
      }
    }

    memcpy(tp->addr, addr, sizeof(tp->addr));
    strncpy(tp->name, name, MAXMANUFLEN);
    tp->name[MAXMANUFLEN-1] = '\0';
    tp->next = NULL;
    return;
  }

  /* This is a range of well-known addresses; add it to the appropriate
     well-known-address table, creating that table if necessary. */
  wka_tp = wka_table[mask];
  if (wka_tp == NULL)
    wka_tp = wka_table[mask] = g_malloc0(sizeof *wka_table[mask]);

  hash_idx = hash_eth_wka(addr, mask);

  etp = (*wka_tp)[hash_idx];

  if( etp == NULL ) {
    etp = (*wka_tp)[hash_idx] = (hashether_t *)g_malloc(sizeof(hashether_t));
  } else {
    while(1) {
      if (memcmp(etp->addr, addr, sizeof(etp->addr)) == 0) {
	/* address already known */
	return;
      }
      if (etp->next == NULL) {
	etp->next = (hashether_t *)g_malloc(sizeof(hashether_t));
	etp = etp->next;
	break;
      }
      etp = etp->next;
    }
  }

  memcpy(etp->addr, addr, sizeof(etp->addr));
  strncpy(etp->name, name, MAXNAMELEN);
  etp->name[MAXNAMELEN-1] = '\0';
  etp->next = NULL;
  etp->is_dummy_entry = FALSE;

} /* add_manuf_name */

static hashmanuf_t *manuf_name_lookup(const guint8 *addr)
{
  int hash_idx;
  hashmanuf_t *tp;

  hash_idx = HASH_ETH_MANUF(addr);

  tp = manuf_table[hash_idx];

  while(tp != NULL) {
    if (memcmp(tp->addr, addr, sizeof(tp->addr)) == 0) {
      return tp;
    }
    tp = tp->next;
  }

  return NULL;

} /* manuf_name_lookup */

static hashether_t *wka_name_lookup(const guint8 *addr, unsigned int mask)
{
  int hash_idx;
  hashether_t *(*wka_tp)[HASHETHSIZE];
  hashether_t *tp;
  guint8 masked_addr[6];
  unsigned int num;
  int i;

  wka_tp = wka_table[mask];
  if (wka_tp == NULL) {
    /* There are no entries in the table for that mask value, as there is
       no table for that mask value. */
    return NULL;
  }

  /* Get the part of the address covered by the mask. */
  for (i = 0, num = mask; num >= 8; i++, num -= 8)
    masked_addr[i] = addr[i];	/* copy octets entirely covered by the mask */
  /* Mask out the first masked octet */
  masked_addr[i] = addr[i] & (0xFF << (8 - num));
  i++;
  /* Zero out completely-masked-out octets */
  for (; i < 6; i++)
    masked_addr[i] = 0;

  hash_idx = hash_eth_wka(masked_addr, mask);

  tp = (*wka_tp)[hash_idx];

  while(tp != NULL) {
    if (memcmp(tp->addr, masked_addr, sizeof(tp->addr)) == 0) {
      return tp;
    }
    tp = tp->next;
  }

  return NULL;

} /* wka_name_lookup */

static void initialize_ethers(void)
{
  ether_t *eth;
  char *manuf_path;
  unsigned int mask;

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

static hashether_t *add_eth_name(const guint8 *addr, const gchar *name)
{
  int hash_idx;
  hashether_t *tp;

  hash_idx = HASH_ETH_ADDRESS(addr);

  tp = eth_table[hash_idx];

  if( tp == NULL ) {
    tp = eth_table[hash_idx] = (hashether_t *)g_malloc(sizeof(hashether_t));
  } else {
    while(1) {
      if (memcmp(tp->addr, addr, sizeof(tp->addr)) == 0) {
	/* address already known */
	if (!tp->is_dummy_entry) {
	  return tp;
	} else {
	  /* replace this dummy (manuf) entry with a real name */
	  break;
	}
      }
      if (tp->next == NULL) {
	tp->next = (hashether_t *)g_malloc(sizeof(hashether_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }

  memcpy(tp->addr, addr, sizeof(tp->addr));
  strncpy(tp->name, name, MAXNAMELEN);
  tp->name[MAXNAMELEN-1] = '\0';
  tp->next = NULL;
  tp->is_dummy_entry = FALSE;

  return tp;

} /* add_eth_name */

static gchar *eth_name_lookup(const guint8 *addr)
{
  int hash_idx;
  hashmanuf_t *manufp;
  hashether_t *tp;
  ether_t *eth;
  hashether_t *etp;
  unsigned int mask;

  hash_idx = HASH_ETH_ADDRESS(addr);

  tp = eth_table[hash_idx];

  if( tp == NULL ) {
    tp = eth_table[hash_idx] = (hashether_t *)g_malloc(sizeof(hashether_t));
  } else {
    while(1) {
      if (memcmp(tp->addr, addr, sizeof(tp->addr)) == 0) {
	return tp->name;
      }
      if (tp->next == NULL) {
	tp->next = (hashether_t *)g_malloc(sizeof(hashether_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }

  /* fill in a new entry */

  memcpy(tp->addr, addr, sizeof(tp->addr));
  tp->next = NULL;

  if ( (eth = get_ethbyaddr(addr)) == NULL) {
    /* Unknown name.  Try looking for it in the well-known-address
       tables for well-known address ranges smaller than 2^24. */
    mask = 7;
    for (;;) {
      /* Only the topmost 5 bytes participate fully */
      if ((etp = wka_name_lookup(addr, mask+40)) != NULL) {
	g_snprintf(tp->name, MAXNAMELEN, "%s_%02x",
	      etp->name, addr[5] & (0xFF >> mask));
	tp->is_dummy_entry = TRUE;
	return (tp->name);
      }
      if (mask == 0)
        break;
      mask--;
    }

    mask = 7;
    for (;;) {
      /* Only the topmost 4 bytes participate fully */
      if ((etp = wka_name_lookup(addr, mask+32)) != NULL) {
	g_snprintf(tp->name, MAXNAMELEN, "%s_%02x:%02x",
	      etp->name, addr[4] & (0xFF >> mask), addr[5]);
	tp->is_dummy_entry = TRUE;
	return (tp->name);
      }
      if (mask == 0)
        break;
      mask--;
    }

    mask = 7;
    for (;;) {
      /* Only the topmost 3 bytes participate fully */
      if ((etp = wka_name_lookup(addr, mask+24)) != NULL) {
	g_snprintf(tp->name, MAXNAMELEN, "%s_%02x:%02x:%02x",
	      etp->name, addr[3] & (0xFF >> mask), addr[4], addr[5]);
	tp->is_dummy_entry = TRUE;
	return (tp->name);
      }
      if (mask == 0)
        break;
      mask--;
    }

    /* Now try looking in the manufacturer table. */
    if ((manufp = manuf_name_lookup(addr)) != NULL) {
      g_snprintf(tp->name, MAXNAMELEN, "%s_%02x:%02x:%02x",
	      manufp->name, addr[3], addr[4], addr[5]);
      tp->is_dummy_entry = TRUE;
      return (tp->name);
    }

    /* Now try looking for it in the well-known-address
       tables for well-known address ranges larger than 2^24. */
    mask = 7;
    for (;;) {
      /* Only the topmost 2 bytes participate fully */
      if ((etp = wka_name_lookup(addr, mask+16)) != NULL) {
	g_snprintf(tp->name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x",
	      etp->name, addr[2] & (0xFF >> mask), addr[3], addr[4],
	      addr[5]);
	tp->is_dummy_entry = TRUE;
	return (tp->name);
      }
      if (mask == 0)
        break;
      mask--;
    }

    mask = 7;
    for (;;) {
      /* Only the topmost byte participates fully */
      if ((etp = wka_name_lookup(addr, mask+8)) != NULL) {
	g_snprintf(tp->name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x",
	      etp->name, addr[1] & (0xFF >> mask), addr[2], addr[3],
	      addr[4], addr[5]);
	tp->is_dummy_entry = TRUE;
	return (tp->name);
      }
      if (mask == 0)
        break;
      mask--;
    }

    for (mask = 7; mask > 0; mask--) {
      /* Not even the topmost byte participates fully */
      if ((etp = wka_name_lookup(addr, mask)) != NULL) {
	g_snprintf(tp->name, MAXNAMELEN, "%s_%02x:%02x:%02x:%02x:%02x:%02x",
	      etp->name, addr[0] & (0xFF >> mask), addr[1], addr[2],
	      addr[3], addr[4], addr[5]);
	tp->is_dummy_entry = TRUE;
	return (tp->name);
      }
    }

    /* No match whatsoever. */
    g_snprintf(tp->name, MAXNAMELEN, "%s", ether_to_str(addr));
    tp->is_dummy_entry = TRUE;

  } else {
    strncpy(tp->name, eth->name, MAXNAMELEN);
    tp->name[MAXNAMELEN-1] = '\0';
    tp->is_dummy_entry = FALSE;
  }

  return (tp->name);

} /* eth_name_lookup */

static guint8 *eth_addr_lookup(const gchar *name)
{
  ether_t *eth;
  hashether_t *tp;
  hashether_t **table = eth_table;
  int i;

  /* to be optimized (hash table from name to addr) */
  for (i = 0; i < HASHETHSIZE; i++) {
    tp = table[i];
    while (tp) {
      if (strcmp(tp->name, name) == 0)
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
static int parse_ipxnets_line(char *line, ipxnet_t *ipxnet)
{
  /*
   *  We allow three address separators (':', '-', and '.'),
   *  as well as no separators
   */

  gchar		*cp;
  guint32	a, a0, a1, a2, a3;
  gboolean	found_single_number = FALSE;

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

  strncpy(ipxnet->name, cp, MAXNAMELEN);
  ipxnet->name[MAXNAMELEN-1] = '\0';

  return 0;

} /* parse_ipxnets_line */

static FILE *ipxnet_p = NULL;

static void set_ipxnetent(char *path)
{
  if (ipxnet_p)
    rewind(ipxnet_p);
  else
    ipxnet_p = fopen(path, "r");
}

static void end_ipxnetent(void)
{
  if (ipxnet_p) {
    fclose(ipxnet_p);
    ipxnet_p = NULL;
  }
}

static ipxnet_t *get_ipxnetent(void)
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

static ipxnet_t *get_ipxnetbyname(const gchar *name)
{
  ipxnet_t *ipxnet;

  set_ipxnetent(g_ipxnets_path);

  while ((ipxnet = get_ipxnetent()) && strncmp(name, ipxnet->name, MAXNAMELEN) != 0)
    ;

  if (ipxnet == NULL) {
    end_ipxnetent();

    set_ipxnetent(g_pipxnets_path);

    while ((ipxnet = get_ipxnetent()) && strncmp(name, ipxnet->name, MAXNAMELEN) != 0)
      ;

    end_ipxnetent();
  }

  return ipxnet;

} /* get_ipxnetbyname */

static ipxnet_t *get_ipxnetbyaddr(guint32 addr)
{

  ipxnet_t *ipxnet;

  set_ipxnetent(g_ipxnets_path);

  while ((ipxnet = get_ipxnetent()) && (addr != ipxnet->addr) ) ;

  if (ipxnet == NULL) {
    end_ipxnetent();

    set_ipxnetent(g_pipxnets_path);

    while ((ipxnet = get_ipxnetent()) && (addr != ipxnet->addr) )
      ;

    end_ipxnetent();
  }

  return ipxnet;

} /* get_ipxnetbyaddr */

static void initialize_ipxnets(void)
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

static hashipxnet_t *add_ipxnet_name(guint addr, const gchar *name)
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
  strncpy(tp->name, name, MAXNAMELEN);
  tp->name[MAXNAMELEN-1] = '\0';
  tp->next = NULL;

  return tp;

} /* add_ipxnet_name */

static gchar *ipxnet_name_lookup(const guint addr)
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
    strncpy(tp->name, ipxnet->name, MAXNAMELEN);
    tp->name[MAXNAMELEN-1] = '\0';
  }

  return (tp->name);

} /* ipxnet_name_lookup */

static guint ipxnet_addr_lookup(const gchar *name, gboolean *success)
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

static gboolean
read_hosts_file (const char *hostspath)
{
  FILE *hf;
  char *line = NULL;
  int size = 0;
  gchar *cp;
  guint32 host_addr[4]; /* IPv4 or IPv6 */
  struct e_in6_addr ipv6_addr;
  gboolean is_ipv6;
  int ret;

  /*
   *  See the hosts(4) or hosts(5) man page for hosts file format
   *  (not available on all systems).
   */
  if ((hf = fopen(hostspath, "r")) == NULL)
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
      memcpy(&ipv6_addr, host_addr, sizeof ipv6_addr);
      add_ipv6_name(&ipv6_addr, cp);
    } else
      add_ipv4_name(host_addr[0], cp);

    /*
     * Add the aliases, too, if there are any.
     */
    while ((cp = strtok(NULL, " \t")) != NULL) {
      if (is_ipv6) {
        memcpy(&ipv6_addr, host_addr, sizeof ipv6_addr);
        add_ipv6_name(&ipv6_addr, cp);
      } else
        add_ipv4_name(host_addr[0], cp);
    }
  }
  if (line != NULL)
    g_free(line);

  fclose(hf);
  return TRUE;
} /* read_hosts_file */

/*
 *  External Functions
 */

void
host_name_lookup_init(void) {
  char *hostspath;

#ifdef HAVE_GNU_ADNS
#ifdef WIN32
  char *sysroot;
  static char rootpath_nt[] = "\\system32\\drivers\\etc\\hosts";
  static char rootpath_ot[] = "\\hosts";
#endif /* WIN32 */
#endif /*GNU_ADNS */

  /*
   * Load the user's hosts file, if they have one.
   */
  hostspath = get_persconffile_path(ENAME_HOSTS, FALSE);
  if (!read_hosts_file(hostspath) && errno != ENOENT) {
    report_open_failure(hostspath, errno, FALSE);
  }
  g_free(hostspath);

#ifdef HAVE_GNU_ADNS
  /*
   * We're using GNU ADNS, which doesn't check the system hosts file;
   * we load that file ourselves.
   */
#ifdef WIN32

  sysroot = getenv("WINDIR");
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
#else /* WIN32 */
  read_hosts_file("/etc/hosts");
#endif /* WIN32 */

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
  gnu_adns_initialized = TRUE;
  adns_currently_queued = 0;
#endif /* HAVE_GNU_ADNS */
}

#ifdef HAVE_GNU_ADNS

/* XXX - The ADNS "documentation" isn't very clear:
 * - Do we need to keep our query structures around?
 */
gint
host_name_lookup_process(gpointer data _U_) {
  adns_queue_msg_t *almsg;
  GList *cur;
  char addr_str[] = "111.222.333.444.in-addr.arpa.";
  guint8 *addr_bytes;
  adns_answer *ans;
  int ret;
  gboolean dequeue;

  adns_queue_head = g_list_first(adns_queue_head);

  cur = adns_queue_head;
  while (cur && adns_currently_queued <= prefs.name_resolve_concurrency) {
    almsg = (adns_queue_msg_t *) cur->data;
    if (! almsg->submitted && almsg->type == AF_INET) {
      addr_bytes = (guint8 *) &almsg->ip4_addr;
      g_snprintf(addr_str, sizeof addr_str, "%u.%u.%u.%u.in-addr.arpa.", addr_bytes[3],
          addr_bytes[2], addr_bytes[1], addr_bytes[0]);
      /* XXX - what if it fails? */
      adns_submit (ads, addr_str, adns_r_ptr, 0, NULL, &almsg->query);
      almsg->submitted = TRUE;
      adns_currently_queued++;
    }
    cur = cur->next;
  }

  cur = adns_queue_head;
  while (cur) {
    dequeue = FALSE;
    almsg = (adns_queue_msg_t *) cur->data;
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
      adns_queue_head = g_list_remove(adns_queue_head, (void *) almsg);
      g_free(almsg);
      adns_currently_queued--;
    }
  }

  /* Keep the timeout in place */
  return 1;
}

void
host_name_lookup_cleanup(void) {
  void *qdata;

  adns_queue_head = g_list_first(adns_queue_head);
  while (adns_queue_head) {
    qdata = adns_queue_head->data;
    adns_queue_head = g_list_remove(adns_queue_head, qdata);
    g_free(qdata);
  }
  
  if (gnu_adns_initialized)
    adns_finish(ads);
}

#else

gint
host_name_lookup_process(gpointer data _U_) {
  /* Kill the timeout, as there's nothing for it to do */
  return 0;
}

void
host_name_lookup_cleanup(void) {
}

#endif /* HAVE_GNU_ADNS */

extern gchar *get_hostname(guint addr)
{
  gboolean found;

  if (!(g_resolv_flags & RESOLV_NETWORK))
    return ip_to_str((guint8 *)&addr);

  return host_name_lookup(addr, &found);
}

extern const gchar *get_hostname6(struct e_in6_addr *addr)
{
  gboolean found;

#ifdef INET6
  if (!(g_resolv_flags & RESOLV_NETWORK))
    return ip6_to_str(addr);
#ifdef SOLARIS8_INET6
  if (IN6_IS_ADDR_LINKLOCAL((struct in6_addr*)addr) || IN6_IS_ADDR_MULTICAST((struct in6_addr*)addr))
#else
  if (IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MULTICAST(addr))
#endif
    return ip6_to_str(addr);
#endif

  return host_name_lookup6(addr, &found);
}

extern void add_ipv4_name(guint addr, const gchar *name)
{
  int hash_idx;
  hashipv4_t *tp;

  hash_idx = HASH_IPV4_ADDRESS(addr);

  tp = ipv4_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv4_table[hash_idx] = (hashipv4_t *)g_malloc(sizeof(hashipv4_t));
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
	tp->next = (hashipv4_t *)g_malloc(sizeof(hashipv4_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }

  strncpy(tp->name, name, MAXNAMELEN);
  tp->name[MAXNAMELEN-1] = '\0';
  tp->addr = addr;
  tp->next = NULL;
  tp->is_dummy_entry = FALSE;

} /* add_ipv4_name */

extern void add_ipv6_name(struct e_in6_addr *addrp, const gchar *name)
{
  int hash_idx;
  hashipv6_t *tp;

  hash_idx = HASH_IPV6_ADDRESS(*addrp);

  tp = ipv6_table[hash_idx];

  if( tp == NULL ) {
    tp = ipv6_table[hash_idx] = (hashipv6_t *)g_malloc(sizeof(hashipv6_t));
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
	tp->next = (hashipv6_t *)g_malloc(sizeof(hashipv6_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }

  strncpy(tp->name, name, MAXNAMELEN);
  tp->name[MAXNAMELEN-1] = '\0';
  tp->addr = *addrp;
  tp->next = NULL;
  tp->is_dummy_entry = FALSE;

} /* add_ipv6_name */

extern gchar *get_udp_port(guint port)
{
  gchar *cur;

  if (!(g_resolv_flags & RESOLV_TRANSPORT)) {
    cur=ep_alloc(MAXNAMELEN);
    g_snprintf(cur, MAXNAMELEN, "%u", port);
    return cur;
  }

  return serv_name_lookup(port, PT_UDP);

} /* get_udp_port */

extern gchar *get_tcp_port(guint port)
{
  gchar *cur;

  if (!(g_resolv_flags & RESOLV_TRANSPORT)) {
    cur=ep_alloc(MAXNAMELEN);
    g_snprintf(cur, MAXNAMELEN, "%u", port);
    return cur;
  }

  return serv_name_lookup(port, PT_TCP);

} /* get_tcp_port */

extern gchar *get_sctp_port(guint port)
{
  gchar *cur;

  if (!(g_resolv_flags & RESOLV_TRANSPORT)) {
    cur=ep_alloc(MAXNAMELEN);
    g_snprintf(cur, MAXNAMELEN, "%u", port);
    return cur;
  }

  return serv_name_lookup(port, PT_SCTP);

} /* get_sctp_port */


const gchar *get_addr_name(address *addr)
{
  const gchar *result;
  
  result = solve_address_to_name(addr);
  
  if (result!=NULL){
	  return result;
  }
  
  /* if it gets here, either it is of type AT_NONE, */
  /* or it should be solvable in address_to_str -unless addr->type is wrongly defined- */
  
  if (addr->type == AT_NONE){
	  return "NONE";
  }
   
  return(address_to_str(addr));
} /* get_addr_name */
  
  
void get_addr_name_buf(address *addr, gchar *buf, guint size)
{
  const gchar *result;
    
  result = get_addr_name(addr);
  
  strncpy(buf,result,size);
  buf[size]='\0';
  return;

} /* get_addr_name_buf */


extern gchar *get_ether_name(const guint8 *addr)
{
  if (!(g_resolv_flags & RESOLV_MAC))
    return ether_to_str(addr);

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = 1;
  }

  return eth_name_lookup(addr);

} /* get_ether_name */

/* Look for an ether name in the hash, and return it if found.
 * If it's not found, simply return NULL. We DO NOT make a new
 * hash entry for it with the hex digits turned into a string.
 */
gchar *get_ether_name_if_known(const guint8 *addr)
{
  int hash_idx;
  hashether_t *tp;

  /* Initialize ether structs if we're the first
   * ether-related function called */
  if (!(g_resolv_flags & RESOLV_MAC))
    return NULL;

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = 1;
  }

  hash_idx = HASH_ETH_ADDRESS(addr);

  tp = eth_table[hash_idx];

  if( tp == NULL ) {
	  /* Hash key not found in table.
	   * Force a lookup (and a hash entry) for addr, then call
	   * myself. I plan on not getting into an infinite loop because
	   * eth_name_lookup() is guaranteed to make a hashtable entry,
	   * so when I call myself again, I can never get into this
	   * block of code again. Knock on wood...
	   */
	  (void) eth_name_lookup(addr);
	  return get_ether_name_if_known(addr); /* a well-placed goto would suffice */
  }
  else {
    while(1) {
      if (memcmp(tp->addr, addr, sizeof(tp->addr)) == 0) {
	      if (!tp->is_dummy_entry) {
		/* A name was found, and its origin is an ethers file */
		return tp->name;
	      }
	      else {
		/* A name was found, but it was created, not found in a file */
		return NULL;
	      }
      }
      if (tp->next == NULL) {
	  /* Read my reason above for why I'm sure I can't get into an infinite loop */
	  (void) eth_name_lookup(addr);
	  return get_ether_name_if_known(addr); /* a well-placed goto would suffice */
      }
      tp = tp->next;
    }
  }
  g_assert_not_reached();
  return NULL;
}


extern guint8 *get_ether_addr(const gchar *name)
{

  /* force resolution (do not check g_resolv_flags) */

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = 1;
  }

  return eth_addr_lookup(name);

} /* get_ether_addr */

extern void add_ether_byip(guint ip, const guint8 *eth)
{

  gchar *host;
  gboolean found;

  /* first check that IP address can be resolved */

  if ((host = host_name_lookup(ip, &found)) == NULL)
    return;

  /* ok, we can add this entry in the ethers hashtable */

  if (found)
    add_eth_name(eth, host);

} /* add_ether_byip */

extern const gchar *get_ipxnet_name(const guint32 addr)
{

  if (!(g_resolv_flags & RESOLV_NETWORK)) {
	  return ipxnet_to_str_punct(addr, '\0');
  }

  if (!ipxnet_resolution_initialized) {
    initialize_ipxnets();
    ipxnet_resolution_initialized = 1;
  }

  return ipxnet_name_lookup(addr);

} /* get_ipxnet_name */

extern guint32 get_ipxnet_addr(const gchar *name, gboolean *known)
{
  guint32 addr;
  gboolean success;

  /* force resolution (do not check g_resolv_flags) */

  if (!ipxnet_resolution_initialized) {
    initialize_ipxnets();
    ipxnet_resolution_initialized = 1;
  }

  addr =  ipxnet_addr_lookup(name, &success);

  *known = success;
  return addr;

} /* get_ipxnet_addr */

extern const gchar *get_manuf_name(const guint8 *addr)
{
  gchar *cur;
  hashmanuf_t  *manufp;

  if ((g_resolv_flags & RESOLV_MAC) && !eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = 1;
  }

  if (!(g_resolv_flags & RESOLV_MAC) || ((manufp = manuf_name_lookup(addr)) == NULL)) {
    cur=ep_alloc(MAXMANUFLEN);
    g_snprintf(cur, MAXMANUFLEN, "%02x:%02x:%02x", addr[0], addr[1], addr[2]);
    return cur;
  }

  return manufp->name;

} /* get_manuf_name */


const gchar *get_manuf_name_if_known(const guint8 *addr)
{
  hashmanuf_t  *manufp;

  if (!eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = 1;
  }

  if ((manufp = manuf_name_lookup(addr)) == NULL) {
    return NULL;
  }

  return manufp->name;

} /* get_manuf_name_if_known */


/* Translate a string, assumed either to be a dotted-quad IP address or
 * a host name, to a numeric IP address.  Return TRUE if we succeed and
 * set "*addrp" to that numeric IP address; return FALSE if we fail.
 * Used more in the dfilter parser rather than in packet dissectors */
gboolean get_host_ipaddr(const char *host, guint32 *addrp)
{
	struct in_addr		ipaddr;
	struct hostent		*hp;

	/*
	 * don't change it to inet_pton(AF_INET), they are not 100% compatible.
	 * inet_pton(AF_INET) does not support hexadecimal notation nor
	 * less-than-4 octet notation.
	 */
	if (!inet_aton(host, &ipaddr)) {
		/* It's not a valid dotted-quad IP address; is it a valid
		 * host name? */
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

	*addrp = g_ntohl(ipaddr.s_addr);
	return TRUE;
}

/*
 * Translate IPv6 numeric address or FQDN hostname, into binary IPv6 address.
 * Return TRUE if we succeed and set "*addrp" to that numeric IP address;
 * return FALSE if we fail.
 */
gboolean get_host_ipaddr6(const char *host, struct e_in6_addr *addrp)
{
	struct hostent *hp;

	if (inet_pton(AF_INET6, host, addrp) == 1)
		return TRUE;

	/* try FQDN */
#ifdef HAVE_GETHOSTBYNAME2
	hp = gethostbyname2(host, AF_INET6);
#else
	hp = NULL;
#endif
	if (hp != NULL && hp->h_length == sizeof(struct e_in6_addr)) {
		memcpy(addrp, hp->h_addr, hp->h_length);
		return TRUE;
	}

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
