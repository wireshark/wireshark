/* resolv.c
 * Routines for network object lookup
 *
 * $Id: resolv.c,v 1.20 2002/01/13 20:35:10 guy Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#ifndef AVOID_DNS_TIMEOUT
#define AVOID_DNS_TIMEOUT
#endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
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
#include <sys/socket.h>
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

#include "packet.h"
#include "ipv6-utils.h"
#include "resolv.h"
#include "filesystem.h"

#define ENAME_ETHERS 		"ethers"
#define ENAME_IPXNETS 		"ipxnets"
#define ENAME_MANUF		"manuf"

#define MAXMANUFLEN	9	/* max vendor name length with ending '\0' */
#define HASHETHSIZE	1024
#define HASHHOSTSIZE	1024
#define HASHIPXNETSIZE	256
#define HASHMANUFSIZE   256
#define HASHPORTSIZE	256

/* hash table used for host and port lookup */

#define HASH_IPV4_ADDRESS(addr)	((addr) & (HASHHOSTSIZE - 1))

#define HASH_PORT(port)	((port) & (HASHPORTSIZE - 1))

typedef struct hashname {
  guint			addr;
  guchar   		name[MAXNAMELEN];
  gboolean              is_dummy_entry;	/* name is IP address in dot format */
  struct hashname 	*next;
} hashname_t;

/* hash table used for IPX network lookup */

/* XXX - check goodness of hash function */

#define HASH_IPX_NET(net)	((net) & (HASHIPXNETSIZE - 1))

typedef struct hashname hashipxnet_t;

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

static hashname_t 	*host_table[HASHHOSTSIZE];
static hashname_t 	*udp_port_table[HASHPORTSIZE];
static hashname_t 	*tcp_port_table[HASHPORTSIZE];
static hashname_t       *sctp_port_table[HASHPORTSIZE];
static hashether_t 	*eth_table[HASHETHSIZE];
static hashmanuf_t 	*manuf_table[HASHMANUFSIZE];
static hashipxnet_t 	*ipxnet_table[HASHIPXNETSIZE];

static int 		eth_resolution_initialized = 0;
static int 		ipxnet_resolution_initialized = 0;

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

/*
 *  Local function definitions 
 */

static guchar *serv_name_lookup(guint port, port_type proto)
{
  int hash_idx;
  hashname_t *tp;
  hashname_t **table;
  char *serv_proto = NULL;
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
    tp = table[hash_idx] = (hashname_t *)g_malloc(sizeof(hashname_t));
  } else {  
    while(1) {
      if( tp->addr == port ) {
	return tp->name;
      }
      if (tp->next == NULL) {
	tp->next = (hashname_t *)g_malloc(sizeof(hashname_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }
  
  /* fill in a new entry */
  tp->addr = port;
  tp->next = NULL;

  if (!(g_resolv_flags & RESOLV_TRANSPORT) || 
      (servp = getservbyport(htons(port), serv_proto)) == NULL) {
    /* unknown port */
    sprintf(tp->name, "%d", port);
  } else {
    strncpy(tp->name, servp->s_name, MAXNAMELEN);
    tp->name[MAXNAMELEN-1] = '\0';
  }

  return (tp->name);

} /* serv_name_lookup */

#ifdef AVOID_DNS_TIMEOUT

#define DNS_TIMEOUT 	2 	/* max sec per call */

jmp_buf hostname_env;

static void abort_network_query(int sig)
{
  longjmp(hostname_env, 1);
}
#endif /* AVOID_DNS_TIMEOUT */

static guchar *host_name_lookup(guint addr, gboolean *found)
{
  int hash_idx;
  hashname_t * volatile tp;
  struct hostent *hostp;

  *found = TRUE;

  hash_idx = HASH_IPV4_ADDRESS(addr);

  tp = host_table[hash_idx];

  if( tp == NULL ) {
    tp = host_table[hash_idx] = (hashname_t *)g_malloc(sizeof(hashname_t));
  } else {  
    while(1) {
      if( tp->addr == addr ) {
	if (tp->is_dummy_entry)
	  *found = FALSE;
	return tp->name;
      }
      if (tp->next == NULL) {
	tp->next = (hashname_t *)g_malloc(sizeof(hashname_t));
	tp = tp->next;
	break;
      }
      tp = tp->next;
    }
  }
  
  /* fill in a new entry */
  tp->addr = addr;
  tp->next = NULL;

  /*
   * The Windows "gethostbyaddr()" insists on translating 0.0.0.0 to
   * the name of the host on which it's running; to work around that
   * botch, we don't try to translate an all-zero IP address to a host
   * name.
   */
  if (addr != 0 && (g_resolv_flags & RESOLV_NETWORK)) {
#ifdef AVOID_DNS_TIMEOUT
    
    /* Quick hack to avoid DNS/YP timeout */
  
    if (!setjmp(hostname_env)) {
      signal(SIGALRM, abort_network_query);
      alarm(DNS_TIMEOUT);
#endif
      hostp = gethostbyaddr((char *)&addr, 4, AF_INET);
#ifdef AVOID_DNS_TIMEOUT
      alarm(0);
#endif
      if (hostp != NULL) {
	strncpy(tp->name, hostp->h_name, MAXNAMELEN);
	tp->name[MAXNAMELEN-1] = '\0';
	tp->is_dummy_entry = FALSE;
	return tp->name;
      }
#ifdef AVOID_DNS_TIMEOUT
    }
#endif
  }

  /* unknown host or DNS timeout */

  ip_to_str_buf((guint8 *)&addr, tp->name);
  tp->is_dummy_entry = TRUE;
  *found = FALSE;

  return (tp->name);

} /* host_name_lookup */

static guchar *host_name_lookup6(struct e_in6_addr *addr, gboolean *found)
{
  static guchar name[MAXNAMELEN];
#ifdef INET6
  struct hostent *hostp;

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
#endif
      if (hostp != NULL) {
	strncpy(name, hostp->h_name, MAXNAMELEN);
	name[MAXNAMELEN-1] = '\0';
	*found = TRUE;
	return name;
      }
#ifdef AVOID_DNS_TIMEOUT
    }
#endif
  }

  /* unknown host or DNS timeout */
#endif /* INET6 */
  *found = FALSE;
  sprintf(name, "%s", ip6_to_str(addr));  
  return (name);
}

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


static int parse_ether_line(char *line, ether_t *eth, int six_bytes)
{
  /*
   *  See man ethers(4) for ethers file format
   *  (not available on all systems).
   *  We allow both ethernet address separators (':' and '-'),
   *  as well as Ethereal's '.' separator.
   */

  gchar *cp;
  int a0, a1, a2, a3, a4, a5;
    
  if ((cp = strchr(line, '#')))
    *cp = '\0';
  
  if ((cp = strtok(line, " \t\n")) == NULL)
    return -1;

  if (six_bytes) {
    if (sscanf(cp, "%x:%x:%x:%x:%x:%x", &a0, &a1, &a2, &a3, &a4, &a5) != 6) {
      if (sscanf(cp, "%x-%x-%x-%x-%x-%x", &a0, &a1, &a2, &a3, &a4, &a5) != 6) {
        if (sscanf(cp, "%x.%x.%x.%x.%x.%x", &a0, &a1, &a2, &a3, &a4, &a5) != 6)
	  return -1;
      }
    }
  } else {
    if (sscanf(cp, "%x:%x:%x", &a0, &a1, &a2) != 3) {
      if (sscanf(cp, "%x-%x-%x", &a0, &a1, &a2) != 3) {
        if (sscanf(cp, "%x.%x.%x", &a0, &a1, &a2) != 3)
	return -1;
      }
    }
  }

  if ((cp = strtok(NULL, " \t\n")) == NULL)
    return -1;

  eth->addr[0] = a0;
  eth->addr[1] = a1;
  eth->addr[2] = a2;
  if (six_bytes) {
    eth->addr[3] = a3;
    eth->addr[4] = a4;
    eth->addr[5] = a5;
  } else {
    eth->addr[3] = 0;
    eth->addr[4] = 0;
    eth->addr[5] = 0;
  }

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

static ether_t *get_ethent(int six_bytes)
{
 
  static ether_t eth;
  static int     size = 0;
  static char   *buf = NULL;
  
  if (eth_p == NULL) 
    return NULL;

  while (fgetline(&buf, &size, eth_p) >= 0) {
    if (parse_ether_line(buf, &eth, six_bytes) == 0) {
      return &eth;
    }
  }
    
  return NULL;

} /* get_ethent */

static ether_t *get_ethbyname(const guchar *name)
{
  ether_t *eth;
  
  set_ethent(g_ethers_path);

  while ((eth = get_ethent(1)) && strncmp(name, eth->name, MAXNAMELEN) != 0)
    ;

  if (eth == NULL) {
    end_ethent();
    
    set_ethent(g_pethers_path);

    while ((eth = get_ethent(1)) && strncmp(name, eth->name, MAXNAMELEN) != 0)
      ;

    end_ethent();
  }

  return eth;

} /* get_ethbyname */

static ether_t *get_ethbyaddr(const guint8 *addr)
{

  ether_t *eth;
  
  set_ethent(g_ethers_path);

  while ((eth = get_ethent(1)) && memcmp(addr, eth->addr, 6) != 0)
    ;

  if (eth == NULL) {
    end_ethent();
    
    set_ethent(g_pethers_path);
    
    while ((eth = get_ethent(1)) && memcmp(addr, eth->addr, 6) != 0)
      ;
    
    end_ethent();
  }

  return eth;

} /* get_ethbyaddr */

static void add_manuf_name(guint8 *addr, guchar *name)
{
  int hash_idx;
  hashmanuf_t *tp;

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

static void initialize_ethers(void)
{
  ether_t *eth;
  char *manuf_path;

  /* Compute the pathname of the ethers file. */
  if (g_ethers_path == NULL) {
    g_ethers_path = g_malloc(strlen(get_systemfile_dir()) +
			     strlen(ENAME_ETHERS) + 2);
    sprintf(g_ethers_path, "%s" G_DIR_SEPARATOR_S "%s",
	    get_systemfile_dir(), ENAME_ETHERS);
  }

  /* Set g_pethers_path here, but don't actually do anything
   * with it. It's used in get_ethbyname() and get_ethbyaddr()
   */
  if (g_pethers_path == NULL)
    g_pethers_path = get_persconffile_path(ENAME_ETHERS, FALSE);

  /* manuf hash table initialization */

  /* Compute the pathname of the manuf file */
  manuf_path = (gchar *) g_malloc(strlen(get_datafile_dir()) +
    strlen(ENAME_MANUF) + 2);
  sprintf(manuf_path, "%s" G_DIR_SEPARATOR_S "%s", get_datafile_dir(),
    ENAME_MANUF);
  
  /* Read it and initialize the hash table */
  set_ethent(manuf_path);

  while ((eth = get_ethent(0))) {
    add_manuf_name(eth->addr, eth->name);
  }

  end_ethent();

  g_free(manuf_path);

} /* initialize_ethers */

static hashether_t *add_eth_name(const guint8 *addr, const guchar *name)
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

static guchar *eth_name_lookup(const guint8 *addr)
{
  int hash_idx;
  hashmanuf_t *manufp;
  hashether_t *tp;
  ether_t *eth;

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
    /* unknown name */

    if ((manufp = manuf_name_lookup(addr)) == NULL)
      sprintf(tp->name, "%s", ether_to_str((guint8 *)addr));
    else
      sprintf(tp->name, "%s_%02x:%02x:%02x", 
	      manufp->name, addr[3], addr[4], addr[5]);

    tp->is_dummy_entry = TRUE;

  } else {
    strncpy(tp->name, eth->name, MAXNAMELEN);
    tp->name[MAXNAMELEN-1] = '\0';
    tp->is_dummy_entry = FALSE;
  }

  return (tp->name);

} /* eth_name_lookup */

static guint8 *eth_addr_lookup(const guchar *name)
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

static ipxnet_t *get_ipxnetbyname(const guchar *name)
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
    g_ipxnets_path = g_malloc(strlen(get_systemfile_dir()) +
			      strlen(ENAME_IPXNETS) + 2);
    sprintf(g_ipxnets_path, "%s" G_DIR_SEPARATOR_S "%s",
	    get_systemfile_dir(), ENAME_IPXNETS);
  }

  /* Set g_pipxnets_path here, but don't actually do anything
   * with it. It's used in get_ipxnetbyname() and get_ipxnetbyaddr()
   */
  if (g_pipxnets_path == NULL)
    g_pipxnets_path = get_persconffile_path(ENAME_IPXNETS, FALSE);

} /* initialize_ipxnets */

static hashipxnet_t *add_ipxnet_name(guint addr, const guchar *name)
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

static guchar *ipxnet_name_lookup(const guint addr)
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
      sprintf(tp->name, "%X", addr);

  } else {
    strncpy(tp->name, ipxnet->name, MAXNAMELEN);
    tp->name[MAXNAMELEN-1] = '\0';
  }

  return (tp->name);

} /* ipxnet_name_lookup */

static guint ipxnet_addr_lookup(const guchar *name, gboolean *success)
{
  ipxnet_t *ipxnet;
  hashipxnet_t *tp;
  hashipxnet_t **table = ipxnet_table;
  int i;

  /* to be optimized (hash table from name to addr) */
  for (i = 0; i < HASHIPXNETSIZE; i++) {
    tp = table[i];
    while (tp) {
      if (strcmp(tp->name, name) == 0)
	return tp->addr;
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


/* 
 *  External Functions
 */

extern guchar *get_hostname(guint addr) 
{
  gboolean found;

  if (!(g_resolv_flags & RESOLV_NETWORK))
    return ip_to_str((guint8 *)&addr);

  return host_name_lookup(addr, &found);
}

extern const guchar *get_hostname6(struct e_in6_addr *addr)
{
  gboolean found;

#ifdef INET6
  if (!(g_resolv_flags & RESOLV_NETWORK))
    return ip6_to_str(addr);
  if (IN6_IS_ADDR_LINKLOCAL(addr) || IN6_IS_ADDR_MULTICAST(addr))
    return ip6_to_str(addr);
#endif

  return host_name_lookup6(addr, &found);
}

extern void add_host_name(guint addr, const guchar *name)
{
  int hash_idx;
  hashname_t *tp;

  hash_idx = HASH_IPV4_ADDRESS(addr);

  tp = host_table[hash_idx];

  if( tp == NULL ) {
    tp = host_table[hash_idx] = (hashname_t *)g_malloc(sizeof(hashname_t));
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
	tp->next = (hashname_t *)g_malloc(sizeof(hashname_t));
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

} /* add_host_name */

extern guchar *get_udp_port(guint port)
{
  static gchar  str[3][MAXNAMELEN];
  static gchar *cur;

  if (!(g_resolv_flags & RESOLV_TRANSPORT)) {
    if (cur == &str[0][0]) {
      cur = &str[1][0];
    } else if (cur == &str[1][0]) {  
      cur = &str[2][0];
    } else {  
      cur = &str[0][0];
    }
    sprintf(cur, "%u", port);
    return cur;
  }

  return serv_name_lookup(port, PT_UDP);

} /* get_udp_port */

extern guchar *get_tcp_port(guint port) 
{
  static gchar  str[3][MAXNAMELEN];
  static gchar *cur;

  if (!(g_resolv_flags & RESOLV_TRANSPORT)) {
    if (cur == &str[0][0]) {
      cur = &str[1][0];
    } else if (cur == &str[1][0]) {  
      cur = &str[2][0];
    } else {  
      cur = &str[0][0];
    }
    sprintf(cur, "%u", port);
    return cur;
  }

  return serv_name_lookup(port, PT_TCP);

} /* get_tcp_port */

extern guchar *get_sctp_port(guint port) 
{
  static gchar  str[3][MAXNAMELEN];
  static gchar *cur;

  if (!(g_resolv_flags & RESOLV_TRANSPORT)) {
    if (cur == &str[0][0]) {
      cur = &str[1][0];
    } else if (cur == &str[1][0]) {  
      cur = &str[2][0];
    } else {  
      cur = &str[0][0];
    }
    sprintf(cur, "%u", port);
    return cur;
  }

  return serv_name_lookup(port, PT_SCTP);

} /* get_sctp_port */

extern guchar *get_ether_name(const guint8 *addr)
{
  if (!(g_resolv_flags & RESOLV_MAC))
    return ether_to_str((guint8 *)addr);

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
guchar *get_ether_name_if_known(const guint8 *addr)
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


extern guint8 *get_ether_addr(const guchar *name)
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

  guchar *host;
  gboolean found;

  /* first check that IP address can be resolved */

  if ((host = host_name_lookup(ip, &found)) == NULL)
    return;
  
  /* ok, we can add this entry in the ethers hashtable */

  if (found)
    add_eth_name(eth, host);

} /* add_ether_byip */

extern const guchar *get_ipxnet_name(const guint32 addr)
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

extern guint32 get_ipxnet_addr(const guchar *name, gboolean *known)
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

extern const guchar *get_manuf_name(const guint8 *addr)
{
  static gchar  str[3][MAXMANUFLEN];
  static gchar *cur;
  hashmanuf_t  *manufp;

  if ((g_resolv_flags & RESOLV_MAC) && !eth_resolution_initialized) {
    initialize_ethers();
    eth_resolution_initialized = 1;
  }

  if (!(g_resolv_flags & RESOLV_MAC) || ((manufp = manuf_name_lookup(addr)) == NULL)) {
    if (cur == &str[0][0]) {
      cur = &str[1][0];
    } else if (cur == &str[1][0]) {  
      cur = &str[2][0];
    } else {  
      cur = &str[0][0];
    }
    sprintf(cur, "%02x:%02x:%02x", addr[0], addr[1], addr[2]);
    return cur;
  }
  
  return manufp->name;

} /* get_manuf_name */



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
	}

	*addrp = ntohl(ipaddr.s_addr);
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
