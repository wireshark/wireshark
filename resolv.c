/* resolv.c
 * Routines for network object lookup
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 * To do:
 *
 * - Add ethernet address resolution
 * - In a future live capture and decode mode, 
 *   add hostname entries in hash table from DNS packet decoding.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef AVOID_DNS_TIMEOUT
#define AVOID_DNS_TIMEOUT
#endif

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>

#ifdef AVOID_DNS_TIMEOUT
# include <setjmp.h>
#endif

#include "packet.h"
#include "resolv.h"

#define MAXNAMELEN  	64	/* max name length (hostname and port name) */
#define HASHHOSTSIZE	1024
#define HASHPORTSIZE	256

/* hash table used for host and port lookup */

typedef struct hashname {
  u_int			addr;
  u_char   		name[MAXNAMELEN];
  struct hashname 	*next;
} hashname_t;

static hashname_t *host_table[HASHHOSTSIZE];
static hashname_t *udp_port_table[HASHPORTSIZE];
static hashname_t *tcp_port_table[HASHPORTSIZE];

/* global variable that indicates if name resolving is actif */

int g_resolving_actif = 1; 	/* routines are active by default */

/* local function definitions */

static u_char *serv_name_lookup(u_int port, u_int proto)
{

  hashname_t *tp;
  hashname_t **table;
  char *serv_proto = NULL;
  struct servent *servp;
  int i;

  switch(proto) {
  case IPPROTO_UDP:
    table = udp_port_table;
    serv_proto = "udp";
    break;
  case IPPROTO_TCP:
    table = tcp_port_table;
    serv_proto = "tcp";
    break;
  default:
    /* not yet implemented */
    return NULL;
    /*NOTREACHED*/
    break;
  } /* proto */
  
  i = port & (HASHPORTSIZE - 1);
  tp = table[ i & (HASHPORTSIZE - 1)];

  if( tp == NULL ) {
    tp = table[ i & (HASHPORTSIZE - 1)] = 
      (hashname_t *)g_malloc(sizeof(hashname_t));
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

  if ((servp = getservbyport(htons(port), serv_proto)) == NULL) {
    /* unknown port */
    sprintf(tp->name, "%d", port);
  } else {
    strncpy(tp->name, servp->s_name, MAXNAMELEN);
  }

  return (tp->name);

} /* serv_name_lookup */

#ifdef AVOID_DNS_TIMEOUT

#define DNS_TIMEOUT 	5 	/* max sec per call */

jmp_buf hostname_env;

static void abort_network_query(int sig)
{
  longjmp(hostname_env, 1);
}
#endif /* AVOID_DNS_TIMEOUT */

static u_char *host_name_lookup(u_int addr)
{

  hashname_t *tp;
  hashname_t **table = host_table;
  struct hostent *hostp;

  tp = table[ addr & (HASHHOSTSIZE - 1)];

  if( tp == NULL ) {
    tp = table[ addr & (HASHHOSTSIZE - 1)] = 
      (hashname_t *)g_malloc(sizeof(hashname_t));
  } else {  
    while(1) {
      if( tp->addr == addr ) {
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
      return tp->name;
    }
#ifdef AVOID_DNS_TIMEOUT
  }
#endif

  /* unknown host or DNS timeout */

  sprintf(tp->name, "%s", ip_to_str((guint8 *)&addr));  
  return (tp->name);

} /* host_name_lookup */

/* external functions */

extern u_char *get_hostname(u_int addr) 
{
  if (!g_resolving_actif)
    return ip_to_str((guint8 *)&addr);

  return host_name_lookup(addr);
}

extern u_char *get_udp_port(u_int port) 
{
  static gchar  str[3][MAXNAMELEN];
  static gchar *cur;

  if (!g_resolving_actif) {
    if (cur == &str[0][0]) {
      cur = &str[1][0];
    } else if (cur == &str[1][0]) {  
      cur = &str[2][0];
    } else {  
      cur = &str[0][0];
    }
    sprintf(cur, "%d", port);
    return cur;
  }

  return serv_name_lookup(port, IPPROTO_UDP);

} /* get_udp_port */


extern u_char *get_tcp_port(u_int port) 
{
  static gchar  str[3][MAXNAMELEN];
  static gchar *cur;

  if (!g_resolving_actif) {
    if (cur == &str[0][0]) {
      cur = &str[1][0];
    } else if (cur == &str[1][0]) {  
      cur = &str[2][0];
    } else {  
      cur = &str[0][0];
    }
    sprintf(cur, "%d", port);
    return cur;
  }

  return serv_name_lookup(port, IPPROTO_TCP);

} /* get_tcp_port */

