/* packet-dns.c
 * Routines for DNS packet disassembly
 *
 * $Id: packet-dns.c,v 1.7 1998/10/15 06:40:50 guy Exp $
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>
#include <pcap.h>

#include <stdio.h>
#include <memory.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "packet-dns.h"


/* DNS structs and definitions */

typedef struct _e_dns {
  guint16 dns_id;
  guint16 dns_flags;
  guint16 dns_quest;
  guint16 dns_ans;
  guint16 dns_auth;
  guint16 dns_add;
} e_dns;

/* type values  */
#define T_A             1               /* host address */
#define T_NS            2               /* authoritative server */
#define T_CNAME         5               /* canonical name */
#define T_SOA           6               /* start of authority zone */
#define T_WKS           11              /* well known service */
#define T_PTR           12              /* domain name pointer */
#define T_HINFO         13              /* host information */
#define T_MX            15              /* mail routing information */
#define T_TXT           16              /* text strings */
#define T_AAAA          28              /* IP6 Address */


static char *
dns_type_name (int type)
{
  char *type_names[36] = {
    "unused", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR",
    "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB",
    "X25", "ISDN", "RT", "NSAP", "NSAP_PTR", "SIG", "KEY", "PX", "GPOS",
    "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR"
  };
  
  if (type <= 35)
    return type_names[type];
  
  /* special cases */
  switch (type) 
    {
      /* non standard  */
    case 100:
      return "UINFO";
    case 101:
      return "UID";
    case 102:
      return "GID";
    case 103:
      return "UNSPEC";
      
      /* queries  */
    case 251:
      return "IXFR";
    case 252:
      return "AXFR";
    case 253:
      return "MAILB";
    case 254:
      return "MAILA";
    case 255:
      return "ANY";
    }
  
  return "unknown";
}


char *
dns_class_name(int class)
{
  char *class_name;
  
  switch (class) {
  case 1:
    class_name = "inet";
    break;
  case 3:
    class_name = "chaos";
    break;
  case 4:
    class_name = "hesiod";
    break;
  default:
    class_name = "unknown";
  }

  return class_name;
}
  

static int
is_compressed_name(const u_char *foo)
{
  return (0xc0 == (*foo & 0xc0));
}


static int
get_compressed_name_offset(const u_char *ptr)
{
  return ((*ptr & ~0xc0) << 8) | *(ptr+1);
}


static int
copy_one_name_component(const u_char *dataptr, char *nameptr)
{
  int len;
  int n;
  
  len = n  = *dataptr++;
  if (0 == len)
    return 0;
  
  while (n-- > 0)
    *nameptr++ = *dataptr++;

  return len;
}


static int
copy_name_component_rec(const u_char *dns_data_ptr, const u_char *dataptr,
  char *nameptr, int *real_string_len)
{
  int len = 0;
  int str_len;
  int offset;
  int compress = 0;
  
  if (is_compressed_name(dataptr)) {
    compress = 1;
    offset = get_compressed_name_offset(dataptr);
    dataptr = dns_data_ptr + offset;
    copy_name_component_rec(dns_data_ptr, dataptr, nameptr, &str_len);
    *real_string_len += str_len;
    nameptr += str_len;
    len = 2;
  }
  else {
    str_len = copy_one_name_component(dataptr, nameptr);
    *real_string_len = str_len;
    dataptr += str_len + 1;
    len     += str_len + 1;
    nameptr += str_len;
  }

  if (compress)
    return len;
  
  (*real_string_len)++;

  if (*dataptr > 0) {
    *nameptr++ = '.';
    len += copy_name_component_rec(dns_data_ptr, dataptr, nameptr, &str_len);
    *real_string_len += str_len;
    return len;
  }

  return len + 1;
}


int
get_dns_name(const u_char *dns_data_ptr, const u_char *pd, int offset,
  char *nameptr, int maxname)
{
  int len;
  const u_char *dataptr = pd + offset;
  int str_len = 0;

  memset (nameptr, 0, maxname);
  len = copy_name_component_rec(dns_data_ptr, dataptr, nameptr, &str_len);
  
  return len;
}


static int
get_dns_name_type_class (const u_char *dns_data_ptr,
			 const u_char *pd,
			 int offset,
			 char *name_ret,
			 int *name_len_ret,
			 int *type_ret,
			 int *class_ret)
{
  int len;
  int name_len;
  int type;
  int class;
  char name[MAXDNAME];
  const u_char *pd_save;

  name_len = get_dns_name(dns_data_ptr, pd, offset, name, sizeof(name));
  pd += offset;
  pd_save = pd;
  pd += name_len;
  
  type = pntohs(pd);
  pd += 2;
  class = pntohs(pd);
  pd += 2;

  strcpy (name_ret, name);
  *type_ret = type;
  *class_ret = class;
  *name_len_ret = name_len;

  len = pd - pd_save;
  return len;
}


static int
dissect_dns_query(const u_char *dns_data_ptr, const u_char *pd, int offset,
  GtkWidget *dns_tree)
{
  int len;
  char name[MAXDNAME];
  int name_len;
  int type;
  int class;
  char *class_name;
  char *type_name;
  const u_char *dptr;
  const u_char *data_start;
  GtkWidget *q_tree, *tq;

  data_start = dptr = pd + offset;

  len = get_dns_name_type_class(dns_data_ptr, pd, offset, name, &name_len,
    &type, &class);
  dptr += len;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);

  tq = add_item_to_tree(dns_tree, offset, len, "%s: type %s, class %s", 
		   name, type_name, class_name);
  q_tree = gtk_tree_new();
  add_subtree(tq, q_tree, ETT_DNS_QD);

  add_item_to_tree(q_tree, offset, name_len, "Name: %s", name);
  offset += name_len;

  add_item_to_tree(q_tree, offset, 2, "Type: %s", type_name);
  offset += 2;

  add_item_to_tree(q_tree, offset, 2, "Class: %s", class_name);
  offset += 2;
  
  return dptr - data_start;
}


GtkWidget *
add_rr_to_tree(GtkWidget *trr, int rr_type, int offset, const char *name,
  int namelen, const char *type_name, const char *class_name, u_int ttl,
  u_short data_len)
{
  GtkWidget *rr_tree;

  rr_tree = gtk_tree_new();
  add_subtree(trr, rr_tree, rr_type);
  add_item_to_tree(rr_tree, offset, namelen, "Name: %s", name);
  offset += namelen;
  add_item_to_tree(rr_tree, offset, 2, "Type: %s", type_name);
  offset += 2;
  add_item_to_tree(rr_tree, offset, 2, "Class: %s", class_name);
  offset += 2;
  add_item_to_tree(rr_tree, offset, 4, "Time to live: %u", ttl);
  offset += 4;
  add_item_to_tree(rr_tree, offset, 2, "Data length: %u", data_len);
  return rr_tree;
}

static int
dissect_dns_answer(const u_char *dns_data_ptr, const u_char *pd, int offset,
  GtkWidget *dns_tree)
{
  int len;
  char name[MAXDNAME];
  int name_len;
  int type;
  int class;
  char *class_name;
  char *type_name;
  const u_char *dptr;
  const u_char *data_start;
  u_int ttl;
  u_short data_len;
  GtkWidget *rr_tree, *trr;

  data_start = dptr = pd + offset;

  len = get_dns_name_type_class(dns_data_ptr, pd, offset, name, &name_len,
    &type, &class);
  dptr += len;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);

  ttl = pntohl(dptr);
  dptr += 4;

  data_len = pntohs(dptr);
  dptr += 2;

  switch (type) {
  case T_A: 		/* "A" record */
    trr = add_item_to_tree(dns_tree, offset, (dptr - data_start) + data_len,
		     "%s: type %s, class %s, addr %s",
		     name, type_name, class_name,
		     ip_to_str((guint8 *)dptr));
    rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len, type_name,
                     class_name, ttl, data_len);
    offset += (dptr - data_start);
    add_item_to_tree(rr_tree, offset, 4, "Addr: %s",
                     ip_to_str((guint8 *)dptr));
    break;

  case T_NS: 		/* "NS" record */
    {
      char ns_name[MAXDNAME];
      int ns_name_len;
      
      ns_name_len = get_dns_name(dns_data_ptr, dptr, 0, ns_name, sizeof(ns_name));
      trr = add_item_to_tree(dns_tree, offset, (dptr - data_start) + data_len,
		       "%s: type %s, class %s, ns %s",
		       name, type_name, class_name, ns_name);
      rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                       type_name, class_name, ttl, data_len);
      offset += (dptr - data_start);
      add_item_to_tree(rr_tree, offset, ns_name_len, "Name server: %s", ns_name);
    }
    break;

    /* TODO: parse more record types */
      
  default:
    trr = add_item_to_tree(dns_tree, offset, (dptr - data_start) + data_len,
                     "%s: type %s, class %s",
		     name, type_name, class_name);
    rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len, type_name,
                       class_name, ttl, data_len);
    offset += (dptr - data_start);
    add_item_to_tree(rr_tree, offset, data_len, "Data");
  }
  
  dptr += data_len;
	
  return dptr - data_start;
}

static int
dissect_query_records(const u_char *dns_data_ptr, int count, const u_char *pd, 
		      int cur_off, GtkWidget *dns_tree)
{
  int start_off;
  GtkWidget *qatree, *ti;
  
  qatree = gtk_tree_new();
  start_off = cur_off;
  
  while (count-- > 0)
    cur_off += dissect_dns_query(dns_data_ptr, pd, cur_off, qatree);
  ti = add_item_to_tree(GTK_WIDGET(dns_tree), 
			start_off, cur_off - start_off, "Queries");
  add_subtree(ti, qatree, ETT_DNS_QRY);

  return cur_off - start_off;
}



static int
dissect_answer_records(const u_char *dns_data_ptr, int count,
                       const u_char *pd, int cur_off, GtkWidget *dns_tree,
                       char *name)
{
  int start_off;
  GtkWidget *qatree, *ti;
  
  qatree = gtk_tree_new();
  start_off = cur_off;

  while (count-- > 0)
    cur_off += dissect_dns_answer(dns_data_ptr, pd, cur_off, qatree);
  ti = add_item_to_tree(GTK_WIDGET(dns_tree), start_off, cur_off - start_off, name);
  add_subtree(ti, qatree, ETT_DNS_ANS);

  return cur_off - start_off;
}


void
dissect_dns(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  const u_char *dns_data_ptr;
  e_dns     *dh;
  GtkWidget *dns_tree, *ti;
  guint16    id, flags, quest, ans, auth, add;
  int query = 0;
  int cur_off;

  dns_data_ptr = &pd[offset];
  dh = (e_dns *) dns_data_ptr;

  /* To do: check for runts, errs, etc. */
  id    = ntohs(dh->dns_id);
  flags = ntohs(dh->dns_flags);
  quest = ntohs(dh->dns_quest);
  ans   = ntohs(dh->dns_ans);
  auth  = ntohs(dh->dns_auth);
  add   = ntohs(dh->dns_add);
  
  query = ! (flags & (1 << 15));
  
  if (fd->win_info[COL_NUM]) {    
    strcpy(fd->win_info[COL_PROTOCOL], "DNS (UDP)");
    strcpy(fd->win_info[COL_INFO], query ? "Query" : "Response");
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 4,
			  query ? "DNS query" : "DNS response");
    
    dns_tree = gtk_tree_new();
    add_subtree(ti, dns_tree, ETT_DNS);
    
    add_item_to_tree(dns_tree, offset,      2, "ID: 0x%04x", id);

    add_item_to_tree(dns_tree, offset +  2, 2, "Flags: 0x%04x", flags);
    add_item_to_tree(dns_tree, offset +  4, 2, "Questions: %d", quest);
    add_item_to_tree(dns_tree, offset +  6, 2, "Answer RRs: %d", ans);
    add_item_to_tree(dns_tree, offset +  8, 2, "Authority RRs: %d", auth);
    add_item_to_tree(dns_tree, offset + 10, 2, "Additional RRs: %d", add);

    cur_off = offset + 12;
    
    if (quest > 0)
      cur_off += dissect_query_records(dns_data_ptr, quest, pd, cur_off,
					dns_tree);
    
    if (ans > 0)
      cur_off += dissect_answer_records(dns_data_ptr, ans, pd, cur_off,
          dns_tree, "Answers");
    
    if (auth > 0)
      cur_off += dissect_answer_records(dns_data_ptr, auth, pd, cur_off,
          dns_tree, "Authoritative nameservers");

    if (add > 0)
      cur_off += dissect_answer_records(dns_data_ptr, add, pd, cur_off,
          dns_tree, "Additional records");
  }
}
