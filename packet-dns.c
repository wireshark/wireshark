/* packet-dns.c
 * Routines for DNS packet disassembly
 *
 * $Id: packet-dns.c,v 1.13 1999/01/04 09:13:46 guy Exp $
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

#include <stdio.h>
#include <string.h>
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
#include "util.h"


/* DNS structs and definitions */

/* Offsets of fields in the DNS header. */
#define	DNS_ID		0
#define	DNS_FLAGS	2
#define	DNS_QUEST	4
#define	DNS_ANS	6
#define	DNS_AUTH	8
#define	DNS_ADD	10

/* Length of DNS header. */
#define	DNS_HDRLEN	12

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

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_RCODE         (0xF<<0)        /* reply code */

/* Opcodes */
#define OPCODE_QUERY    (0<<11)         /* standard query */
#define OPCODE_IQUERY   (1<<11)         /* inverse query */
#define OPCODE_STATUS   (2<<11)         /* server status request */

/* Reply codes */
#define RCODE_NOERROR   (0<<0)
#define RCODE_FMTERROR  (1<<0)
#define RCODE_SERVFAIL  (2<<0)
#define RCODE_NAMEERROR (3<<0)
#define RCODE_NOTIMPL   (4<<0)
#define RCODE_REFUSED   (5<<0)

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
  
  start_off = cur_off;
  ti = add_item_to_tree(GTK_WIDGET(dns_tree), 
			start_off, 0, "Queries");
  qatree = gtk_tree_new();
  add_subtree(ti, qatree, ETT_DNS_QRY);
  while (count-- > 0)
    cur_off += dissect_dns_query(dns_data_ptr, pd, cur_off, qatree);
  set_item_len(ti, cur_off - start_off);

  return cur_off - start_off;
}



static int
dissect_answer_records(const u_char *dns_data_ptr, int count,
                       const u_char *pd, int cur_off, GtkWidget *dns_tree,
                       char *name)
{
  int start_off;
  GtkWidget *qatree, *ti;
  
  start_off = cur_off;
  ti = add_item_to_tree(GTK_WIDGET(dns_tree),
			start_off, 0, name);
  qatree = gtk_tree_new();
  add_subtree(ti, qatree, ETT_DNS_ANS);
  while (count-- > 0)
    cur_off += dissect_dns_answer(dns_data_ptr, pd, cur_off, qatree);
  set_item_len(ti, cur_off - start_off);

  return cur_off - start_off;
}


void
dissect_dns(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
  const u_char *dns_data_ptr;
  GtkWidget *dns_tree, *ti, *field_tree, *tf;
  guint16    id, flags, quest, ans, auth, add;
  char buf[128+1];
  int cur_off;
  static const value_string opcode_vals[] = {
		  { OPCODE_QUERY,  "Standard query"        },
		  { OPCODE_IQUERY, "Inverse query"         },
		  { OPCODE_STATUS, "Server status request" },
		  { 0,              NULL                   } };
  static const value_string rcode_vals[] = {
		  { RCODE_NOERROR,   "No error"        },
		  { RCODE_FMTERROR,  "Format error"    },
		  { RCODE_SERVFAIL,  "Server failure"  },
		  { RCODE_NAMEERROR, "Name error"      },
		  { RCODE_NOTIMPL,   "Not implemented" },
		  { RCODE_REFUSED,   "Refused"         },
		  { 0,               NULL              } };

  dns_data_ptr = &pd[offset];

  /* To do: check for runts, errs, etc. */
  id    = pntohs(&pd[offset + DNS_ID]);
  flags = pntohs(&pd[offset + DNS_FLAGS]);
  quest = pntohs(&pd[offset + DNS_QUEST]);
  ans   = pntohs(&pd[offset + DNS_ANS]);
  auth  = pntohs(&pd[offset + DNS_AUTH]);
  add   = pntohs(&pd[offset + DNS_ADD]);
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "DNS (UDP)");
  if (check_col(fd, COL_INFO)) {
    col_add_fstr(fd, COL_INFO, "%s%s",
                val_to_str(flags & F_OPCODE, opcode_vals,
                           "Unknown operation (%x)"),
                (flags & F_RESPONSE) ? " response" : "");
  }
  
  if (tree) {
    ti = add_item_to_tree(GTK_WIDGET(tree), offset, 4,
			  (flags & F_RESPONSE) ? "DNS response" : "DNS query");
    
    dns_tree = gtk_tree_new();
    add_subtree(ti, dns_tree, ETT_DNS);
    
    add_item_to_tree(dns_tree, offset + DNS_ID, 2, "Transaction ID: 0x%04x",
    			id);

    strcpy(buf, val_to_str(flags & F_OPCODE, opcode_vals, "Unknown (%x)"));
    if (flags & F_RESPONSE) {
      strcat(buf, " response");
      strcat(buf, ", ");
      strcat(buf, val_to_str(flags & F_RCODE, rcode_vals,
            "Unknown error (%x)"));
    }
    tf = add_item_to_tree(dns_tree, offset + DNS_FLAGS, 2, "Flags: 0x%04x (%s)",
                          flags, buf);
    field_tree = gtk_tree_new();
    add_subtree(tf, field_tree, ETT_DNS_FLAGS);
    add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_RESPONSE,
            2*8, "Response", "Query"));
    add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_enumerated_bitfield(flags, F_OPCODE,
            2*8, opcode_vals, "%s"));
    if (flags & F_RESPONSE) {
      add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
         decode_boolean_bitfield(flags, F_AUTHORITATIVE,
              2*8,
              "Server is an authority for domain",
              "Server isn't an authority for domain"));
    }
    add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_TRUNCATED,
            2*8,
            "Message is truncated",
            "Message is not truncated"));
    add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_RECDESIRED,
            2*8,
            "Do query recursively",
            "Don't do query recursively"));
    if (flags & F_RESPONSE) {
      add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
         decode_boolean_bitfield(flags, F_RECAVAIL,
              2*8,
              "Server can do recursive queries",
              "Server can't do recursive queries"));
      add_item_to_tree(field_tree, offset + DNS_FLAGS, 2, "%s",
         decode_enumerated_bitfield(flags, F_RCODE,
              2*8, rcode_vals, "%s"));
    }
    add_item_to_tree(dns_tree, offset + DNS_QUEST, 2, "Questions: %d", quest);
    add_item_to_tree(dns_tree, offset + DNS_ANS, 2, "Answer RRs: %d", ans);
    add_item_to_tree(dns_tree, offset + DNS_AUTH, 2, "Authority RRs: %d", auth);
    add_item_to_tree(dns_tree, offset + DNS_ADD, 2, "Additional RRs: %d", add);

    cur_off = offset + DNS_HDRLEN;
    
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
