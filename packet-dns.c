/* packet-dns.c
 * Routines for DNS packet disassembly
 *
 * $Id: packet-dns.c,v 1.19 1999/07/07 22:51:41 gram Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <glib.h>
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
#define T_NS            2               /* authoritative name server */
#define T_MD            3               /* mail destination (obsolete) */
#define T_MF            4               /* mail forwarder (obsolete) */
#define T_CNAME         5               /* canonical name */
#define T_SOA           6               /* start of authority zone */
#define T_MB            7               /* mailbox domain name (experimental) */
#define T_MG            8               /* mail group member (experimental) */
#define T_MR            9               /* mail rename domain name (experimental) */
#define T_NULL          10              /* null RR (experimental) */
#define T_WKS           11              /* well known service */
#define T_PTR           12              /* domain name pointer */
#define T_HINFO         13              /* host information */
#define T_MINFO         14              /* mailbox or mail list information */
#define T_MX            15              /* mail routing information */
#define T_TXT           16              /* text strings */
#define T_RP            17              /* responsible person (RFC 1183) */
#define T_AFSDB         18              /* AFS data base location (RFC 1183) */
#define T_X25           19              /* X.25 address (RFC 1183) */
#define T_ISDN          20              /* ISDN address (RFC 1183) */
#define T_RT            21              /* route-through (RFC 1183) */
#define T_NSAP          22              /* OSI NSAP (RFC 1706) */
#define T_NSAP_PTR      23              /* PTR equivalent for OSI NSAP (RFC 1348 - obsolete) */
#define T_SIG           24              /* digital signature (RFC 2065) */
#define T_KEY           25              /* public key (RFC 2065) */
#define T_PX            26              /* pointer to X.400/RFC822 mapping info (RFC 1664) */
#define T_GPOS          27              /* geographical position (RFC 1712) */
#define T_AAAA          28              /* IPv6 address (RFC 1886) */
#define T_LOC           29              /* geographical location (RFC 1876) */
#define T_NXT           30              /* "next" name (RFC 2065) */
#define T_EID           31              /* ??? (Nimrod?) */
#define T_NIMLOC        32              /* ??? (Nimrod?) */
#define T_SRV           33              /* service location (RFC 2052) */
#define T_ATMA          34              /* ??? */
#define T_NAPTR         35              /* naming authority pointer (RFC 2168) */

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

/* See RFC 1035 for all RR types for which no RFC is listed. */
static char *
dns_type_name (int type)
{
  char *type_names[36] = {
    "unused",
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT",
    "RP",				/* RFC 1183 */
    "AFSDB",				/* RFC 1183 */
    "X25",				/* RFC 1183 */
    "ISDN",				/* RFC 1183 */
    "RT",				/* RFC 1183 */
    "NSAP",				/* RFC 1706 */
    "NSAP-PTR",				/* RFC 1348 */
    "SIG",				/* RFC 2065 */
    "KEY",				/* RFC 2065 */
    "PX",				/* RFC 1664 */
    "GPOS",				/* RFC 1712 */
    "AAAA",				/* RFC 1886 */
    "LOC",				/* RFC 1876 */
    "NXT",				/* RFC 2065 */
    "EID",
    "NIMLOC",
    "SRV",				/* RFC 2052 */
    "ATMA",
    "NAPTR"				/* RFC 2168 */
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
      return "IXFR";	/* RFC 1995 */
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


static char *
dns_long_type_name (int type)
{
  char *type_names[36] = {
    "unused",
    "Host address",
    "Authoritative name server",	
    "Mail destination",
    "Mail forwarder",
    "Canonical name for an alias",
    "Start of zone of authority",
    "Mailbox domain name",
    "Mail group member",
    "Mail rename domain name",
    "Null resource record",
    "Well-known service description",
    "Domain name pointer",
    "Host information",
    "Mailbox or mail list information",
    "Mail exchange",
    "Text strings",
    "Responsible person",		/* RFC 1183 */
    "AFS data base location",		/* RFC 1183 */
    "X.25 address",			/* RFC 1183 */
    "ISDN number",			/* RFC 1183 */
    "Route through",			/* RFC 1183 */
    "OSI NSAP",				/* RFC 1706 */
    "OSI NSAP name pointer",		/* RFC 1348 */
    "Signature",			/* RFC 2065 */
    "Public key",			/* RFC 2065 */
    "Pointer to X.400/RFC822 mapping info", /* RFC 1664 */
    "Geographical position",		/* RFC 1712 */
    "IPv6 address",			/* RFC 1886 */
    "Location",				/* RFC 1876 */
    "Next",				/* RFC 2065 */
    "EID",
    "NIMLOC",
    "Service location",			/* RFC 2052 */
    "ATMA",
    "Naming authority pointer"		/* RFC 2168 */
  };
  static char unkbuf[7+1+2+1+4+1+1+10+1+1];	/* "Unknown RR type (%d)" */
  
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
      return "Request for incremental zone transfer";	/* RFC 1995 */
    case 252:
      return "Request for full zone transfer";
    case 253:
      return "Request for mailbox-related records";
    case 254:
      return "Request for mail agent resource records";
    case 255:
      return "Request for all records";
    }
  
  sprintf(unkbuf, "Unknown RR type (%d)", type);
  return unkbuf;
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

int
get_dns_name(const u_char *dns_data_ptr, const u_char *dptr, char *name,
    int maxname)
{
  const u_char *dp = dptr;
  char *np = name;
  int len = -1;
  u_int component_len;
  int offset;

  maxname--;	/* reserve space for the trailing '\0' */
  while ((component_len = *dp++) != 0) {
    switch (component_len & 0xc0) {

    case 0x00:
      /* Label */
      if (np != name) {
      	/* Not the first component - put in a '.'. */
        if (maxname > 0) {
          *np++ = '.';
          maxname--;
        }
      }
      while (component_len > 0) {
        if (maxname > 0) {
          *np++ = *dp;
          maxname--;
        }
      	component_len--;
      	dp++;
      }
      break;

    case 0x40:
    case 0x80:
      goto error;	/* error */

    case 0xc0:
      /* Pointer. */
      /* XXX - check to make sure we aren't looping, by keeping track
         of how many characters are in the DNS packet, and of how many
         characters we've looked at, and quitting if the latter
         becomes bigger than the former. */
      offset = ((component_len & ~0xc0) << 8) | *dp++;
      /* If "len" is negative, we are still working on the original name,
         not something pointed to by a pointer, and so we should set "len"
         to the length of the original name. */
      if (len < 0)
        len = dp - dptr;
      dp = dns_data_ptr + offset;
      break;	/* now continue processing from there */
    }
  }
        
error:
  *np = '\0';
  /* If "len" is negative, we haven't seen a pointer, and thus haven't
     set the length, so set it. */
  if (len < 0)
    len = dp - dptr;
  /* Zero-length name means "root server" */
  if (*name == '\0')
    strcpy(name, "<Root>");
  return len;
}


static int
get_dns_name_type_class (const u_char *dns_data_ptr,
			 const u_char *dptr,
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
  const u_char *dptr_save;

  name_len = get_dns_name(dns_data_ptr, dptr, name, sizeof(name));
  dptr_save = dptr;
  dptr += name_len;
  
  type = pntohs(dptr);
  dptr += 2;
  class = pntohs(dptr);
  dptr += 2;

  strcpy (name_ret, name);
  *type_ret = type;
  *class_ret = class;
  *name_len_ret = name_len;

  len = dptr - dptr_save;
  return len;
}


static int
dissect_dns_query(const u_char *dns_data_ptr, const u_char *pd, int offset,
  proto_tree *dns_tree)
{
  int len;
  char name[MAXDNAME];
  int name_len;
  int type;
  int class;
  char *class_name;
  char *type_name;
  char *long_type_name;
  const u_char *dptr;
  const u_char *data_start;
  proto_tree *q_tree;
  proto_item *tq;

  data_start = dptr = pd + offset;

  len = get_dns_name_type_class(dns_data_ptr, dptr, name, &name_len,
    &type, &class);
  dptr += len;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);
  long_type_name = dns_long_type_name(type);

  tq = proto_tree_add_text(dns_tree, offset, len, "%s: type %s, class %s", 
		   name, type_name, class_name);
  q_tree = proto_item_add_subtree(tq, ETT_DNS_QD);

  proto_tree_add_text(q_tree, offset, name_len, "Name: %s", name);
  offset += name_len;

  proto_tree_add_text(q_tree, offset, 2, "Type: %s", long_type_name);
  offset += 2;

  proto_tree_add_text(q_tree, offset, 2, "Class: %s", class_name);
  offset += 2;
  
  return dptr - data_start;
}


proto_tree *
add_rr_to_tree(proto_item *trr, int rr_type, int offset, const char *name,
  int namelen, const char *type_name, const char *class_name, u_int ttl,
  u_short data_len)
{
  proto_tree *rr_tree;

  rr_tree = proto_item_add_subtree(trr, rr_type);
  proto_tree_add_text(rr_tree, offset, namelen, "Name: %s", name);
  offset += namelen;
  proto_tree_add_text(rr_tree, offset, 2, "Type: %s", type_name);
  offset += 2;
  proto_tree_add_text(rr_tree, offset, 2, "Class: %s", class_name);
  offset += 2;
  proto_tree_add_text(rr_tree, offset, 4, "Time to live: %s",
						time_secs_to_str(ttl));
  offset += 4;
  proto_tree_add_text(rr_tree, offset, 2, "Data length: %u", data_len);
  return rr_tree;
}

static int
dissect_dns_answer(const u_char *dns_data_ptr, const u_char *pd, int offset,
  proto_tree *dns_tree)
{
  int len;
  char name[MAXDNAME];
  int name_len;
  int type;
  int class;
  char *class_name;
  char *type_name;
  char *long_type_name;
  const u_char *dptr;
  const u_char *data_start;
  u_int ttl;
  u_short data_len;
  proto_tree *rr_tree;
  proto_item *trr;
  const u_char *rrptr;

  data_start = dptr = pd + offset;

  len = get_dns_name_type_class(dns_data_ptr, dptr, name, &name_len,
    &type, &class);
  dptr += len;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);
  long_type_name = dns_long_type_name(type);

  ttl = pntohl(dptr);
  dptr += 4;

  data_len = pntohs(dptr);
  dptr += 2;

  switch (type) {
  case T_A:
    trr = proto_tree_add_text(dns_tree, offset, (dptr - data_start) + data_len,
		     "%s: type %s, class %s, addr %s",
		     name, type_name, class_name,
		     ip_to_str((guint8 *)dptr));
    rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                     long_type_name, class_name, ttl, data_len);
    offset += (dptr - data_start);
    proto_tree_add_text(rr_tree, offset, 4, "Addr: %s",
                     ip_to_str((guint8 *)dptr));
    break;

  case T_NS:
    {
      char ns_name[MAXDNAME];
      int ns_name_len;
      
      ns_name_len = get_dns_name(dns_data_ptr, dptr, ns_name, sizeof(ns_name));
      trr = proto_tree_add_text(dns_tree, offset, (dptr - data_start) + data_len,
		       "%s: type %s, class %s, ns %s",
		       name, type_name, class_name, ns_name);
      rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                       long_type_name, class_name, ttl, data_len);
      offset += (dptr - data_start);
      proto_tree_add_text(rr_tree, offset, ns_name_len, "Name server: %s", ns_name);
    }
    break;

  case T_CNAME:
    {
      char cname[MAXDNAME];
      int cname_len;
      
      cname_len = get_dns_name(dns_data_ptr, dptr, cname, sizeof(cname));
      trr = proto_tree_add_text(dns_tree, offset, (dptr - data_start) + data_len,
		     "%s: type %s, class %s, cname %s",
		     name, type_name, class_name, cname);
      rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                       long_type_name, class_name, ttl, data_len);
      offset += (dptr - data_start);
      proto_tree_add_text(rr_tree, offset, cname_len, "Primary name: %s", cname);
    }
    break;

  case T_SOA:
    {
      char mname[MAXDNAME];
      int mname_len;
      char rname[MAXDNAME];
      int rname_len;
      guint32 serial;
      guint32 refresh;
      guint32 retry;
      guint32 expire;
      guint32 minimum;

      rrptr = dptr;
      mname_len = get_dns_name(dns_data_ptr, rrptr, mname, sizeof(mname));
      rrptr += mname_len;
      trr = proto_tree_add_text(dns_tree, offset, (dptr - data_start) + data_len,
		     "%s: type %s, class %s, mname %s",
		     name, type_name, class_name, mname);
      rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                       long_type_name, class_name, ttl, data_len);
      offset += (dptr - data_start);
      proto_tree_add_text(rr_tree, offset, mname_len, "Primary name server: %s",
                       mname);
      offset += mname_len;
      rname_len = get_dns_name(dns_data_ptr, rrptr, rname, sizeof(rname));
      proto_tree_add_text(rr_tree, offset, rname_len, "Responsible authority's mailbox: %s",
                       rname);
      rrptr += rname_len;
      offset += rname_len;
      serial = pntohl(rrptr);
      proto_tree_add_text(rr_tree, offset, 4, "Serial number: %u",
                       serial);
      rrptr += 4;
      offset += 4;
      refresh = pntohl(rrptr);
      proto_tree_add_text(rr_tree, offset, 4, "Refresh interval: %s",
                       time_secs_to_str(refresh));
      rrptr += 4;
      offset += 4;
      retry = pntohl(rrptr);
      proto_tree_add_text(rr_tree, offset, 4, "Retry interval: %s",
                       time_secs_to_str(retry));
      rrptr += 4;
      offset += 4;
      expire = pntohl(rrptr);
      proto_tree_add_text(rr_tree, offset, 4, "Expiration limit: %s",
                       time_secs_to_str(expire));
      rrptr += 4;
      offset += 4;
      minimum = pntohl(rrptr);
      proto_tree_add_text(rr_tree, offset, 4, "Minimum TTL: %s",
                       time_secs_to_str(minimum));
    }
    break;

  case T_PTR:
    {
      char pname[MAXDNAME];
      int pname_len;
      
      pname_len = get_dns_name(dns_data_ptr, dptr, pname, sizeof(pname));
      trr = proto_tree_add_text(dns_tree, offset, (dptr - data_start) + data_len,
		     "%s: type %s, class %s, ptr %s",
		     name, type_name, class_name, pname);
      rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                       long_type_name, class_name, ttl, data_len);
      offset += (dptr - data_start);
      proto_tree_add_text(rr_tree, offset, pname_len, "Domain name: %s", pname);
      break;
    }
    break;
      
    /* TODO: parse more record types */

  default:
    trr = proto_tree_add_text(dns_tree, offset, (dptr - data_start) + data_len,
                     "%s: type %s, class %s",
		     name, type_name, class_name);
    rr_tree = add_rr_to_tree(trr, ETT_DNS_RR, offset, name, name_len,
                       long_type_name, class_name, ttl, data_len);
    offset += (dptr - data_start);
    proto_tree_add_text(rr_tree, offset, data_len, "Data");
  }
  
  dptr += data_len;
	
  return dptr - data_start;
}

static int
dissect_query_records(const u_char *dns_data_ptr, int count, const u_char *pd, 
		      int cur_off, proto_tree *dns_tree)
{
  int start_off;
  proto_tree *qatree;
  proto_item *ti;
  
  start_off = cur_off;
  ti = proto_tree_add_text(dns_tree, start_off, 0, "Queries");
  qatree = proto_item_add_subtree(ti, ETT_DNS_QRY);
  while (count-- > 0)
    cur_off += dissect_dns_query(dns_data_ptr, pd, cur_off, qatree);
  proto_item_set_len(ti, cur_off - start_off);

  return cur_off - start_off;
}



static int
dissect_answer_records(const u_char *dns_data_ptr, int count,
                       const u_char *pd, int cur_off, proto_tree *dns_tree,
                       char *name)
{
  int start_off;
  proto_tree *qatree;
  proto_item *ti;
  
  start_off = cur_off;
  ti = proto_tree_add_text(dns_tree, start_off, 0, name);
  qatree = proto_item_add_subtree(ti, ETT_DNS_ANS);
  while (count-- > 0)
    cur_off += dissect_dns_answer(dns_data_ptr, pd, cur_off, qatree);
  proto_item_set_len(ti, cur_off - start_off);

  return cur_off - start_off;
}


void
dissect_dns(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  const u_char *dns_data_ptr;
  proto_tree *dns_tree, *field_tree;
  proto_item *ti, *tf;
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
    ti = proto_tree_add_text(tree, offset, 4,
			  (flags & F_RESPONSE) ? "DNS response" : "DNS query");
    
    dns_tree = proto_item_add_subtree(ti, ETT_DNS);
    
    proto_tree_add_text(dns_tree, offset + DNS_ID, 2, "Transaction ID: 0x%04x",
    			id);

    strcpy(buf, val_to_str(flags & F_OPCODE, opcode_vals, "Unknown operation"));
    if (flags & F_RESPONSE) {
      strcat(buf, " response");
      strcat(buf, ", ");
      strcat(buf, val_to_str(flags & F_RCODE, rcode_vals,
            "Unknown error"));
    }
    tf = proto_tree_add_text(dns_tree, offset + DNS_FLAGS, 2, "Flags: 0x%04x (%s)",
                          flags, buf);
    field_tree = proto_item_add_subtree(tf, ETT_DNS_FLAGS);
    proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_RESPONSE,
            2*8, "Response", "Query"));
    proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_enumerated_bitfield(flags, F_OPCODE,
            2*8, opcode_vals, "%s"));
    if (flags & F_RESPONSE) {
      proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
         decode_boolean_bitfield(flags, F_AUTHORITATIVE,
              2*8,
              "Server is an authority for domain",
              "Server isn't an authority for domain"));
    }
    proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_TRUNCATED,
            2*8,
            "Message is truncated",
            "Message is not truncated"));
    proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_RECDESIRED,
            2*8,
            "Do query recursively",
            "Don't do query recursively"));
    if (flags & F_RESPONSE) {
      proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
         decode_boolean_bitfield(flags, F_RECAVAIL,
              2*8,
              "Server can do recursive queries",
              "Server can't do recursive queries"));
      proto_tree_add_text(field_tree, offset + DNS_FLAGS, 2, "%s",
         decode_enumerated_bitfield(flags, F_RCODE,
              2*8, rcode_vals, "%s"));
    }
    proto_tree_add_text(dns_tree, offset + DNS_QUEST, 2, "Questions: %d", quest);
    proto_tree_add_text(dns_tree, offset + DNS_ANS, 2, "Answer RRs: %d", ans);
    proto_tree_add_text(dns_tree, offset + DNS_AUTH, 2, "Authority RRs: %d", auth);
    proto_tree_add_text(dns_tree, offset + DNS_ADD, 2, "Additional RRs: %d", add);

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
