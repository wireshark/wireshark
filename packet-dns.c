/* packet-dns.c
 * Routines for DNS packet disassembly
 *
 * $Id: packet-dns.c,v 1.80 2002/01/21 07:36:33 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <glib.h>
#include <epan/packet.h>
#include "ipproto.h"
#include <epan/resolv.h>
#include "packet-dns.h"
#include "prefs.h"

static int proto_dns = -1;
static int hf_dns_length = -1;
static int hf_dns_response = -1;
static int hf_dns_query = -1;
static int hf_dns_flags = -1;
static int hf_dns_transaction_id = -1;
static int hf_dns_count_questions = -1;
static int hf_dns_count_answers = -1;
static int hf_dns_count_auth_rr = -1;
static int hf_dns_count_add_rr = -1;

static gint ett_dns = -1;
static gint ett_dns_qd = -1;
static gint ett_dns_rr = -1;
static gint ett_dns_qry = -1;
static gint ett_dns_ans = -1;
static gint ett_dns_flags = -1;
static gint ett_t_key_flags = -1;

/* desegmentation of DNS over TCP */
static gboolean dns_desegment = TRUE;

/* DNS structs and definitions */

/* Ports used for DNS. */
#define UDP_PORT_DNS     53
#define TCP_PORT_DNS     53

/* Offsets of fields in the DNS header. */
#define	DNS_ID		0
#define	DNS_FLAGS	2
#define	DNS_QUEST	4
#define	DNS_ANS		6
#define	DNS_AUTH	8
#define	DNS_ADD		10

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
#define T_SIG           24              /* digital signature (RFC 2535) */
#define T_KEY           25              /* public key (RFC 2535) */
#define T_PX            26              /* pointer to X.400/RFC822 mapping info (RFC 1664) */
#define T_GPOS          27              /* geographical position (RFC 1712) */
#define T_AAAA          28              /* IPv6 address (RFC 1886) */
#define T_LOC           29              /* geographical location (RFC 1876) */
#define T_NXT           30              /* "next" name (RFC 2535) */
#define T_EID           31              /* ??? (Nimrod?) */
#define T_NIMLOC        32              /* ??? (Nimrod?) */
#define T_SRV           33              /* service location (RFC 2052) */
#define T_ATMA          34              /* ??? */
#define T_NAPTR         35              /* naming authority pointer (RFC 2168) */
#define	T_KX		36		/* Key Exchange (RFC 2230) */
#define	T_CERT		37		/* Certificate (RFC 2538) */
#define T_A6		38              /* IPv6 address with indirection (RFC 2874) */
#define T_DNAME         39              /* Non-terminal DNS name redirection (RFC 2672) */
#define T_OPT		41		/* OPT pseudo-RR (RFC 2671) */
#define T_TKEY		249		/* Transaction Key (RFC 2930) */
#define T_TSIG		250		/* Transaction Signature (RFC 2845) */
#define T_WINS		65281		/* Microsoft's WINS RR */
#define T_WINS_R	65282		/* Microsoft's WINS-R RR */

/* Class values */
#define C_IN		1		/* the Internet */
#define C_CS		2		/* CSNET (obsolete) */
#define C_CH		3		/* CHAOS */
#define C_HS		4		/* Hesiod */
#define	C_NONE		254		/* none */
#define	C_ANY		255		/* any */

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_AUTHENTIC     (1<<5)          /* authentic data (RFC2535) */
#define F_CHECKDISABLE  (1<<4)          /* checking disabled (RFC2535) */
#define F_RCODE         (0xF<<0)        /* reply code */

/* Opcodes */
#define OPCODE_QUERY    (0<<11)         /* standard query */
#define OPCODE_IQUERY   (1<<11)         /* inverse query */
#define OPCODE_STATUS   (2<<11)         /* server status request */
#define OPCODE_NOTIFY   (4<<11)         /* zone change notification */
#define OPCODE_UPDATE   (5<<11)         /* dynamic update */

/* Reply codes */
#define RCODE_NOERROR   (0<<0)
#define RCODE_FORMERR   (1<<0)
#define RCODE_SERVFAIL  (2<<0)
#define RCODE_NXDOMAIN  (3<<0)
#define RCODE_NOTIMPL   (4<<0)
#define RCODE_REFUSED   (5<<0)
#define RCODE_YXDOMAIN  (6<<0)
#define RCODE_YXRRSET   (7<<0)
#define RCODE_NXRRSET   (8<<0)
#define RCODE_NOTAUTH   (9<<0)
#define RCODE_NOTZONE   (10<<0)

static const value_string rcode_vals[] = {
	  { RCODE_NOERROR,   "No error"             },
	  { RCODE_FORMERR,   "Format error"         },
	  { RCODE_SERVFAIL,  "Server failure"       },
	  { RCODE_NXDOMAIN,  "No such name"         },
	  { RCODE_NOTIMPL,   "Not implemented"      },
	  { RCODE_REFUSED,   "Refused"              },
	  { RCODE_YXDOMAIN,  "Name exists"          },
	  { RCODE_YXRRSET,   "RRset exists"         },
	  { RCODE_NXRRSET,   "RRset does not exist" },
	  { RCODE_NOTAUTH,   "Not authoritative"    },
	  { RCODE_NOTZONE,   "Name out of zone"     },
	  { 0,               NULL                   } };

/* TSIG/TKEY extended errors */
#define TSIGERROR_BADSIG   (16)
#define TSIGERROR_BADKEY   (17)
#define TSIGERROR_BADTIME  (18)
#define TSIGERROR_BADMODE  (19)
#define TSIGERROR_BADNAME  (20)
#define TSIGERROR_BADALG   (21)

static const value_string tsigerror_vals[] = {
	  { TSIGERROR_BADSIG,   "Bad signature"        },
	  { TSIGERROR_BADKEY,   "Bad key"              },
	  { TSIGERROR_BADTIME,  "Bad time failure"     },
	  { TSIGERROR_BADMODE,  "Bad mode such name"   },
	  { TSIGERROR_BADNAME,  "Bad name implemented" },
	  { TSIGERROR_BADALG,   "Bad algorithm"        },
	  { 0,                  NULL                   } };

#define TKEYMODE_SERVERASSIGNED             (1)
#define TKEYMODE_DIFFIEHELLMAN              (2)
#define TKEYMODE_GSSAPI                     (3)
#define TKEYMODE_RESOLVERASSIGNED           (4)
#define TKEYMODE_DELETE                     (5)

/* See RFC 1035 for all RR types for which no RFC is listed, except for
   the ones with "???", and for the Microsoft WINS and WINS-R RRs, for
   which one should look at

http://www.windows.com/windows2000/en/server/help/sag_DNS_imp_UsingWinsLookup.htm
   
   and
   
http://www.microsoft.com/windows2000/library/resources/reskit/samplechapters/cncf/cncf_imp_wwaw.asp

   which discuss them to some extent. */
static char *
dns_type_name (u_int type)
{
  char *type_names[] = {
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
    "SIG",				/* RFC 2535 */
    "KEY",				/* RFC 2535 */
    "PX",				/* RFC 1664 */
    "GPOS",				/* RFC 1712 */
    "AAAA",				/* RFC 1886 */
    "LOC",				/* RFC 1876 */
    "NXT",				/* RFC 2535 */
    "EID",
    "NIMLOC",
    "SRV",				/* RFC 2052 */
    "ATMA",
    "NAPTR",				/* RFC 2168 */
    "KX",				/* RFC 2230 */
    "CERT",				/* RFC 2538 */
    "A6",				/* RFC 2874 */
    "DNAME",				/* RFC 2672 */
    NULL,
    "OPT"				/* RFC 2671 */
  };
  
  if (type < sizeof(type_names)/sizeof(type_names[0]))
    return type_names[type] ? type_names[type] : "unknown";
  
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
    case T_WINS:
      return "WINS";
    case T_WINS_R:
      return "WINS-R";

      /* meta */
    case T_TKEY:
      return "TKEY";
    case T_TSIG:
      return "TSIG";

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
dns_long_type_name (u_int type)
{
  char *type_names[] = {
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
    "Signature",			/* RFC 2535 */
    "Public key",			/* RFC 2535 */
    "Pointer to X.400/RFC822 mapping info", /* RFC 1664 */
    "Geographical position",		/* RFC 1712 */
    "IPv6 address",			/* RFC 1886 */
    "Location",				/* RFC 1876 */
    "Next",				/* RFC 2535 */
    "EID",
    "NIMLOC",
    "Service location",			/* RFC 2052 */
    "ATMA",
    "Naming authority pointer",		/* RFC 2168 */
    "Key Exchange",			/* RFC 2230 */
    "Certificate",			/* RFC 2538 */
    "IPv6 address with indirection",	/* RFC 2874 */
    "Non-terminal DNS name redirection", /* RFC 2672 */
    NULL,
    "EDNS0 option"			/* RFC 2671 */
  };
  static char unkbuf[7+1+2+1+4+1+1+10+1+1];	/* "Unknown RR type (%d)" */
  
  if (type < sizeof(type_names)/sizeof(type_names[0]))
    return type_names[type] ? type_names[type] : "unknown";
  
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
    case T_WINS:
      return "WINS";
    case T_WINS_R:
      return "WINS-R";

      /* meta */
    case T_TKEY:
      return "Transaction Key";
    case T_TSIG:
      return "Transaction Signature";

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
  case C_IN:
    class_name = "inet";
    break;
  case C_CS:
    class_name = "csnet";
    break;
  case C_CH:
    class_name = "chaos";
    break;
  case C_HS:
    class_name = "hesiod";
    break;
  case C_NONE:
    class_name = "none";
    break;
  case C_ANY:
    class_name = "any";
    break;
  default:
    class_name = "unknown";
  }

  return class_name;
}

int
get_dns_name(tvbuff_t *tvb, int offset, int dns_data_offset,
    char *name, int maxname)
{
  int start_offset = offset;
  char *np = name;
  int len = -1;
  int chars_processed = 0;
  int data_size = tvb_reported_length_remaining(tvb, dns_data_offset);
  int component_len;
  int indir_offset;

  maxname--;	/* reserve space for the trailing '\0' */
  for (;;) {
    component_len = tvb_get_guint8(tvb, offset);
    offset++;
    if (component_len == 0)
      break;
    chars_processed++;
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
          *np++ = tvb_get_guint8(tvb, offset);
          maxname--;
        }
      	component_len--;
      	offset++;
        chars_processed++;
      }
      break;

    case 0x40:
      /* Extended label (RFC 2673) */
      switch (component_len & 0x3f) {

      case 0x01:
	/* Bitstring label */
	{
	  int bit_count;
	  int label_len;

	  bit_count = tvb_get_guint8(tvb, offset);
	  offset++;
	  label_len = (bit_count - 1) / 8 + 1;
	
	  np += sprintf(np, "\\[x");
	  while(label_len--) {
	    np += sprintf(np, "%02x", tvb_get_guint8(tvb, offset));
	    offset++;
	  }
	  np += sprintf(np, "/%d]", bit_count);
	}
	break;

      default:
	strcpy(name, "<Unknown extended label>");
	/* Parsing will propably fail from here on, since the */
	/* label length is unknown... */
	return offset - start_offset;
      }
      break;

    case 0x80:
      goto error;	/* error */

    case 0xc0:
      /* Pointer. */
      indir_offset = dns_data_offset +
          (((component_len & ~0xc0) << 8) | tvb_get_guint8(tvb, offset));
      offset++;
      chars_processed++;

      /* If "len" is negative, we are still working on the original name,
         not something pointed to by a pointer, and so we should set "len"
         to the length of the original name. */
      if (len < 0)
        len = offset - start_offset;

      /* If we've looked at every character in the message, this pointer
         will make us look at some character again, which means we're
	 looping. */
      if (chars_processed >= data_size) {
        strcpy(name, "<Name contains a pointer that loops>");
        return len;
      }

      offset = indir_offset;
      break;	/* now continue processing from there */
    }
  }
        
error:
  *np = '\0';
  /* If "len" is negative, we haven't seen a pointer, and thus haven't
     set the length, so set it. */
  if (len < 0)
    len = offset - start_offset;
  /* Zero-length name means "root server" */
  if (*name == '\0')
    strcpy(name, "<Root>");
  return len;
}


static int
get_dns_name_type_class(tvbuff_t *tvb, int offset, int dns_data_offset,
    char *name_ret, int *name_len_ret, int *type_ret, int *class_ret)
{
  int len;
  int name_len;
  int type;
  int class;
  char name[MAXDNAME];
  int start_offset = offset;

  name_len = get_dns_name(tvb, offset, dns_data_offset, name, sizeof(name));
  offset += name_len;
  
  type = tvb_get_ntohs(tvb, offset);
  offset += 2;

  class = tvb_get_ntohs(tvb, offset);
  offset += 2;

  strcpy (name_ret, name);
  *type_ret = type;
  *class_ret = class;
  *name_len_ret = name_len;

  len = offset - start_offset;
  return len;
}

static double
rfc1867_size(tvbuff_t *tvb, int offset)
{
  guint8 val;
  double size;
  guint32 exponent;

  val = tvb_get_guint8(tvb, offset);
  size = (val & 0xF0) >> 4;
  exponent = (val & 0x0F);
  while (exponent != 0) {
    size *= 10;
    exponent--;
  }
  return size / 100;	/* return size in meters, not cm */
}

static char *
rfc1867_angle(tvbuff_t *tvb, int offset, const char *nsew)
{
  guint32 angle;
  char direction;
  guint32 degrees, minutes, secs, tsecs;
  static char buf[10+1+3+1 + 2+1+3+1 + 2+1+3+1+3+1 + 1 + 1];

  angle = tvb_get_ntohl(tvb, offset);

  if (angle < 0x80000000U) {
    angle = 0x80000000U - angle;
    direction = nsew[1];
  } else {
    angle = angle - 0x80000000U;
    direction = nsew[0];
  }
  tsecs = angle % 1000;
  angle = angle / 1000;
  secs = angle % 60;
  angle = angle / 60;
  minutes = angle % 60;
  degrees = angle / 60;
  sprintf(buf, "%u deg %u min %u.%03u sec %c", degrees, minutes, secs,
		tsecs, direction);
  return buf;
}

static int
dissect_dns_query(tvbuff_t *tvb, int offset, int dns_data_offset,
  column_info *cinfo, proto_tree *dns_tree)
{
  int len;
  char name[MAXDNAME];
  int name_len;
  int type;
  int class;
  char *class_name;
  char *type_name;
  char *long_type_name;
  int data_offset;
  int data_start;
  proto_tree *q_tree;
  proto_item *tq;

  data_start = data_offset = offset;

  len = get_dns_name_type_class(tvb, offset, dns_data_offset, name, &name_len,
    &type, &class);
  data_offset += len;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);
  long_type_name = dns_long_type_name(type);

  if (cinfo != NULL)
    col_append_fstr(cinfo, COL_INFO, " %s %s", type_name, name);
  if (dns_tree != NULL) {
    tq = proto_tree_add_text(dns_tree, tvb, offset, len, "%s: type %s, class %s", 
		   name, type_name, class_name);
    q_tree = proto_item_add_subtree(tq, ett_dns_qd);

    proto_tree_add_text(q_tree, tvb, offset, name_len, "Name: %s", name);
    offset += name_len;

    proto_tree_add_text(q_tree, tvb, offset, 2, "Type: %s", long_type_name);
    offset += 2;

    proto_tree_add_text(q_tree, tvb, offset, 2, "Class: %s", class_name);
    offset += 2;
  }
  
  return data_offset - data_start;
}


proto_tree *
add_rr_to_tree(proto_item *trr, int rr_type, tvbuff_t *tvb, int offset,
  const char *name, int namelen, const char *type_name, const char *class_name,
  u_int ttl, u_short data_len)
{
  proto_tree *rr_tree;

  rr_tree = proto_item_add_subtree(trr, rr_type);
  proto_tree_add_text(rr_tree, tvb, offset, namelen, "Name: %s", name);
  offset += namelen;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "Type: %s", type_name);
  offset += 2;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "Class: %s", class_name);
  offset += 2;
  proto_tree_add_text(rr_tree, tvb, offset, 4, "Time to live: %s",
						time_secs_to_str(ttl));
  offset += 4;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "Data length: %u", data_len);
  return rr_tree;
}

static proto_tree *
add_opt_rr_to_tree(proto_item *trr, int rr_type, tvbuff_t *tvb, int offset,
  const char *name, int namelen, const char *type_name, int class,
  u_int ttl, u_short data_len)
{
  proto_tree *rr_tree;

  rr_tree = proto_item_add_subtree(trr, rr_type);
  proto_tree_add_text(rr_tree, tvb, offset, namelen, "Name: %s", name);
  offset += namelen;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "Type: %s", type_name);
  offset += 2;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "UDP payload size: %u",
      class & 0xffff);
  offset += 2;
  proto_tree_add_text(rr_tree, tvb, offset, 1, "Higher bits in extended RCODE: 0x%x",
      (ttl >> 24) & 0xff0);
  offset++;
  proto_tree_add_text(rr_tree, tvb, offset, 1, "EDNS0 version: %u",
      (ttl >> 16) & 0xff);
  offset++;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "Must be zero: 0x%x", ttl & 0xffff);
  offset += 2;
  proto_tree_add_text(rr_tree, tvb, offset, 2, "Data length: %u", data_len);
  return rr_tree;
}

/*
 * SIG, KEY, and CERT RR algorithms.
 */
#define	DNS_ALGO_RSAMD5		1	/* RSA/MD5 */
#define	DNS_ALGO_DH		2	/* Diffie-Hellman */
#define	DNS_ALGO_DSA		3	/* DSA */
#define	DNS_ALGO_ECC		4	/* Elliptic curve crypto */
#define	DNS_ALGO_INDIRECT	252	/* Indirect key */
#define	DNS_ALGO_PRIVATEDNS	253	/* Private, domain name  */
#define	DNS_ALGO_PRIVATEOID	254	/* Private, OID */	

static const value_string algo_vals[] = {
	  { DNS_ALGO_RSAMD5,     "RSA/MD5" },
	  { DNS_ALGO_DH,         "Diffie-Hellman" },
	  { DNS_ALGO_DSA,        "DSA" },
	  { DNS_ALGO_ECC,        "Elliptic curve crypto" },
	  { DNS_ALGO_INDIRECT,   "Indirect key" },
	  { DNS_ALGO_PRIVATEDNS, "Private, domain name" },
	  { DNS_ALGO_PRIVATEOID, "Private, OID" },
	  { 0,                   NULL }
};

#define DNS_CERT_PGP		1	/* PGP */
#define DNS_CERT_PKIX		2	/* PKIX */
#define DNS_CERT_SPKI		3	/* SPKI */
#define DNS_CERT_PRIVATEURI	253	/* Private, URI */
#define DNS_CERT_PRIVATEOID	254	/* Private, OID */

static const value_string cert_vals[] = {
	  { DNS_CERT_PGP,        "PGP" },
	  { DNS_CERT_PKIX,       "PKIX" },
	  { DNS_CERT_SPKI,       "SPKI" },
	  { DNS_CERT_PRIVATEURI, "Private, URI" },
	  { DNS_CERT_PRIVATEOID, "Private, OID" },
	  { 0,                   NULL }
};

static int
dissect_dns_answer(tvbuff_t *tvb, int offset, int dns_data_offset,
  column_info *cinfo, proto_tree *dns_tree)
{
  int len;
  char name[MAXDNAME];
  int name_len;
  int type;
  int class;
  char *class_name;
  char *type_name;
  char *long_type_name;
  int data_offset;
  int cur_offset;
  int data_start;
  u_int ttl;
  u_short data_len;
  proto_tree *rr_tree = NULL;
  proto_item *trr = NULL;

  data_start = data_offset = offset;
  cur_offset = offset;

  len = get_dns_name_type_class(tvb, offset, dns_data_offset, name, &name_len,
    &type, &class);
  data_offset += len;
  cur_offset += len;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);
  long_type_name = dns_long_type_name(type);

  ttl = tvb_get_ntohl(tvb, data_offset);
  data_offset += 4;
  cur_offset += 4;

  data_len = tvb_get_ntohs(tvb, data_offset);
  data_offset += 2;
  cur_offset += 2;

  if (cinfo != NULL)
    col_append_fstr(cinfo, COL_INFO, " %s", type_name);
  if (dns_tree != NULL) {
    trr = proto_tree_add_text(dns_tree, tvb, offset,
				(data_offset - data_start) + data_len,
				"%s: type %s, class %s",
				name, type_name, class_name);
    if (type != T_OPT) {
      rr_tree = add_rr_to_tree(trr, ett_dns_rr, tvb, offset, name, name_len,
		     long_type_name, class_name, ttl, data_len);
    } else  {
      rr_tree = add_opt_rr_to_tree(trr, ett_dns_rr, tvb, offset, name, name_len,
		     long_type_name, class, ttl, data_len);
    }
  }

  switch (type) {

  case T_A:
    {
      const guint8 *addr;
      guint32 addr_int;

      addr = tvb_get_ptr(tvb, cur_offset, 4);
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", ip_to_str(addr));
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", addr %s", ip_to_str(addr));
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Addr: %s",
		     ip_to_str(addr));
      }
      if (class == C_IN) {
	memcpy(&addr_int, addr, sizeof(addr_int));
	add_host_name(addr_int, name);
      }
    }
    break;

  case T_NS:
    {
      char ns_name[MAXDNAME];
      int ns_name_len;
      
      ns_name_len = get_dns_name(tvb, cur_offset, dns_data_offset, ns_name, sizeof(ns_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", ns_name);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", ns %s", ns_name);
	proto_tree_add_text(rr_tree, tvb, cur_offset, ns_name_len, "Name server: %s",
			ns_name);
      }
    }
    break;

  case T_CNAME:
    {
      char cname[MAXDNAME];
      int cname_len;
      
      cname_len = get_dns_name(tvb, cur_offset, dns_data_offset, cname, sizeof(cname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", cname);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", cname %s", cname);
	proto_tree_add_text(rr_tree, tvb, cur_offset, cname_len, "Primary name: %s",
			cname);
      }
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

      mname_len = get_dns_name(tvb, cur_offset, dns_data_offset, mname, sizeof(mname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", mname);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", mname %s", mname);
	proto_tree_add_text(rr_tree, tvb, cur_offset, mname_len, "Primary name server: %s",
		       mname);
	cur_offset += mname_len;
      
	rname_len = get_dns_name(tvb, cur_offset, dns_data_offset, rname, sizeof(rname));
	proto_tree_add_text(rr_tree, tvb, cur_offset, rname_len, "Responsible authority's mailbox: %s",
		       rname);
	cur_offset += rname_len;

	serial = tvb_get_ntohl(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Serial number: %u",
		       serial);
	cur_offset += 4;

	refresh = tvb_get_ntohl(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Refresh interval: %s",
		       time_secs_to_str(refresh));
	cur_offset += 4;

	retry = tvb_get_ntohl(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Retry interval: %s",
		       time_secs_to_str(retry));
	cur_offset += 4;

	expire = tvb_get_ntohl(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Expiration limit: %s",
		       time_secs_to_str(expire));
	cur_offset += 4;

	minimum = tvb_get_ntohl(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Minimum TTL: %s",
		       time_secs_to_str(minimum));
      }
    }
    break;

  case T_PTR:
    {
      char pname[MAXDNAME];
      int pname_len;
      
      pname_len = get_dns_name(tvb, cur_offset, dns_data_offset, pname, sizeof(pname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", pname);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", ptr %s", pname);
	proto_tree_add_text(rr_tree, tvb, cur_offset, pname_len, "Domain name: %s",
			pname);
      }
      break;
    }
    break;

  case T_WKS:
    {
      int rr_len = data_len;
      const guint8 *wks_addr;
      guint8 protocol;
      guint8 bits;
      int mask;
      int port_num;
      int i;
      char bitnames[128+1];
      char portnumstring[10+1];
      
      wks_addr = tvb_get_ptr(tvb, cur_offset, 4);
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", ip_to_str(wks_addr));
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", addr %s", ip_to_str(wks_addr));
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Addr: %s",
		     ip_to_str(wks_addr));
	cur_offset += 4;
	rr_len -= 4;

	protocol = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Protocol: %s",
		     ipprotostr(protocol));
	cur_offset += 1;
	rr_len -= 1;

	port_num = 0;
	while (rr_len != 0) {
	  bits = tvb_get_guint8(tvb, cur_offset);
	  if (bits != 0) {
	    mask = 1<<7;
	    bitnames[0] = '\0';
	    for (i = 0; i < 8; i++) {
	      if (bits & mask) {
		if (bitnames[0] != '\0')
		  strcat(bitnames, ", ");
		switch (protocol) {

		case IP_PROTO_TCP:
		  strcat(bitnames, get_tcp_port(port_num));
		  break;

		case IP_PROTO_UDP:
		  strcat(bitnames, get_udp_port(port_num));
		  break;

		default:
		  sprintf(portnumstring, "%u", port_num);
		  strcat(bitnames, portnumstring);
		  break;
	        }
	      }
	      mask >>= 1;
	      port_num++;
	    }
	    proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
		"Bits: 0x%02x (%s)", bits, bitnames);
	  } else
	    port_num += 8;
	  cur_offset += 1;
	  rr_len -= 1;
	}
      }
    }
    break;

  case T_HINFO:
    {
      int cpu_offset;
      int cpu_len;
      const guint8 *cpu;
      int os_offset;
      int os_len;
      const guint8 *os;

      cpu_offset = cur_offset;
      cpu_len = tvb_get_guint8(tvb, cpu_offset);
      cpu = tvb_get_ptr(tvb, cpu_offset + 1, cpu_len);
      os_offset = cpu_offset + 1 + cpu_len;
      os_len = tvb_get_guint8(tvb, os_offset);
      os = tvb_get_ptr(tvb, os_offset + 1, os_len);
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %.*s %.*s", cpu_len, cpu,
	    os_len, os);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", CPU %.*s, OS %.*s",
		     cpu_len, cpu, os_len, os);
	proto_tree_add_text(rr_tree, tvb, cpu_offset, 1 + cpu_len, "CPU: %.*s",
			cpu_len, cpu);
	proto_tree_add_text(rr_tree, tvb, os_offset, 1 + os_len, "OS: %.*s",
			os_len, os);
      }
      break;
    }
    break;

  case T_MX:
    {
      guint16 preference = 0;
      char mx_name[MAXDNAME];
      int mx_name_len;
      
      preference = tvb_get_ntohs(tvb, cur_offset);
      mx_name_len = get_dns_name(tvb, cur_offset + 2, dns_data_offset, mx_name, sizeof(mx_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %u %s", preference, mx_name);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", preference %u, mx %s",
		       preference, mx_name);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Preference: %u", preference);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 2, mx_name_len, "Mail exchange: %s",
			mx_name);
      }
    }
    break;

  case T_TXT:
    {
      int rr_len = data_len;
      int txt_offset;
      int txt_len;

      if (dns_tree != NULL) {
	txt_offset = cur_offset;
	while (rr_len != 0) {
	  txt_len = tvb_get_guint8(tvb, txt_offset);
	  proto_tree_add_text(rr_tree, tvb, txt_offset, 1 + txt_len,
	   "Text: %.*s", txt_len, tvb_get_ptr(tvb, txt_offset + 1, txt_len));
	  txt_offset += 1 + txt_len;
	  rr_len -= 1 + txt_len;
	}
      }
    }
    break;

  case T_SIG:
    {
      int rr_len = data_len;
      guint16 type_covered;
      nstime_t nstime;
      char signer_name[MAXDNAME];
      int signer_name_len;

      if (dns_tree != NULL) {
	type_covered = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Type covered: %s (%s)",
		dns_type_name(type_covered),
		dns_long_type_name(type_covered));
	cur_offset += 2;
	rr_len -= 2;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(tvb_get_guint8(tvb, cur_offset), algo_vals,
	            "Unknown (0x%02X)"));
	cur_offset += 1;
	rr_len -= 1;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Labels: %u",
		tvb_get_guint8(tvb, cur_offset));
	cur_offset += 1;
	rr_len -= 1;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Original TTL: %s",
		time_secs_to_str(tvb_get_ntohl(tvb, cur_offset)));
	cur_offset += 4;
	rr_len -= 4;

	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Signature expiration: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Time signed: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Key footprint: 0x%04x",
		tvb_get_ntohs(tvb, cur_offset));
	cur_offset += 2;
	rr_len -= 2;

	signer_name_len = get_dns_name(tvb, cur_offset, dns_data_offset, signer_name, sizeof(signer_name));
	proto_tree_add_text(rr_tree, tvb, cur_offset, signer_name_len,
		"Signer's name: %s", signer_name);
	cur_offset += signer_name_len;
	rr_len -= signer_name_len;

	proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Signature");
      }
    }
    break;

  case T_KEY:
    {
      int rr_len = data_len;
      guint16 flags;
      proto_item *tf;
      proto_tree *flags_tree;

      if (dns_tree != NULL) {
        flags = tvb_get_ntohs(tvb, cur_offset);
	tf = proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Flags: 0x%04X", flags);
	flags_tree = proto_item_add_subtree(tf, ett_t_key_flags);
	proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x8000,
		  2*8, "Key prohibited for authentication",
		       "Key allowed for authentication"));
	proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x4000,
		  2*8, "Key prohibited for confidentiality",
		       "Key allowed for confidentiality"));
	if ((flags & 0xC000) != 0xC000) {
	  /* We have a key */
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x2000,
		  2*8, "Key is experimental or optional",
		       "Key is required"));
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x0400,
		  2*8, "Key is associated with a user",
		       "Key is not associated with a user"));
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x0200,
		  2*8, "Key is associated with the named entity",
		       "Key is not associated with the named entity"));
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x0100,
		  2*8, "This is the zone key for the specified zone",
		       "This is not a zone key"));
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x0080,
		  2*8, "Key is valid for use with IPSEC",
		       "Key is not valid for use with IPSEC"));
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_boolean_bitfield(flags, 0x0040,
		  2*8, "Key is valid for use with MIME security multiparts",
		       "Key is not valid for use with MIME security multiparts"));
	  proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		decode_numeric_bitfield(flags, 0x000F,
		  2*8, "Signatory = %u"));
	}
	cur_offset += 2;
	rr_len -= 2;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Protocol: %u",
		tvb_get_guint8(tvb, cur_offset));
	cur_offset += 1;
	rr_len -= 1;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(tvb_get_guint8(tvb, cur_offset), algo_vals,
	            "Unknown (0x%02X)"));
	cur_offset += 1;
		rr_len -= 1;

	proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Public key");
      }
    }
    break;

  case T_AAAA:
    {
      const guint8 *addr6;

      addr6 = tvb_get_ptr(tvb, cur_offset, 16);
      if (cinfo != NULL) {
	col_append_fstr(cinfo, COL_INFO, " %s",
			ip6_to_str((struct e_in6_addr *)addr6));
      }
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", addr %s",
		     ip6_to_str((struct e_in6_addr *)addr6));
	proto_tree_add_text(rr_tree, tvb, cur_offset, 16, "Addr: %s",
		     ip6_to_str((struct e_in6_addr *)addr6));
      }
    }
    break;

  case T_A6:
    {
      unsigned short pre_len;
      unsigned short suf_len;
      unsigned short suf_octet_count;
      char pname[MAXDNAME];
      int pname_len;
      int a6_offset;
      int suf_offset;
      guint8 suffix[16];

      a6_offset = cur_offset;
      pre_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset++;
      suf_len = 128 - pre_len;
      suf_octet_count = suf_len ? (suf_len - 1) / 8 + 1 : 0;
      /* Pad prefix */
      for (suf_offset = 0; suf_offset < 16 - suf_octet_count; suf_offset++) {
        suffix[suf_offset] = 0;
      }
      for (; suf_offset < 16; suf_offset++) {
        suffix[suf_offset] = tvb_get_guint8(tvb, cur_offset);
        cur_offset++;
      }

      if (pre_len > 0) {
        pname_len = get_dns_name(tvb, cur_offset, dns_data_offset, 
                                 pname, sizeof(pname));
      } else {
        strcpy(pname, "");   
        pname_len = 0;
      }

      if (cinfo != NULL) {
        col_append_fstr(cinfo, COL_INFO, " %d %s %s", 
                        pre_len, 
                        ip6_to_str((struct e_in6_addr *)&suffix), 
                        pname);
      }
      if (dns_tree != NULL) {
        proto_tree_add_text(rr_tree, tvb, a6_offset, 1, 
                            "Prefix len: %u", pre_len);
        a6_offset++;
        if (suf_len) {
          proto_tree_add_text(rr_tree, tvb, a6_offset, suf_octet_count,
                              "Address suffix: %s", 
                              ip6_to_str((struct e_in6_addr *)&suffix));
          a6_offset += suf_octet_count;
        }
        if (pre_len > 0) {
          proto_tree_add_text(rr_tree, tvb, a6_offset, pname_len, 
                              "Prefix name: %s", pname);
        }
        proto_item_append_text(trr, ", addr %d %s %s",
                            pre_len, 
                            ip6_to_str((struct e_in6_addr *)&suffix), 
                            pname);
      }
    }
    break;

  case T_DNAME:
    {
      char dname[MAXDNAME];
      int dname_len;
      
      dname_len = get_dns_name(tvb, cur_offset, dns_data_offset, 
			       dname, sizeof(dname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", dname);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", dname %s", dname);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 
			    dname_len, "Target name: %s", dname);
      }
    }
    break;

  case T_LOC:
    {
      guint8 version;

      if (dns_tree != NULL) {
	version = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Version: %u", version);
	if (version == 0) {
	  /* Version 0, the only version RFC 1876 discusses. */
	  cur_offset++;

	  proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Size: %g m",
				rfc1867_size(tvb, cur_offset));
	  cur_offset++;

	  proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Horizontal precision: %g m",
				rfc1867_size(tvb, cur_offset));
	  cur_offset++;

	  proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Vertical precision: %g m",
				rfc1867_size(tvb, cur_offset));
	  cur_offset++;

	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Latitude: %s",
				rfc1867_angle(tvb, cur_offset, "NS"));
	  cur_offset += 4;

	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Longitude: %s",
				rfc1867_angle(tvb, cur_offset, "EW"));
	  cur_offset += 4;

	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Altitude: %g m",
				(tvb_get_ntohl(tvb, cur_offset) - 10000000)/100.0);
	} else
	  proto_tree_add_text(rr_tree, tvb, cur_offset, data_len, "Data");
      }
      break;
    }
    break;
      
  case T_NXT:
    {
      int rr_len = data_len;
      char next_domain_name[MAXDNAME];
      int next_domain_name_len;
      int rr_type;
      guint8 bits;
      int mask;
      int i;

      next_domain_name_len = get_dns_name(tvb, cur_offset, dns_data_offset,
			next_domain_name, sizeof(next_domain_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", next_domain_name);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", next domain name %s",
		     next_domain_name);
	proto_tree_add_text(rr_tree, tvb, cur_offset, next_domain_name_len,
			"Next domain name: %s", next_domain_name);
	cur_offset += next_domain_name_len;
	rr_len -= next_domain_name_len;
	rr_type = 0;
	while (rr_len != 0) {
	  bits = tvb_get_guint8(tvb, cur_offset);
	  mask = 1<<7;
	  for (i = 0; i < 8; i++) {
	    if (bits & mask) {
	      proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
			"RR type in bit map: %s (%s)",
			dns_type_name(rr_type),
			dns_long_type_name(rr_type));
	    }
	    mask >>= 1;
	    rr_type++;
	  }
	  cur_offset += 1;
	  rr_len -= 1;
	}
      }
    }
    break;

  case T_KX:
    {
      guint16 preference = 0;
      char kx_name[MAXDNAME];
      int kx_name_len;
      
      preference = tvb_get_ntohs(tvb, cur_offset);
      kx_name_len = get_dns_name(tvb, cur_offset + 2, dns_data_offset, kx_name, sizeof(kx_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %u %s", preference, kx_name);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", preference %u, kx %s",
		       preference, kx_name);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Preference: %u", preference);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 2, kx_name_len, "Key exchange: %s",
			kx_name);
      }
    }
    break;

  case T_CERT:
    {
      guint16 cert_type, cert_keytag;
      guint8 cert_keyalg;
      int rr_len = data_len;

      cert_type = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;
      rr_len -= 2;
      cert_keytag = tvb_get_ntohs(tvb, cur_offset);
      cur_offset += 2;
      rr_len -= 2;
      cert_keyalg = tvb_get_guint8(tvb, cur_offset);
      cur_offset += 1;
      rr_len -= 1;

      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Type: %s",
		val_to_str(cert_keyalg, cert_vals,
	            "Unknown (0x%02X)"));
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Key footprint: 0x%04x",
		cert_keytag);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(cert_keyalg, algo_vals,
	            "Unknown (0x%02X)"));
	proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Public key");
      }

    }
    break;

  case T_OPT:
    if (dns_tree != NULL)
      proto_tree_add_text(rr_tree, tvb, cur_offset, data_len, "Data");
    break;

  case T_TKEY:
    {
      char tkey_algname[MAXDNAME];
      int tkey_algname_len;
      guint16 tkey_mode, tkey_error, tkey_keylen, tkey_otherlen;
      int rr_len = data_len;
      nstime_t nstime;
      static const value_string tkey_modes[] = {
		  { TKEYMODE_SERVERASSIGNED,   "Server assigned"   },
		  { TKEYMODE_DIFFIEHELLMAN,    "Diffie Hellman"    },
		  { TKEYMODE_GSSAPI,           "GSSAPI"            },
		  { TKEYMODE_RESOLVERASSIGNED, "Resolver assigned" },
		  { TKEYMODE_DELETE,           "Delete"            },
		  { 0,                         NULL                } };

      if (dns_tree != NULL) {
	tkey_algname_len = get_dns_name(tvb, cur_offset, dns_data_offset, tkey_algname, sizeof(tkey_algname));
	proto_tree_add_text(rr_tree, tvb, cur_offset, tkey_algname_len,
		"Algorithm name: %s", tkey_algname);
	cur_offset += tkey_algname_len;
	rr_len -= tkey_algname_len;

	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Signature inception: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Signature expiration: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	tkey_mode = tvb_get_ntohs(tvb, cur_offset);
	cur_offset += 2;
	rr_len -= 2;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Mode: %s",
		val_to_str(tkey_mode, tkey_modes,
	            "Unknown (0x%02X)"));

	tkey_error = tvb_get_ntohs(tvb, cur_offset);
	cur_offset += 2;
	rr_len -= 2;

        proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Error: %s",
		val_to_str(tkey_error, rcode_vals,
		val_to_str(tkey_error, tsigerror_vals, "Unknown error (%x)")));

	tkey_keylen = tvb_get_ntohs(tvb, cur_offset);
	cur_offset += 2;
	rr_len -= 2;

	proto_tree_add_text(rr_tree, tvb, cur_offset, tkey_keylen, "Key");
	cur_offset += tkey_keylen;
	rr_len -= tkey_keylen;

	tkey_otherlen = tvb_get_ntohs(tvb, cur_offset);
	cur_offset += 2;
	rr_len -= 2;

	proto_tree_add_text(rr_tree, tvb, cur_offset, tkey_otherlen, "Other");
	cur_offset += tkey_otherlen;
	rr_len -= tkey_otherlen;
      }
    }
    break;

  case T_TSIG:
    {
      guint16 tsig_fudge;
      guint16 tsig_originalid, tsig_error, tsig_timehi, tsig_siglen, tsig_otherlen;
      guint32 tsig_timelo;
      char tsig_algname[MAXDNAME];
      int tsig_algname_len;
      nstime_t nstime;
      int rr_len = data_len;

      if (dns_tree != NULL) {
	tsig_algname_len = get_dns_name(tvb, cur_offset, dns_data_offset, tsig_algname, sizeof(tsig_algname));
	proto_tree_add_text(rr_tree, tvb, cur_offset, tsig_algname_len,
		"Algorithm name: %s", tsig_algname);
	cur_offset += tsig_algname_len;
	rr_len -= tsig_algname_len;

	tsig_timehi = tvb_get_ntohs(tvb, cur_offset);
	tsig_timelo = tvb_get_ntohl(tvb, cur_offset + 2);
	nstime.secs = tsig_timelo;
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 6, "Time signed: %s%s",
		abs_time_to_str(&nstime), tsig_timehi == 0 ? "" : "(high bits set)");
	cur_offset += 6;
	rr_len -= 6;

	tsig_fudge = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Fudge: %u",
		tsig_fudge);
	cur_offset += 2;
	rr_len -= 2;

	tsig_siglen = tvb_get_ntohs(tvb, cur_offset);
	cur_offset += 2;
	rr_len -= 2;

	proto_tree_add_text(rr_tree, tvb, cur_offset, tsig_siglen, "Signature");
	cur_offset += tsig_siglen;
	rr_len -= tsig_siglen;

	tsig_originalid = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Original id: %d",
		tsig_originalid);
	cur_offset += 2;
	rr_len -= 2;

	tsig_error = tvb_get_ntohs(tvb, cur_offset);
        proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Error: %s",
		val_to_str(tsig_error, rcode_vals,
		val_to_str(tsig_error, tsigerror_vals, "Unknown error (%x)")));
	cur_offset += 2;
	rr_len -= 2;

	tsig_otherlen = tvb_get_ntohs(tvb, cur_offset);
	cur_offset += 2;
	rr_len -= 2;

	proto_tree_add_text(rr_tree, tvb, cur_offset, tsig_otherlen, "Other");
	cur_offset += tsig_otherlen;
	rr_len -= tsig_otherlen;
      }
    }
    break;

  case T_WINS:
    {
      int rr_len = data_len;
      guint32 local_flag;
      guint32 lookup_timeout;
      guint32 cache_timeout;
      guint32 nservers;

      if (dns_tree != NULL) {
	local_flag = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Local flag: %s",
		       local_flag ? "true" : "false");
	}
	cur_offset += 4;
	rr_len -= 4;

	lookup_timeout = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Lookup timeout: %u seconds",
		       lookup_timeout);
	}
	cur_offset += 4;
	rr_len -= 4;

	cache_timeout = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Cache timeout: %u seconds",
		       cache_timeout);
	}
	cur_offset += 4;
	rr_len -= 4;

	nservers = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Number of WINS servers: %u",
		       nservers);
	}
	cur_offset += 4;
	rr_len -= 4;

	while (rr_len != 0 && nservers != 0) {
	  if (dns_tree != NULL) {
	    proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "WINS server address: %s",
		     ip_to_str(tvb_get_ptr(tvb, cur_offset, 4)));
	  }
	  cur_offset += 4;
	  rr_len -= 4;
	  nservers--;
	}
      }
    }
    break;

  case T_WINS_R:
    {
      int rr_len = data_len;
      guint32 local_flag;
      guint32 lookup_timeout;
      guint32 cache_timeout;
      char dname[MAXDNAME];
      int dname_len;

      local_flag = tvb_get_ntohl(tvb, cur_offset);
      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Local flag: %s",
		       local_flag ? "true" : "false");
      }
      cur_offset += 4;
      rr_len -= 4;

      lookup_timeout = tvb_get_ntohl(tvb, cur_offset);
      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Lookup timeout: %u seconds",
		       lookup_timeout);
      }
      cur_offset += 4;
      rr_len -= 4;

      cache_timeout = tvb_get_ntohl(tvb, cur_offset);
      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Cache timeout: %u seconds",
		       cache_timeout);
      }
      cur_offset += 4;
      rr_len -= 4;

      dname_len = get_dns_name(tvb, cur_offset, dns_data_offset, dname, sizeof(dname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", dname);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", name result domain %s", dname);
	proto_tree_add_text(rr_tree, tvb, cur_offset, dname_len, "Name result domain: %s",
			dname);
      }
    }
    break;

  case T_SRV:
    {
      guint16 priority = 0;
      guint16 weight = 0;
      guint16 port = 0;
      char target[MAXDNAME];
      int target_len;
      
      priority = tvb_get_ntohs(tvb, cur_offset);
      weight = tvb_get_ntohs(tvb, cur_offset+2);
      port = tvb_get_ntohs(tvb, cur_offset+4);

      target_len = get_dns_name(tvb, cur_offset + 6, dns_data_offset, target, sizeof(target));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %u %u %u %s", priority, weight, port, target);
      if (dns_tree != NULL) {
	proto_item_append_text(trr,
		       ", priority %u, weight %u, port %u, target %s",
		       priority, weight, port, target);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Priority: %u", priority);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 2, 2, "Weight: %u", weight);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 4, 2, "Port: %u", port);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 6, target_len, "Target: %s",
			target);
      }
    }
    break;

    /* TODO: parse more record types */

  default:
    if (dns_tree != NULL)
      proto_tree_add_text(rr_tree, tvb, cur_offset, data_len, "Data");
    break;
  }
  
  data_offset += data_len;
	
  return data_offset - data_start;
}

static int
dissect_query_records(tvbuff_t *tvb, int cur_off, int dns_data_offset,
    int count, column_info *cinfo, proto_tree *dns_tree, int isupdate)
{
  int start_off, add_off;
  proto_tree *qatree = NULL;
  proto_item *ti = NULL;
  
  start_off = cur_off;
  if (dns_tree) {
    char *s = (isupdate ?  "Zone" : "Queries");
    ti = proto_tree_add_text(dns_tree, tvb, start_off, -1, s);
    qatree = proto_item_add_subtree(ti, ett_dns_qry);
  }
  while (count-- > 0) {
    add_off = dissect_dns_query(tvb, cur_off, dns_data_offset, cinfo, qatree);
    cur_off += add_off;
  }
  if (ti)
    proto_item_set_len(ti, cur_off - start_off);

  return cur_off - start_off;
}

static int
dissect_answer_records(tvbuff_t *tvb, int cur_off, int dns_data_offset,
    int count, column_info *cinfo, proto_tree *dns_tree, char *name)
{
  int start_off, add_off;
  proto_tree *qatree = NULL;
  proto_item *ti = NULL;
  
  start_off = cur_off;
  if (dns_tree) {
    ti = proto_tree_add_text(dns_tree, tvb, start_off, -1, name);
    qatree = proto_item_add_subtree(ti, ett_dns_ans);
  }
  while (count-- > 0) {
    add_off = dissect_dns_answer(tvb, cur_off, dns_data_offset, cinfo, qatree);
    cur_off += add_off;
  }
  if (ti)
    proto_item_set_len(ti, cur_off - start_off);

  return cur_off - start_off;
}

static int
dissect_dns_common(tvbuff_t *tvb, int offset, int msg_len, packet_info *pinfo,
	proto_tree *tree, gboolean is_tcp)
{
  int dns_data_offset;
  column_info *cinfo;
  proto_tree *dns_tree = NULL, *field_tree;
  proto_item *ti, *tf;
  guint16    id, flags, quest, ans, auth, add;
  char buf[128+1];
  int cur_off;
  int isupdate;
  static const value_string opcode_vals[] = {
		  { OPCODE_QUERY,  "Standard query"           },
		  { OPCODE_IQUERY, "Inverse query"            },
		  { OPCODE_STATUS, "Server status request"    },
		  { OPCODE_NOTIFY, "Zone change notification" },
		  { OPCODE_UPDATE, "Dynamic update"           },
		  { 0,              NULL                      } };

  dns_data_offset = offset;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNS");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  /* To do: check for errs, etc. */
  id    = tvb_get_ntohs(tvb, offset + DNS_ID);
  flags = tvb_get_ntohs(tvb, offset + DNS_FLAGS);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    strcpy(buf, val_to_str(flags & F_OPCODE, opcode_vals, "Unknown operation (%x)"));
    if (flags & F_RESPONSE) {
      strcat(buf, " response");
      if ((flags & F_RCODE) != RCODE_NOERROR) {
        strcat(buf, ", ");
        strcat(buf, val_to_str(flags & F_RCODE, rcode_vals,
            "Unknown error (%x)"));
      }
    }
    col_add_str(pinfo->cinfo, COL_INFO, buf);
    cinfo = pinfo->cinfo;
  } else {
    /* Set "cinfo" to NULL; we pass a NULL "cinfo" to the query and answer
       dissectors, as a way of saying that they shouldn't add stuff
       to the COL_INFO column (a call to "check_col(cinfo, COL_INFO)"
       is more expensive than a check that a pointer isn't NULL). */
    cinfo = NULL;
  }
  if ((flags & F_OPCODE) == OPCODE_UPDATE)
    isupdate = 1;
  else
    isupdate = 0;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_dns, tvb, offset, msg_len,
      "Domain Name System (%s)", (flags & F_RESPONSE) ? "response" : "query");
    
    dns_tree = proto_item_add_subtree(ti, ett_dns);

    if (is_tcp) {
      /* Put the length indication into the tree. */
      proto_tree_add_uint(dns_tree, hf_dns_length, tvb, offset - 2, 2, msg_len);
    }

    if (flags & F_RESPONSE)
      proto_tree_add_boolean_hidden(dns_tree, hf_dns_response, tvb, offset, 4, 1);
    else
      proto_tree_add_boolean_hidden(dns_tree, hf_dns_query, tvb, offset, 4, 1);

    proto_tree_add_uint(dns_tree, hf_dns_transaction_id, tvb, 
			offset + DNS_ID, 2, id);

    strcpy(buf, val_to_str(flags & F_OPCODE, opcode_vals, "Unknown operation"));
    if (flags & F_RESPONSE) {
      strcat(buf, " response");
      strcat(buf, ", ");
      strcat(buf, val_to_str(flags & F_RCODE, rcode_vals,
            "Unknown error"));
    }
    tf = proto_tree_add_uint_format(dns_tree, hf_dns_flags, tvb, 
				    offset + DNS_FLAGS, 2, 
				    flags,
				    "Flags: 0x%04x (%s)",
				    flags, buf);
    field_tree = proto_item_add_subtree(tf, ett_dns_flags);
    proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_RESPONSE,
            2*8, "Response", "Query"));
    proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
       decode_enumerated_bitfield(flags, F_OPCODE,
            2*8, opcode_vals, "%s"));
    if (flags & F_RESPONSE) {
      proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
         decode_boolean_bitfield(flags, F_AUTHORITATIVE,
              2*8,
              "Server is an authority for domain",
              "Server is not an authority for domain"));
    }
    proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_TRUNCATED,
            2*8,
            "Message is truncated",
            "Message is not truncated"));
    proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
       decode_boolean_bitfield(flags, F_RECDESIRED,
            2*8,
            "Do query recursively",
            "Don't do query recursively"));
    if (flags & F_RESPONSE) {
      proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
         decode_boolean_bitfield(flags, F_RECAVAIL,
              2*8,
              "Server can do recursive queries",
              "Server can't do recursive queries"));
      proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
	 decode_boolean_bitfield(flags, F_AUTHENTIC,
            2*8,
            "Answer/authority portion was authenticated by the server",
            "Answer/authority portion was not authenticated by the server"));
    }
    if ((flags & F_RESPONSE) == 0) {
      proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
	 decode_boolean_bitfield(flags, F_CHECKDISABLE,
            2*8,
            "Non-authenticated data is acceptable",
            "Non-authenticated data is unacceptable"));
    }
    if (flags & F_RESPONSE) {
      proto_tree_add_text(field_tree, tvb, offset + DNS_FLAGS, 2, "%s",
         decode_enumerated_bitfield(flags, F_RCODE,
              2*8, rcode_vals, "%s"));
    }
  }
  quest = tvb_get_ntohs(tvb, offset + DNS_QUEST);
  if (tree) {
    proto_tree_add_uint(dns_tree, hf_dns_count_questions, tvb, 
			offset + DNS_QUEST, 2, quest);
  }
  ans = tvb_get_ntohs(tvb, offset + DNS_ANS);
  if (tree) {
    proto_tree_add_uint(dns_tree, hf_dns_count_answers, tvb, 
			offset + DNS_ANS, 2, ans);
  }
  auth = tvb_get_ntohs(tvb, offset + DNS_AUTH);
  if (tree) {
    proto_tree_add_uint(dns_tree, hf_dns_count_auth_rr, tvb, 
			offset + DNS_AUTH, 2, auth);
  }
  add = tvb_get_ntohs(tvb, offset + DNS_ADD);
  if (tree) {
    proto_tree_add_uint(dns_tree, hf_dns_count_add_rr, tvb, 
			offset + DNS_ADD, 2, add);

  }
  cur_off = offset + DNS_HDRLEN;

  if (quest > 0) {
    /* If this is a response, don't add information about the queries
       to the summary, just add information about the answers. */
    cur_off += dissect_query_records(tvb, cur_off, dns_data_offset, quest,
				     (!(flags & F_RESPONSE) ? cinfo : NULL),
				     dns_tree, isupdate);
  }
    
  if (ans > 0) {
    /* If this is a request, don't add information about the answers
       to the summary, just add information about the queries. */
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, ans,
				      ((flags & F_RESPONSE) ? cinfo : NULL),
				      dns_tree,
				      (isupdate ?  "Prerequisites" : "Answers"));
  }
    
  /* Don't add information about the authoritative name servers, or the
     additional records, to the summary. */
  if (auth > 0) {
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, auth,
				      NULL, dns_tree,
				      (isupdate ?  "Updates" :
						   "Authoritative nameservers"));
  }

  if (add > 0) {
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, add,
				      NULL, dns_tree, "Additional records");
  }

  return cur_off;
}

static void
dissect_dns_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_dns_common(tvb, 0, tvb_length(tvb), pinfo, tree, FALSE);
}

static void
dissect_dns_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint16 plen;

	for (;;) {
		/*
		 * XXX - should handle a length field split across segment
		 * boundaries.
		 */
		if (!tvb_bytes_exist(tvb, offset, 2))
			break;
		plen = tvb_get_ntohs(tvb, offset);

		/*
		 * Desegmentation check.
		 */
		if (dns_desegment) {
			if (pinfo->can_desegment
			    && plen > tvb_length_remaining(tvb, offset+2)) {
				/*
				 * This frame doesn't have all of the data
				 * for this message, but we can do reassembly
				 * on it.
				 *
				 * Tell the TCP dissector where the data for
				 * this message starts in the data it handed
				 * us, and how many more bytes we need, and
				 * return.
				 */
				pinfo->desegment_offset = offset;
				pinfo->desegment_len =
				    plen - tvb_length_remaining(tvb, offset+2);
				return;
			}
		}

		offset += 2;

		/*
		 * Is all of the DNS message in this TCP segment?
		 */
		if (tvb_reported_length_remaining(tvb, offset) < plen)
			break;

		/*
		 * Yes - dissect it.
		 */
		offset = dissect_dns_common(tvb, offset, plen, pinfo, tree,
		    TRUE);
	}
}

void
proto_register_dns(void)
{
  static hf_register_info hf[] = {
    { &hf_dns_length,
      { "Length",		"dns.length",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Length of DNS-over-TCP request or response", HFILL }},
    { &hf_dns_response,
      { "Response",		"dns.response",  
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if DNS response", HFILL }},
    { &hf_dns_query,
      { "Query",		"dns.query",  
	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	"TRUE if DNS query", HFILL }},
    { &hf_dns_flags,
      { "Flags",		"dns.flags",  
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"", HFILL }},
    { &hf_dns_transaction_id,
      { "Transaction ID",      	"dns.id",  
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Identification of transaction", HFILL }},
    { &hf_dns_count_questions,
      { "Questions",		"dns.count.queries",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of queries in packet", HFILL }},
    { &hf_dns_count_answers,
      { "Answer RRs",		"dns.count.answers",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of answers in packet", HFILL }},
    { &hf_dns_count_auth_rr,
      { "Authority RRs",       	"dns.count.auth_rr",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of authoritative records in packet", HFILL }},
    { &hf_dns_count_add_rr,
      { "Additional RRs",      	"dns.count.add_rr",  
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of additional records in packet", HFILL }}
  };
  static gint *ett[] = {
    &ett_dns,
    &ett_dns_qd,
    &ett_dns_rr,
    &ett_dns_qry,
    &ett_dns_ans,
    &ett_dns_flags,
    &ett_t_key_flags,
  };
  module_t *dns_module;

  proto_dns = proto_register_protocol("Domain Name Service", "DNS", "dns");
  proto_register_field_array(proto_dns, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dns_module = prefs_register_protocol(proto_dns, NULL);
  prefs_register_bool_preference(dns_module, "desegment_dns_messages",
    "Desegment all DNS messages spanning multiple TCP segments",
    "Whether the DNS dissector should desegment all messages spanning multiple TCP segments",
    &dns_desegment);
}

void
proto_reg_handoff_dns(void)
{
  dissector_handle_t dns_udp_handle;
  dissector_handle_t dns_tcp_handle;

  dns_udp_handle = create_dissector_handle(dissect_dns_udp, proto_dns);
  dns_tcp_handle = create_dissector_handle(dissect_dns_tcp, proto_dns);
  dissector_add("udp.port", UDP_PORT_DNS, dns_udp_handle);
  dissector_add("tcp.port", TCP_PORT_DNS, dns_tcp_handle);
}
