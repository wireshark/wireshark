/* packet-dns.c
 * Routines for DNS packet disassembly
 *
 * RFC 1034, RFC 1035
 * RFC 2136 for dynamic DNS
 * http://files.multicastdns.org/draft-cheshire-dnsext-multicastdns.txt
 *  for multicast DNS
 *
 * $Id$
 *
 * Copyright 2004, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
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

#include <stdio.h>
#include <string.h>
#include <memory.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include "packet-dns.h"
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/emem.h>

static int proto_dns = -1;
static int hf_dns_length = -1;
static int hf_dns_flags = -1;
static int hf_dns_flags_response = -1;
static int hf_dns_flags_opcode = -1;
static int hf_dns_flags_authoritative = -1;
static int hf_dns_flags_truncated = -1;
static int hf_dns_flags_recdesired = -1;
static int hf_dns_flags_recavail = -1;
static int hf_dns_flags_z = -1;
static int hf_dns_flags_authenticated = -1;
static int hf_dns_flags_checkdisable = -1;
static int hf_dns_flags_rcode = -1;
static int hf_dns_transaction_id = -1;
static int hf_dns_count_questions = -1;
static int hf_dns_count_zones = -1;
static int hf_dns_count_answers = -1;
static int hf_dns_count_prerequisites = -1;
static int hf_dns_count_updates = -1;
static int hf_dns_count_auth_rr = -1;
static int hf_dns_count_add_rr = -1;
static int hf_dns_qry_name = -1;
static int hf_dns_qry_type = -1;
static int hf_dns_qry_class = -1;
static int hf_dns_qry_class_mdns = -1;
static int hf_dns_qry_qu = -1;
static int hf_dns_rr_name = -1;
static int hf_dns_rr_type = -1;
static int hf_dns_rr_class = -1;
static int hf_dns_rr_class_mdns = -1;
static int hf_dns_rr_cache_flush = -1;
static int hf_dns_rr_ttl = -1;
static int hf_dns_rr_len = -1;
static int hf_dns_tsig_error = -1;
static int hf_dns_tsig_fudge = -1;
static int hf_dns_tsig_mac_size = -1;
static int hf_dns_tsig_mac = -1;
static int hf_dns_tsig_original_id = -1;
static int hf_dns_tsig_algorithm_name = -1;
static int hf_dns_tsig_other_len = -1;
static int hf_dns_tsig_other_data = -1;
static int hf_dns_response_in = -1;
static int hf_dns_response_to = -1;
static int hf_dns_time = -1;

static gint ett_dns = -1;
static gint ett_dns_qd = -1;
static gint ett_dns_rr = -1;
static gint ett_dns_qry = -1;
static gint ett_dns_ans = -1;
static gint ett_dns_flags = -1;
static gint ett_t_key_flags = -1;
static gint ett_t_key = -1;
static gint ett_dns_mac = -1;

static dissector_table_t dns_tsig_dissector_table=NULL;

/* desegmentation of DNS over TCP */
static gboolean dns_desegment = TRUE;

/* Dissector handle for GSSAPI */
static dissector_handle_t gssapi_handle;
static dissector_handle_t ntlmssp_handle;

/* Structure containing transaction specific information */
typedef struct _dns_transaction_t {
        guint32 req_frame;
        guint32 rep_frame;
        nstime_t req_time;
} dns_transaction_t;

/* Structure containing conversation specific information */
typedef struct _dns_conv_info_t {
        emem_tree_t *pdus;
} dns_conv_info_t;

/* DNS structs and definitions */

/* Ports used for DNS. */
#define UDP_PORT_DNS     53
#define TCP_PORT_DNS     53
#define UDP_PORT_MDNS    5353
#define TCP_PORT_MDNS    5353

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
#define T_DS            43		/* Delegation Signature(RFC 3658) */
#define T_IPSECKEY      45              /* draft-ietf-ipseckey-rr */
#define T_RRSIG         46              /* future RFC 2535bis */
#define T_NSEC          47              /* future RFC 2535bis */
#define T_DNSKEY        48              /* future RFC 2535bis */
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

#define C_QU		(1<<15)		/* High bit is set in queries for unicast queries */
#define C_FLUSH         (1<<15)         /* High bit is set for MDNS cache flush */

/* Bit fields in the flags */
#define F_RESPONSE      (1<<15)         /* packet is response */
#define F_OPCODE        (0xF<<11)       /* query opcode */
#define OPCODE_SHIFT	11
#define F_AUTHORITATIVE (1<<10)         /* response is authoritative */
#define F_TRUNCATED     (1<<9)          /* response is truncated */
#define F_RECDESIRED    (1<<8)          /* recursion desired */
#define F_RECAVAIL      (1<<7)          /* recursion available */
#define F_Z		(1<<6)		/* Z */
#define F_AUTHENTIC     (1<<5)          /* authentic data (RFC2535) */
#define F_CHECKDISABLE  (1<<4)          /* checking disabled (RFC2535) */
#define F_RCODE         (0xF<<0)        /* reply code */

static const true_false_string tfs_flags_response = {
	"Message is a response",
	"Message is a query"
};

static const true_false_string tfs_flags_authoritative = {
	"Server is an authority for domain",
	"Server is not an authority for domain"
};

static const true_false_string tfs_flags_truncated = {
	"Message is truncated",
	"Message is not truncated"
};

static const true_false_string tfs_flags_recdesired = {
	"Do query recursively",
	"Don't do query recursively"
};

static const true_false_string tfs_flags_recavail = {
	"Server can do recursive queries",
	"Server can't do recursive queries"
};

static const true_false_string tfs_flags_z = {
	"reserved - incorrect!",
	"reserved (0)"
};

static const true_false_string tfs_flags_authenticated = {
	"Answer/authority portion was authenticated by the server",
	"Answer/authority portion was not authenticated by the server"
};

static const true_false_string tfs_flags_checkdisable = {
	"Non-authenticated data is acceptable",
	"Non-authenticated data is unacceptable"
};

/* Opcodes */
#define OPCODE_QUERY    0         /* standard query */
#define OPCODE_IQUERY   1         /* inverse query */
#define OPCODE_STATUS   2         /* server status request */
#define OPCODE_NOTIFY   4         /* zone change notification */
#define OPCODE_UPDATE   5         /* dynamic update */

static const value_string opcode_vals[] = {
	  { OPCODE_QUERY,  "Standard query"           },
	  { OPCODE_IQUERY, "Inverse query"            },
	  { OPCODE_STATUS, "Server status request"    },
	  { OPCODE_NOTIFY, "Zone change notification" },
	  { OPCODE_UPDATE, "Dynamic update"           },
	  { 0,              NULL                      } };

/* Reply codes */
#define RCODE_NOERROR   0
#define RCODE_FORMERR   1
#define RCODE_SERVFAIL  2
#define RCODE_NXDOMAIN  3
#define RCODE_NOTIMPL   4
#define RCODE_REFUSED   5
#define RCODE_YXDOMAIN  6
#define RCODE_YXRRSET   7
#define RCODE_NXRRSET   8
#define RCODE_NOTAUTH   9
#define RCODE_NOTZONE   10

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

#define TDSDIGEST_RESERVED (0)
#define TDSDIGEST_SHA1     (1)

/* See RFC 1035 for all RR types for which no RFC is listed, except for
   the ones with "???", and for the Microsoft WINS and WINS-R RRs, for
   which one should look at

http://www.windows.com/windows2000/en/server/help/sag_DNS_imp_UsingWinsLookup.htm

   and

http://www.microsoft.com/windows2000/library/resources/reskit/samplechapters/cncf/cncf_imp_wwaw.asp

   which discuss them to some extent. */

static const value_string dns_types[] = {
	{ 0,		"Unused" },
	{ T_A,		"A" },
	{ T_NS,		"NS" },
	{ T_MD,		"MD" },
	{ T_MF,		"MF" },
	{ T_CNAME,	"CNAME" },
	{ T_SOA,	"SOA" },
	{ T_MB,		"MB" },
	{ T_MG,		"MG" },
	{ T_MR,		"MR" },
	{ T_NULL,	"NULL" },
	{ T_WKS,	"WKS" },
	{ T_PTR,	"PTR" },
	{ T_HINFO,	"HINFO" },
	{ T_MINFO,	"MINFO" },
	{ T_MX,		"MX" },
	{ T_TXT,	"TXT" },
	{ T_RP,		"RP" }, /* RFC 1183 */
	{ T_AFSDB,	"AFSDB" }, /* RFC 1183 */
	{ T_X25,	"X25" }, /* RFC 1183 */
	{ T_ISDN,	"ISDN" }, /* RFC 1183 */
	{ T_RT,		"RT" }, /* RFC 1183 */
	{ T_NSAP,	"NSAP" }, /* RFC 1706 */
	{ T_NSAP_PTR,	"NSAP-PTR" }, /* RFC 1348 */
	{ T_SIG,	"SIG" }, /* RFC 2535 */
	{ T_KEY,	"KEY" }, /* RFC 2535 */
	{ T_PX,		"PX" }, /* RFC 1664 */
	{ T_GPOS,	"GPOS" }, /* RFC 1712 */
	{ T_AAAA,	"AAAA" }, /* RFC 1886 */
	{ T_LOC,	"LOC" }, /* RFC 1886 */
	{ T_NXT,	"NXT" }, /* RFC 1876 */
	{ T_EID,	"EID" },
	{ T_NIMLOC,	"NIMLOC" },
	{ T_SRV,	"SRV" }, /* RFC 2052 */
	{ T_ATMA,	"ATMA" },
	{ T_NAPTR,	"NAPTR" }, /* RFC 2168 */
	{ T_KX,		"KX" }, /* RFC 2230 */
	{ T_CERT,	"CERT" }, /* RFC 2538 */
	{ T_A6,		"A6" }, /* RFC 2874 */
	{ T_DNAME,	"DNAME" }, /* RFC 2672 */

	{ T_OPT,	"OPT" }, /* RFC 2671 */

	{ T_DS,		"DS" }, /* RFC 3658 */

	{ T_IPSECKEY,	"IPSECKEY" }, /* draft-ietf-ipseckey-rr */
	{ T_RRSIG,	"RRSIG" }, /* future RFC 2535bis */
	{ T_NSEC,	"NSEC" }, /* future RFC 2535bis */
	{ T_DNSKEY,	"DNSKEY" }, /* future RFC 2535bis */

	{ 100,		"UINFO" },
	{ 101,		"UID" },
	{ 102,		"GID" },
	{ 103,		"UNSPEC" },

	{ T_TKEY,	"TKEY"},
	{ T_TSIG,	"TSIG"},

	{ T_WINS,	"WINS"},
	{ T_WINS_R,	"WINS-R"},

	{ 251,		"IXFR"},
	{ 252,		"AXFR"},
	{ 253,		"MAILB"},
	{ 254,		"MAILA"},
	{ 255,		"ANY"},

	{0,		NULL}
};

static const char *
dns_type_name (guint type)
{
  return val_to_str(type, dns_types, "Unknown (%u)");
}

static char *
dns_type_description (guint type)
{
  static const char *type_names[] = {
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
    "EDNS0 option",			/* RFC 2671 */
    NULL,
    "Delegation Signer",                /* RFC 3658 */
    NULL,
    "key to use with IPSEC",            /* draft-ietf-ipseckey-rr */
    "RR signature",                     /* future RFC 2535bis */
    "Next secured",                     /* future RFC 2535bis */
    "DNS public key"                    /* future RFC 2535bis */
  };
  const char *short_name;
  const char *long_name;
#define MAX_STRBUF_LEN 1024
  char *strbuf;

  strbuf=ep_alloc(MAX_STRBUF_LEN);
  short_name = dns_type_name(type);
  if (short_name == NULL) {
    g_snprintf(strbuf, MAX_STRBUF_LEN, "Unknown (%u)", type);
    return strbuf;
  }
  if (type < sizeof(type_names)/sizeof(type_names[0]))
    long_name = type_names[type];
  else {
    /* special cases */
    switch (type) {
        /* meta */
      case T_TKEY:
        long_name = "Transaction Key";
        break;
      case T_TSIG:
        long_name = "Transaction Signature";
        break;

        /* queries  */
      case 251:
        long_name = "Request for incremental zone transfer";	/* RFC 1995 */
        break;
      case 252:
        long_name = "Request for full zone transfer";
        break;
      case 253:
        long_name = "Request for mailbox-related records";
        break;
      case 254:
        long_name = "Request for mail agent resource records";
        break;
      case 255:
        long_name = "Request for all records";
        break;
      default:
        long_name = NULL;
        break;
      }
  }

  if (long_name != NULL)
    g_snprintf(strbuf, MAX_STRBUF_LEN, "%s (%s)", short_name, long_name);
  else
    g_snprintf(strbuf, MAX_STRBUF_LEN, "%s", short_name);
  return strbuf;
}

static const value_string dns_classes[] = {
	{C_IN, "IN"},
	{C_CS, "CS"},
	{C_CH, "CH"},
	{C_HS, "HS"},
	{C_NONE, "NONE"},
	{C_ANY, "ANY"},
	{0,NULL}
};

const char *
dns_class_name(int class)
{
  return val_to_str(class, dns_classes, "Unknown (%u)");
}

/* This function returns the number of bytes consumed and the expanded string
 * in *name.
 * The string is allocated with ep scope and does not need to be free()d.
 * it will be automatically free()d when the packet has been dissected.
 */
int
get_dns_name(tvbuff_t *tvb, int offset, int dns_data_offset,
    char **name)
{
  int start_offset = offset;
  char *np;
  int len = -1;
  int chars_processed = 0;
  int data_size = tvb_reported_length_remaining(tvb, dns_data_offset);
  int component_len;
  int indir_offset;
  int maxname;

  const int min_len = 1;	/* Minimum length of encoded name (for root) */
	/* If we're about to return a value (probably negative) which is less
	 * than the minimum length, we're looking at bad data and we're liable
	 * to put the dissector into a loop.  Instead we throw an exception */

  maxname=MAXDNAME;
  *name=ep_alloc(maxname);
  np=*name;

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
      if (np != *name) {
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
	  int print_len;

	  bit_count = tvb_get_guint8(tvb, offset);
	  offset++;
	  label_len = (bit_count - 1) / 8 + 1;

	  if (maxname > 0) {
	    print_len = g_snprintf(np, maxname + 1, "\\[x");
	    if (print_len != -1 && print_len <= maxname) {
	      /* Some versions of g_snprintf return -1 if they'd truncate
	         the output.  Others return <buf_size> or greater. */
	      np += print_len;
	      maxname -= print_len;
	    } else {
	      /* Nothing printed, as there's no room.
	         Suppress all subsequent printing. */
	      maxname = 0;
	    }
	  }
	  while(label_len--) {
	    if (maxname > 0) {
	      print_len = g_snprintf(np, maxname + 1, "%02x",
	        tvb_get_guint8(tvb, offset));
	      if (print_len != -1 && print_len <= maxname) {
		/* Some versions of g_snprintf return -1 if they'd truncate
		 the output.  Others return <buf_size> or greater. */
		np += print_len;
		maxname -= print_len;
	      } else {
		/* Nothing printed, as there's no room.
		   Suppress all subsequent printing. */
		maxname = 0;
	      }
	    }
	    offset++;
	  }
	  if (maxname > 0) {
	    print_len = g_snprintf(np, maxname + 1, "/%d]", bit_count);
	    if (print_len != -1 && print_len <= maxname) {
	      /* Some versions of g_snprintf return -1 if they'd truncate
	         the output.  Others return <buf_size> or greater. */
	      np += print_len;
	      maxname -= print_len;
	    } else {
	      /* Nothing printed, as there's no room.
	         Suppress all subsequent printing. */
	      maxname = 0;
	    }
	  }
	}
	break;

      default:
	*name="<Unknown extended label>";
	/* Parsing will propably fail from here on, since the */
	/* label length is unknown... */
	len = offset - start_offset;
        if (len < min_len)
          THROW(ReportedBoundsError);
        return len;
      }
      break;

    case 0x80:
      THROW(ReportedBoundsError);

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
        *name="<Name contains a pointer that loops>";
        if (len < min_len)
          THROW(ReportedBoundsError);
        return len;
      }

      offset = indir_offset;
      break;	/* now continue processing from there */
    }
  }

  *np = '\0';
  /* If "len" is negative, we haven't seen a pointer, and thus haven't
     set the length, so set it. */
  if (len < 0)
    len = offset - start_offset;
  /* Zero-length name means "root server" */
  if (**name == '\0')
    *name="<Root>";
  if (len < min_len)
    THROW(ReportedBoundsError);
  return len;
}


static int
get_dns_name_type_class(tvbuff_t *tvb, int offset, int dns_data_offset,
    char **name_ret, int *name_len_ret, int *type_ret, int *class_ret)
{
  int len;
  int name_len;
  int type;
  int class;
  int start_offset = offset;

  name_len = get_dns_name(tvb, offset, dns_data_offset, name_ret);
  offset += name_len;

  type = tvb_get_ntohs(tvb, offset);
  offset += 2;

  class = tvb_get_ntohs(tvb, offset);
  offset += 2;

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
      /* "%u deg %u min %u.%03u sec %c" */
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
  g_snprintf(buf, sizeof(buf), "%u deg %u min %u.%03u sec %c", degrees, minutes, secs,
		tsecs, direction);
  return buf;
}

static int
dissect_dns_query(tvbuff_t *tvb, int offset, int dns_data_offset,
  column_info *cinfo, proto_tree *dns_tree, gboolean is_mdns)
{
  int len;
  char *name;
  char *name_out;
  int name_len;
  int type;
  int class;
  int qu;
  const char *type_name;
  int data_offset;
  int data_start;
  proto_tree *q_tree;
  proto_item *tq;

  data_start = data_offset = offset;

  len = get_dns_name_type_class(tvb, offset, dns_data_offset, &name, &name_len,
    &type, &class);
  data_offset += len;
  if (is_mdns) {
    /* Split the QU flag and the class */
    qu = class & C_QU;
    class &= ~C_QU;
  } else
    qu = 0;

  type_name = dns_type_name(type);

  /*
   * The name might contain octets that aren't printable characters,
   * format it for display.
   */
  name_out = format_text(name, strlen(name));

  if (cinfo != NULL) {
    col_append_fstr(cinfo, COL_INFO, " %s %s", type_name, name_out);
    if (is_mdns && qu)
      col_append_str(cinfo, COL_INFO, ", \"QU\" question");
  }
  if (dns_tree != NULL) {
    tq = proto_tree_add_text(dns_tree, tvb, offset, len, "%s: type %s, class %s",
		   name_out, type_name, dns_class_name(class));
    if (is_mdns && qu)
      proto_item_append_text(tq, ", \"QU\" question");
    q_tree = proto_item_add_subtree(tq, ett_dns_qd);

    proto_tree_add_string(q_tree, hf_dns_qry_name, tvb, offset, name_len, name);
    offset += name_len;

    proto_tree_add_uint_format(q_tree, hf_dns_qry_type, tvb, offset, 2, type,
		"Type: %s", dns_type_description(type));
    offset += 2;

    if (is_mdns) {
      proto_tree_add_uint(q_tree, hf_dns_qry_class_mdns, tvb, offset, 2, class);
      proto_tree_add_boolean(q_tree, hf_dns_qry_qu, tvb, offset, 2, qu);
    } else
      proto_tree_add_uint(q_tree, hf_dns_qry_class, tvb, offset, 2, class);
    
    offset += 2;
  }

  return data_offset - data_start;
}


static proto_tree *
add_rr_to_tree(proto_item *trr, int rr_type, tvbuff_t *tvb, int offset,
  const char *name, int namelen, int type, int class, int flush,
  guint ttl, gushort data_len, gboolean is_mdns)
{
  proto_tree *rr_tree;

  rr_tree = proto_item_add_subtree(trr, rr_type);
  proto_tree_add_string(rr_tree, hf_dns_rr_name, tvb, offset, namelen, name);
  offset += namelen;
  proto_tree_add_uint_format(rr_tree, hf_dns_rr_type, tvb, offset, 2, type,
		"Type: %s", dns_type_description(type));
  offset += 2;
  if (is_mdns) {
    proto_tree_add_uint(rr_tree, hf_dns_rr_class_mdns, tvb, offset, 2, class);
    proto_tree_add_boolean(rr_tree, hf_dns_rr_cache_flush, tvb, offset, 2, flush);
  } else
    proto_tree_add_uint(rr_tree, hf_dns_rr_class, tvb, offset, 2, class);
  offset += 2;
  proto_tree_add_uint_format(rr_tree, hf_dns_rr_ttl, tvb, offset, 4, ttl,
		"Time to live: %s", time_secs_to_str(ttl));
  offset += 4;
  proto_tree_add_uint(rr_tree, hf_dns_rr_len, tvb, offset, 2, data_len);
  return rr_tree;
}


static proto_tree *
add_opt_rr_to_tree(proto_item *trr, int rr_type, tvbuff_t *tvb, int offset,
  const char *name, int namelen, int type, int class,
  guint ttl, gushort data_len)
{
  proto_tree *rr_tree, *Z_tree;
  proto_item *Z_item = NULL;

  rr_tree = proto_item_add_subtree(trr, rr_type);
  proto_tree_add_string(rr_tree, hf_dns_rr_name, tvb, offset, namelen, name);
  offset += namelen;
  proto_tree_add_uint_format(rr_tree, hf_dns_rr_type, tvb, offset, 2, type,
		"Type: %s", dns_type_description(type));
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
  Z_item = proto_tree_add_text(rr_tree, tvb, offset, 2, "Z: 0x%x", ttl & 0xffff);
  if (ttl & 0x8000) {
     Z_tree = proto_item_add_subtree(Z_item, rr_type);
     proto_tree_add_text(Z_tree, tvb, offset, 2, "Bit 0 (DO bit): 1 (Accepts DNSSEC security RRs)");
     proto_tree_add_text(Z_tree, tvb, offset, 2, "Bits 1-15: 0x%x (reserved)", (ttl >> 17) & 0xff);
  }
  offset += 2;
  proto_tree_add_uint(rr_tree, hf_dns_rr_len, tvb, offset, 2, data_len);
  return rr_tree;
}

/*
 * SIG, KEY, and CERT RR algorithms.
 */
#define	DNS_ALGO_RSAMD5		1	/* RSA/MD5 */
#define	DNS_ALGO_DH		2	/* Diffie-Hellman */
#define	DNS_ALGO_DSA		3	/* DSA */
#define	DNS_ALGO_ECC		4	/* Elliptic curve crypto */
#define DNS_ALGO_RSASHA1        5	/* RSA/SHA1 */
#define DNS_ALGO_HMACMD5        157	/* HMAC/MD5 */
#define	DNS_ALGO_INDIRECT	252	/* Indirect key */
#define	DNS_ALGO_PRIVATEDNS	253	/* Private, domain name  */
#define	DNS_ALGO_PRIVATEOID	254	/* Private, OID */

static const value_string algo_vals[] = {
	  { DNS_ALGO_RSAMD5,     "RSA/MD5" },
	  { DNS_ALGO_DH,         "Diffie-Hellman" },
	  { DNS_ALGO_DSA,        "DSA" },
	  { DNS_ALGO_ECC,        "Elliptic curve crypto" },
	  { DNS_ALGO_RSASHA1,    "RSA/SHA1" },
	  { DNS_ALGO_HMACMD5,    "HMAC/MD5" },
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

/**
 *   Compute the key id of a KEY RR depending of the algorithm used.
 */
static guint16
compute_key_id(tvbuff_t *tvb, int offset, int size, guint8 algo) 
{
  guint32 ac;
  guint8 c1, c2;

  DISSECTOR_ASSERT(size >= 4);
  
  switch( algo ) {
     case DNS_ALGO_RSAMD5:
       return (guint16)(tvb_get_guint8(tvb, offset + size - 3) << 8) + tvb_get_guint8( tvb, offset + size - 2 );
     default:
       for (ac = 0; size > 1; size -= 2, offset += 2) {
	 c1 = tvb_get_guint8( tvb, offset );
	 c2 = tvb_get_guint8( tvb, offset + 1 );
	 ac +=  (c1 << 8) + c2 ;
       }
       if (size > 0) {
	 c1 = tvb_get_guint8( tvb, offset );
	 ac += c1 << 8;
       }
       ac += (ac >> 16) & 0xffff;
       return (guint16)(ac & 0xffff);
  }
}


static int
dissect_dns_answer(tvbuff_t *tvb, int offset, int dns_data_offset,
  column_info *cinfo, proto_tree *dns_tree, packet_info *pinfo,
  gboolean is_mdns)
{
  int len;
  char *name;
  char *name_out;
  int name_len;
  int type;
  int class;
  int flush;
  const char *class_name;
  const char *type_name;
  int data_offset;
  int cur_offset;
  int data_start;
  guint ttl;
  gushort data_len;
  proto_tree *rr_tree = NULL;
  proto_item *trr = NULL;

  data_start = data_offset = offset;
  cur_offset = offset;

  len = get_dns_name_type_class(tvb, offset, dns_data_offset, &name, &name_len,
    &type, &class);
  data_offset += len;
  cur_offset += len;
  if (is_mdns && type != T_OPT) {
    /* Split the FLUSH flag and the class */
    flush = class & C_FLUSH;
    class &= ~C_FLUSH;
  } else
    flush = 0;

  type_name = dns_type_name(type);
  class_name = dns_class_name(class);

  ttl = tvb_get_ntohl(tvb, data_offset);
  data_offset += 4;
  cur_offset += 4;

  data_len = tvb_get_ntohs(tvb, data_offset);
  data_offset += 2;
  cur_offset += 2;

  if (cinfo != NULL) {
    col_append_fstr(cinfo, COL_INFO, " %s", type_name);
    if (is_mdns && flush)
      col_append_str(cinfo, COL_INFO, ", cache flush");
  }
  if (dns_tree != NULL) {
    /*
     * The name might contain octets that aren't printable characters,
     * format it for display.
     */
    name_out = format_text(name, strlen(name));
    if (type != T_OPT) {
      trr = proto_tree_add_text(dns_tree, tvb, offset,
		    (data_offset - data_start) + data_len,
		    "%s: type %s, class %s",
		    name_out, type_name, class_name);
      if (is_mdns && flush)
        proto_item_append_text(trr, ", cache flush");
      rr_tree = add_rr_to_tree(trr, ett_dns_rr, tvb, offset, name, name_len,
		     type, class, flush, ttl, data_len, is_mdns);
    } else  {
      trr = proto_tree_add_text(dns_tree, tvb, offset,
		    (data_offset - data_start) + data_len,
		    "%s: type %s", name_out, type_name);
      rr_tree = add_opt_rr_to_tree(trr, ett_dns_rr, tvb, offset, name, name_len,
		     type, class, ttl, data_len);
    }
  }

  if (data_len == 0)
    return data_offset - data_start;

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
      if ((class & 0x7f) == C_IN) {
	memcpy(&addr_int, addr, sizeof(addr_int));
	add_ipv4_name(addr_int, name);
      }
    }
    break;

  case T_NS:
    {
      char *ns_name;
      int ns_name_len;

      ns_name_len = get_dns_name(tvb, cur_offset, dns_data_offset, &ns_name);
      name_out = format_text(ns_name, strlen(ns_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", ns %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, ns_name_len, "Name server: %s",
			name_out);
      }
    }
    break;

  case T_CNAME:
    {
      char *cname;
      int cname_len;

      cname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &cname);
      name_out = format_text(cname, strlen(cname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", cname %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, cname_len, "Primary name: %s",
			name_out);
      }
    }
    break;

  case T_SOA:
    {
      char *mname;
      int mname_len;
      char *rname;
      int rname_len;
      guint32 serial;
      guint32 refresh;
      guint32 retry;
      guint32 expire;
      guint32 minimum;

      mname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &mname);
      name_out = format_text(mname, strlen(mname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", mname %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, mname_len, "Primary name server: %s",
		       name_out);
	cur_offset += mname_len;

	rname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &rname);
        name_out = format_text(rname, strlen(rname));
	proto_tree_add_text(rr_tree, tvb, cur_offset, rname_len, "Responsible authority's mailbox: %s",
		       name_out);
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
      char *pname;
      int pname_len;

      pname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &pname);
      name_out = format_text(pname, strlen(pname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, pname_len, "Domain name: %s",
			name_out);
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
      char *bitnames, *strptr;

#define MAX_STR_LEN 128
      bitnames=ep_alloc(MAX_STR_LEN);
      bitnames[0]=0;
      strptr=bitnames;

      if (rr_len < 4) {
	if (dns_tree != NULL)
	  goto bad_rr;
	break;
      }
      wks_addr = tvb_get_ptr(tvb, cur_offset, 4);
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", ip_to_str(wks_addr));
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", addr %s", ip_to_str(wks_addr));
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Addr: %s",
		     ip_to_str(wks_addr));
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 1)
	  goto bad_rr;
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
            bitnames[0]=0;
            strptr=bitnames;
	    for (i = 0; i < 8; i++) {
	      if (bits & mask) {
		if (strptr!=bitnames)
		  strptr += MIN(MAX_STR_LEN-(strptr-bitnames),
				g_snprintf(strptr, MAX_STR_LEN-(strptr-bitnames), ", "));
		switch (protocol) {

		case IP_PROTO_TCP:
		  strptr += MIN(MAX_STR_LEN-(strptr-bitnames),
				g_snprintf(strptr, MAX_STR_LEN-(strptr-bitnames), get_tcp_port(port_num)));
		  break;

		case IP_PROTO_UDP:
		  strptr += MIN(MAX_STR_LEN-(strptr-bitnames),
				g_snprintf(strptr, MAX_STR_LEN-(strptr-bitnames), get_udp_port(port_num)));
		  break;

		default:
		  strptr += MIN(MAX_STR_LEN-(strptr-bitnames),
				g_snprintf(strptr, MAX_STR_LEN-(strptr-bitnames), "%u", port_num));
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
      char *mx_name;
      int mx_name_len;

      preference = tvb_get_ntohs(tvb, cur_offset);
      mx_name_len = get_dns_name(tvb, cur_offset + 2, dns_data_offset, &mx_name);
      name_out = format_text(mx_name, strlen(mx_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %u %s", preference, name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", preference %u, mx %s",
		       preference, name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Preference: %u", preference);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 2, mx_name_len, "Mail exchange: %s",
			name_out);
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

  case T_RRSIG:
  case T_SIG:
    {
      int rr_len = data_len;
      guint16 type_covered;
      nstime_t nstime;
      char *signer_name;
      int signer_name_len;

      if (dns_tree != NULL) {
	if (rr_len < 2)
	  goto bad_rr;
	type_covered = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Type covered: %s",
		dns_type_description(type_covered));
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 1)
	  goto bad_rr;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(tvb_get_guint8(tvb, cur_offset), algo_vals,
	            "Unknown (0x%02X)"));
	cur_offset += 1;
	rr_len -= 1;

	if (rr_len < 1)
	  goto bad_rr;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Labels: %u",
		tvb_get_guint8(tvb, cur_offset));
	cur_offset += 1;
	rr_len -= 1;

	if (rr_len < 4)
	  goto bad_rr;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Original TTL: %s",
		time_secs_to_str(tvb_get_ntohl(tvb, cur_offset)));
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 4)
	  goto bad_rr;
	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Signature expiration: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 4)
	  goto bad_rr;
	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Time signed: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 2)
	  goto bad_rr;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Id of signing key(footprint): %u",
		tvb_get_ntohs(tvb, cur_offset));
	cur_offset += 2;
	rr_len -= 2;

	signer_name_len = get_dns_name(tvb, cur_offset, dns_data_offset, &signer_name);
	proto_tree_add_text(rr_tree, tvb, cur_offset, signer_name_len,
		"Signer's name: %s",
		format_text(signer_name, strlen(signer_name)));
	cur_offset += signer_name_len;
	rr_len -= signer_name_len;

	if (rr_len != 0)
	  proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Signature");
      }
    }
    break;

  case T_DNSKEY:  
  case T_KEY:
    {
      int rr_len = data_len;
      guint16 flags;
      proto_item *tf;
      proto_tree *flags_tree;
      guint8 algo;
      guint16 key_id;

      if (dns_tree != NULL) {
	if (rr_len < 2)
	  goto bad_rr;
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
	  if( type != T_DNSKEY )
	        proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
		    decode_numeric_bitfield(flags, 0x000F,
		       2*8, "Signatory = %u"));
	    else proto_tree_add_text(flags_tree, tvb, cur_offset, 2, "%s",
 	            decode_boolean_bitfield(flags, 0x0001, 
		       2*8, "Key is a Key Signing Key",
		            "Key is a Zone Signing Key") );
	}
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 1)
	  goto bad_rr;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Protocol: %u",
		tvb_get_guint8(tvb, cur_offset));
	cur_offset += 1;
	rr_len -= 1;

	if (rr_len < 1)
	  goto bad_rr;
	algo = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(algo, algo_vals, "Unknown (0x%02X)"));
	cur_offset += 1;
	rr_len -= 1;

	key_id = compute_key_id(tvb, cur_offset-4, rr_len+4, algo);
	proto_tree_add_text(rr_tree, tvb, 0, 0, "Key id: %u", key_id);

	if (rr_len != 0)
	  proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Public key");
      }
    }
    break;
  case T_IPSECKEY:
    {
      int rr_len = data_len;
      guint8 gw_type, algo;
      const guint8 *addr;
      char *gw;
      int gw_name_len;
      static const value_string gw_algo[] = {
	  { 1,     "DSA" },
	  { 2,     "RSA" },
	  { 0,      NULL }
      };
      

      if( dns_tree != NULL ) {
	if(rr_len < 3) 
	  goto bad_rr;

	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Gateway precedence: %u",
		tvb_get_guint8(tvb, cur_offset));
	cur_offset += 1;
	rr_len -= 1;

	gw_type = tvb_get_guint8(tvb, cur_offset);
	cur_offset += 1;
	rr_len -= 1;

	algo = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(algo, gw_algo, "Unknown (0x%02X)"));
	cur_offset += 1;
	rr_len -= 1;
	switch( gw_type ) {
	   case 0:
	     proto_tree_add_text(rr_tree, tvb, cur_offset, 0, "Gateway: no gateway");
	     break;
	   case 1:
	     addr = tvb_get_ptr(tvb, cur_offset, 4);
	     proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Gateway: %s",
				 ip_to_str(addr) );

	     cur_offset += 4;
	     rr_len -= 4;
	     break;
	   case 2:
	     addr = tvb_get_ptr(tvb, cur_offset, 16);
	     proto_tree_add_text(rr_tree, tvb, cur_offset, 16, "Gateway: %s", 
				 ip6_to_str((const struct e_in6_addr *)addr));

	     cur_offset += 16;
	     rr_len -= 16;
	     break;
	   case 3:
	     gw_name_len = get_dns_name(tvb, cur_offset, dns_data_offset, &gw);
	     proto_tree_add_text(rr_tree, tvb, cur_offset, gw_name_len,
				 "Gateway: %s", format_text(gw, strlen(gw)));

	     cur_offset += gw_name_len;
	     rr_len -= gw_name_len;	     
	     break;
	   default:
	     proto_tree_add_text(rr_tree, tvb, cur_offset, 0, "Gateway: Unknow gateway type(%u)", gw_type);
	     break;
	}
	if (rr_len != 0)
	  proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Public key");	
      }
    }
    break;

  case T_AAAA:
    {
      const guint8 *addr6;
      struct e_in6_addr addr_in6;

      addr6 = tvb_get_ptr(tvb, cur_offset, 16);
      if (cinfo != NULL) {
	col_append_fstr(cinfo, COL_INFO, " %s",
			ip6_to_str((const struct e_in6_addr *)addr6));
      }
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", addr %s",
		     ip6_to_str((const struct e_in6_addr *)addr6));
	proto_tree_add_text(rr_tree, tvb, cur_offset, 16, "Addr: %s",
		     ip6_to_str((const struct e_in6_addr *)addr6));
      }
      if ((class & 0x7f) == C_IN) {
	memcpy(&addr_in6, addr6, sizeof(addr_in6));
	add_ipv6_name(&addr_in6, name);
      }
    }
    break;

  case T_A6:
    {
      unsigned short pre_len;
      unsigned short suf_len;
      unsigned short suf_octet_count;
      char *pname;
      int pname_len;
      int a6_offset;
      int suf_offset;
      struct e_in6_addr suffix;

      a6_offset = cur_offset;
      pre_len = tvb_get_guint8(tvb, cur_offset);
      cur_offset++;
      suf_len = 128 - pre_len;
      suf_octet_count = suf_len ? (suf_len - 1) / 8 + 1 : 0;
      /* Pad prefix */
      for (suf_offset = 0; suf_offset < 16 - suf_octet_count; suf_offset++) {
        suffix.bytes[suf_offset] = 0;
      }
      for (; suf_offset < 16; suf_offset++) {
        suffix.bytes[suf_offset] = tvb_get_guint8(tvb, cur_offset);
        cur_offset++;
      }

      if (pre_len > 0) {
        pname_len = get_dns_name(tvb, cur_offset, dns_data_offset,
                                 &pname);
      } else {
        pname="";
        pname_len = 0;
      }
      name_out = format_text(pname, strlen(pname));

      if (cinfo != NULL) {
        col_append_fstr(cinfo, COL_INFO, " %d %s %s",
                        pre_len,
                        ip6_to_str(&suffix),
                        name_out);
      }
      if (dns_tree != NULL) {
        proto_tree_add_text(rr_tree, tvb, a6_offset, 1,
                            "Prefix len: %u", pre_len);
        a6_offset++;
        if (suf_len) {
          proto_tree_add_text(rr_tree, tvb, a6_offset, suf_octet_count,
                              "Address suffix: %s",
                              ip6_to_str(&suffix));
          a6_offset += suf_octet_count;
        }
        if (pre_len > 0) {
          proto_tree_add_text(rr_tree, tvb, a6_offset, pname_len,
                              "Prefix name: %s", name_out);
        }
        proto_item_append_text(trr, ", addr %d %s %s",
                            pre_len,
                            ip6_to_str(&suffix),
                            name_out);
      }
    }
    break;

  case T_DNAME:
    {
      char *dname;
      int dname_len;

      dname_len = get_dns_name(tvb, cur_offset, dns_data_offset,
			       &dname);
      name_out = format_text(dname, strlen(dname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", dname %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset,
			    dname_len, "Target name: %s", name_out);
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
				((gint32)tvb_get_ntohl(tvb, cur_offset) - 10000000)/100.0);
	} else
	  proto_tree_add_text(rr_tree, tvb, cur_offset, data_len, "Data");
      }
    }
    break;

  case T_NSEC:
    {
      int rr_len = data_len;
      char *next_domain_name;
      int next_domain_name_len;
      int rr_type;
      guint8 bits;
      int mask, blockbase, blocksize;
      int i;

      next_domain_name_len = get_dns_name(tvb, cur_offset, dns_data_offset,
			&next_domain_name);
      name_out = format_text(next_domain_name, strlen(next_domain_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", next domain name %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, next_domain_name_len,
			"Next domain name: %s", name_out);
	cur_offset += next_domain_name_len;
	rr_len -= next_domain_name_len;
	rr_type = 0;
	while (rr_len != 0) {
	  blockbase = tvb_get_guint8(tvb, cur_offset);
	  blocksize = tvb_get_guint8(tvb, cur_offset + 1);
	  cur_offset += 2;
	  rr_len -= 2;
	  rr_type = blockbase * 256;
	  for( ; blocksize; blocksize-- ) {	    
  	       bits = tvb_get_guint8(tvb, cur_offset);
	       mask = 1<<7;
	       for (i = 0; i < 8; i++) {
		 if (bits & mask) {
		   proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
			"RR type in bit map: %s",
			dns_type_description(rr_type));
		 }
		 mask >>= 1;
		 rr_type++;
	       }
	       cur_offset += 1;
	       rr_len -= 1;
	  }
        }
      }
    }
    break;

  case T_NXT:
    {
      int rr_len = data_len;
      char *next_domain_name;
      int next_domain_name_len;
      int rr_type;
      guint8 bits;
      int mask;
      int i;

      next_domain_name_len = get_dns_name(tvb, cur_offset, dns_data_offset,
			&next_domain_name);
      name_out = format_text(next_domain_name, strlen(next_domain_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", next domain name %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, next_domain_name_len,
			"Next domain name: %s", name_out);
	cur_offset += next_domain_name_len;
	rr_len -= next_domain_name_len;
	rr_type = 0;
	while (rr_len != 0) {
	  bits = tvb_get_guint8(tvb, cur_offset);
	  mask = 1<<7;
	  for (i = 0; i < 8; i++) {
	    if (bits & mask) {
	      proto_tree_add_text(rr_tree, tvb, cur_offset, 1,
			"RR type in bit map: %s",
			dns_type_description(rr_type));
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
      char *kx_name;
      int kx_name_len;

      preference = tvb_get_ntohs(tvb, cur_offset);
      kx_name_len = get_dns_name(tvb, cur_offset + 2, dns_data_offset, &kx_name);
      name_out = format_text(kx_name, strlen(kx_name));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %u %s", preference, name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", preference %u, kx %s",
		       preference, name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Preference: %u", preference);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 2, kx_name_len, "Key exchange: %s",
			name_out);
      }
    }
    break;

  case T_CERT:
    {
      guint16 cert_type, cert_keytag;
      guint8 cert_keyalg;
      int rr_len = data_len;

      if (dns_tree != NULL) {
	if (rr_len < 2)
	  goto bad_rr;
	cert_type = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Type: %s",
		val_to_str(cert_type, cert_vals,
	            "Unknown (0x%02X)"));
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 2)
	  goto bad_rr;
	cert_keytag = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Key footprint: 0x%04x",
		cert_keytag);
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 1)
	  goto bad_rr;
	cert_keyalg = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s",
		val_to_str(cert_keyalg, algo_vals,
	            "Unknown (0x%02X)"));
	cur_offset += 1;
	rr_len -= 1;

	if (rr_len != 0)
	  proto_tree_add_text(rr_tree, tvb, cur_offset, rr_len, "Public key");
      }
    }
    break;

  case T_OPT:
    if (dns_tree != NULL)
      proto_tree_add_text(rr_tree, tvb, cur_offset, data_len, "Data");
    break;

  case T_DS:
    {
      guint16 keytag, digest_data_size = -1;
      guint8  ds_algorithm, ds_digest;
      int rr_len = data_len;

      static const value_string tds_digests[] = {
	{ TDSDIGEST_RESERVED, "Reserved digest" },
	{ TDSDIGEST_SHA1,     "SHA-1" },
	{ 0, NULL }
      };

      if (dns_tree != NULL) {
	if (rr_len < 2)
	  goto bad_rr;
	keytag = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Key id: %04u", keytag);
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 1)
	  goto bad_rr;
	ds_algorithm = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Algorithm: %s", val_to_str(ds_algorithm, algo_vals,"Unknown (0x%02X)") );
	cur_offset += 1;
	rr_len -= 1;

	if (rr_len < 1)
	  goto bad_rr;
	ds_digest = tvb_get_guint8(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 1, "Digest type: %s", val_to_str(ds_digest, tds_digests, "Unknown (0x%02X)"));
	cur_offset += 1;
	rr_len -= 1;

	if (ds_digest == TDSDIGEST_SHA1)
	  digest_data_size = 20; /* SHA1 key is always 20 bytes long */
	if (digest_data_size > 0) {
	  if (rr_len < digest_data_size)
	    goto bad_rr;
	  proto_tree_add_text(rr_tree, tvb, cur_offset, digest_data_size, "Public key"); 
	}
      }
    }
    break;

  case T_TKEY:
    {
      char *tkey_algname;
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
	proto_tree *key_tree;
	proto_item *key_item;

	tkey_algname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &tkey_algname);
	proto_tree_add_text(rr_tree, tvb, cur_offset, tkey_algname_len,
		"Algorithm name: %s",
		format_text(tkey_algname, strlen(tkey_algname)));
	cur_offset += tkey_algname_len;
	rr_len -= tkey_algname_len;

	if (rr_len < 4)
	  goto bad_rr;
	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Signature inception: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 4)
	  goto bad_rr;
	nstime.secs = tvb_get_ntohl(tvb, cur_offset);
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Signature expiration: %s",
		abs_time_to_str(&nstime));
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 2)
	  goto bad_rr;
	tkey_mode = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Mode: %s",
		val_to_str(tkey_mode, tkey_modes,
	            "Unknown (0x%04X)"));
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 2)
	  goto bad_rr;
	tkey_error = tvb_get_ntohs(tvb, cur_offset);
        proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Error: %s",
		val_to_str(tkey_error, rcode_vals,
		val_to_str(tkey_error, tsigerror_vals, "Unknown error (%x)")));
	cur_offset += 2;
	rr_len -= 2;

	tkey_keylen = tvb_get_ntohs(tvb, cur_offset);
        proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Key Size: %u",
            tkey_keylen);
	cur_offset += 2;
	rr_len -= 2;

	if (tkey_keylen != 0) {
		key_item = proto_tree_add_text(
			rr_tree, tvb, cur_offset, tkey_keylen, "Key Data");

		key_tree = proto_item_add_subtree(key_item, ett_t_key);

		switch(tkey_mode) {
		case TKEYMODE_GSSAPI: {
			tvbuff_t *gssapi_tvb;

			/*
			 * XXX - in at least one capture, this appears to
			 * be an NTLMSSP blob, with no ASN.1 in it, in
			 * a query.
			 *
			 * See RFC 3645 which might indicate what's going
			 * on here.  (The key is an output_token from
			 * GSS_Init_sec_context.)
			 *
			 * How the heck do we know what method is being
			 * used, so we know how to decode the key?  Do we
			 * have to look at the algorithm name, e.g.
			 * "gss.microsoft.com"?  We currently do as the
			 * the SMB dissector does in some cases, and check
			 * whether the security blob begins with "NTLMSSP".
			 */
			gssapi_tvb = tvb_new_subset(
				tvb, cur_offset, tkey_keylen, tkey_keylen);
			if(tvb_strneql(gssapi_tvb, 0, "NTLMSSP", 7) == 0)
				call_dissector(ntlmssp_handle, gssapi_tvb, pinfo, key_tree);
			else
				call_dissector(gssapi_handle, gssapi_tvb, pinfo,
				key_tree);

			break;
		}
		default:

			/* No dissector for this key mode */

			break;
		}

		cur_offset += tkey_keylen;
		rr_len -= tkey_keylen;
	}

	if (rr_len < 2)
	  goto bad_rr;
	tkey_otherlen = tvb_get_ntohs(tvb, cur_offset);
        proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Other Size: %u",
            tkey_otherlen);
	cur_offset += 2;
	rr_len -= 2;

	if (tkey_otherlen != 0) {
	  if (rr_len < tkey_otherlen)
	    goto bad_rr;
	  proto_tree_add_text(rr_tree, tvb, cur_offset, tkey_otherlen, "Other Data");
	  cur_offset += tkey_otherlen;
	  rr_len -= tkey_otherlen;
	}
      }
    }
    break;

  case T_TSIG:
    {
      guint16 tsig_error, tsig_timehi, tsig_siglen, tsig_otherlen;
      guint32 tsig_timelo;
      char *tsig_raw_algname, *tsig_algname;
      int tsig_algname_len;
      nstime_t nstime;
      int rr_len = data_len;

      if (dns_tree != NULL) {
	tsig_algname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &tsig_raw_algname);
	tsig_algname=format_text(tsig_raw_algname, strlen(tsig_raw_algname));
	proto_tree_add_string(rr_tree, hf_dns_tsig_algorithm_name, tvb, cur_offset, tsig_algname_len, tsig_algname);
	cur_offset += tsig_algname_len;
	rr_len -= tsig_algname_len;

	if (rr_len < 6)
	  goto bad_rr;
	tsig_timehi = tvb_get_ntohs(tvb, cur_offset);
	tsig_timelo = tvb_get_ntohl(tvb, cur_offset + 2);
	nstime.secs = tsig_timelo;
	nstime.nsecs = 0;
	proto_tree_add_text(rr_tree, tvb, cur_offset, 6, "Time signed: %s%s",
		abs_time_to_str(&nstime), tsig_timehi == 0 ? "" : "(high bits set)");
	cur_offset += 6;
	rr_len -= 6;

	if (rr_len < 2)
	  goto bad_rr;

	proto_tree_add_item(rr_tree, hf_dns_tsig_fudge, tvb, cur_offset, 2, FALSE);
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 2)
	  goto bad_rr;
	tsig_siglen = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_item(rr_tree, hf_dns_tsig_mac_size, tvb, cur_offset, 2, FALSE);
	cur_offset += 2;
	rr_len -= 2;

	if (tsig_siglen != 0) {
	  proto_item *mac_item;
	  proto_tree *mac_tree;
	  tvbuff_t *sub_tvb;

	  if (rr_len < tsig_siglen)
	    goto bad_rr;

	  mac_item = proto_tree_add_item(rr_tree, hf_dns_tsig_mac, tvb, cur_offset, tsig_siglen, FALSE);
	  mac_tree = proto_item_add_subtree(mac_item, ett_dns_mac);

	  sub_tvb=tvb_new_subset(tvb, cur_offset, tsig_siglen, tsig_siglen);

	  if(!dissector_try_string(dns_tsig_dissector_table, tsig_algname, sub_tvb, pinfo, mac_tree)){
		proto_tree_add_text(mac_tree, sub_tvb, 0, tvb_length(sub_tvb), "No dissector for algorithm:%s", tsig_algname);
	  }

	  cur_offset += tsig_siglen;
	  rr_len -= tsig_siglen;
	}

	if (rr_len < 2)
	  goto bad_rr;
	proto_tree_add_item(rr_tree, hf_dns_tsig_original_id, tvb, cur_offset, 2, FALSE);
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 2)
	  goto bad_rr;
	tsig_error = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_uint_format(rr_tree, hf_dns_tsig_error, tvb, cur_offset, 2, tsig_error, "Error: %s (%d)",
		val_to_str(tsig_error, rcode_vals,val_to_str(tsig_error, tsigerror_vals, "Unknown error")),
		tsig_error);
	cur_offset += 2;
	rr_len -= 2;

	if (rr_len < 2)
	  goto bad_rr;
	tsig_otherlen = tvb_get_ntohs(tvb, cur_offset);
	proto_tree_add_item(rr_tree, hf_dns_tsig_other_len, tvb, cur_offset, 2, FALSE);
	cur_offset += 2;
	rr_len -= 2;

	if (tsig_otherlen != 0) {
	  if (rr_len < tsig_otherlen)
	    goto bad_rr;
	  proto_tree_add_item(rr_tree, hf_dns_tsig_other_data, tvb, cur_offset, tsig_otherlen, FALSE);
	  cur_offset += tsig_otherlen;
	  rr_len -= tsig_otherlen;
	}
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
	if (rr_len < 4)
	  goto bad_rr;
	local_flag = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Local flag: %s",
		       local_flag ? "true" : "false");
	}
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 4)
	  goto bad_rr;
	lookup_timeout = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Lookup timeout: %u seconds",
		       lookup_timeout);
	}
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 4)
	  goto bad_rr;
	cache_timeout = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Cache timeout: %u seconds",
		       cache_timeout);
	}
	cur_offset += 4;
	rr_len -= 4;

	if (rr_len < 4)
	  goto bad_rr;
	nservers = tvb_get_ntohl(tvb, cur_offset);
	if (dns_tree != NULL) {
	  proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Number of WINS servers: %u",
		       nservers);
	}
	cur_offset += 4;
	rr_len -= 4;

	while (rr_len != 0 && nservers != 0) {
	  if (rr_len < 4)
	    goto bad_rr;
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
      char *dname;
      int dname_len;

      if (rr_len < 4)
	goto bad_rr;
      local_flag = tvb_get_ntohl(tvb, cur_offset);
      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Local flag: %s",
		       local_flag ? "true" : "false");
      }
      cur_offset += 4;
      rr_len -= 4;

      if (rr_len < 4)
	goto bad_rr;
      lookup_timeout = tvb_get_ntohl(tvb, cur_offset);
      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Lookup timeout: %u seconds",
		       lookup_timeout);
      }
      cur_offset += 4;
      rr_len -= 4;

      if (rr_len < 4)
	goto bad_rr;
      cache_timeout = tvb_get_ntohl(tvb, cur_offset);
      if (dns_tree != NULL) {
	proto_tree_add_text(rr_tree, tvb, cur_offset, 4, "Cache timeout: %u seconds",
		       cache_timeout);
      }
      cur_offset += 4;
      rr_len -= 4;

      dname_len = get_dns_name(tvb, cur_offset, dns_data_offset, &dname);
      name_out = format_text(dname, strlen(dname));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %s", name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr, ", name result domain %s", name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, dname_len, "Name result domain: %s",
			name_out);
      }
    }
    break;

  case T_SRV:
    {
      guint16 priority = 0;
      guint16 weight = 0;
      guint16 port = 0;
      char *target;
      int target_len;

      priority = tvb_get_ntohs(tvb, cur_offset);
      weight = tvb_get_ntohs(tvb, cur_offset+2);
      port = tvb_get_ntohs(tvb, cur_offset+4);

      target_len = get_dns_name(tvb, cur_offset + 6, dns_data_offset, &target);
      name_out = format_text(target, strlen(target));
      if (cinfo != NULL)
	col_append_fstr(cinfo, COL_INFO, " %u %u %u %s", priority, weight, port, name_out);
      if (dns_tree != NULL) {
	proto_item_append_text(trr,
		       ", priority %u, weight %u, port %u, target %s",
		       priority, weight, port, name_out);
	proto_tree_add_text(rr_tree, tvb, cur_offset, 2, "Priority: %u", priority);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 2, 2, "Weight: %u", weight);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 4, 2, "Port: %u", port);
	proto_tree_add_text(rr_tree, tvb, cur_offset + 6, target_len, "Target: %s",
			name_out);
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

bad_rr:
  if (dns_tree != NULL) {
    proto_item_append_text(trr, ", bad RR length %d, too short",
			data_len);
  }

  data_offset += data_len;

  return data_offset - data_start;
}

static int
dissect_query_records(tvbuff_t *tvb, int cur_off, int dns_data_offset,
    int count, column_info *cinfo, proto_tree *dns_tree, gboolean isupdate,
    gboolean is_mdns)
{
  int start_off, add_off;
  proto_tree *qatree = NULL;
  proto_item *ti = NULL;

  start_off = cur_off;
  if (dns_tree) {
    const char *s = (isupdate ?  "Zone" : "Queries");
    ti = proto_tree_add_text(dns_tree, tvb, start_off, -1, s);
    qatree = proto_item_add_subtree(ti, ett_dns_qry);
  }
  while (count-- > 0) {
    add_off = dissect_dns_query(tvb, cur_off, dns_data_offset, cinfo, qatree,
                                is_mdns);
    cur_off += add_off;
  }
  if (ti)
    proto_item_set_len(ti, cur_off - start_off);

  return cur_off - start_off;
}

static int
dissect_answer_records(tvbuff_t *tvb, int cur_off, int dns_data_offset,
    int count, column_info *cinfo, proto_tree *dns_tree, const char *name,
    packet_info *pinfo, gboolean is_mdns)
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
    add_off = dissect_dns_answer(
	    tvb, cur_off, dns_data_offset, cinfo, qatree, pinfo, is_mdns);
    cur_off += add_off;
  }
  if (ti)
    proto_item_set_len(ti, cur_off - start_off);

  return cur_off - start_off;
}

static void
dissect_dns_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean is_tcp, gboolean is_mdns)
{
  int offset = is_tcp ? 2 : 0;
  int dns_data_offset;
  column_info *cinfo;
  proto_tree *dns_tree = NULL, *field_tree;
  proto_item *ti, *tf;
  guint16    id, flags, opcode, rcode, quest, ans, auth, add;
  char *buf;
  int bufpos;
  int cur_off;
  gboolean isupdate;
  conversation_t *conversation;
  dns_conv_info_t *dns_info;
  dns_transaction_t *dns_trans;

  dns_data_offset = offset;

  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

#define MAX_BUF_SIZE (128+1)
  buf=ep_alloc(MAX_BUF_SIZE);
  buf[0]=0;
  bufpos=0;

  /* To do: check for errs, etc. */
  id    = tvb_get_ntohs(tvb, offset + DNS_ID);
  flags = tvb_get_ntohs(tvb, offset + DNS_FLAGS);
  opcode = (guint16) ((flags & F_OPCODE) >> OPCODE_SHIFT);
  rcode  = (guint16)  (flags & F_RCODE);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    bufpos=0;
    bufpos+=MIN(MAX_BUF_SIZE-bufpos,
		g_snprintf(buf+bufpos, MAX_BUF_SIZE-bufpos, "%s%s",
		val_to_str(opcode, opcode_vals, "Unknown operation (%u)"),
		(flags&F_RESPONSE)?" response":""));
		
    if (flags & F_RESPONSE) {
      if ((flags & F_RCODE) != RCODE_NOERROR) {
	bufpos+=MIN(MAX_BUF_SIZE-bufpos,
		    g_snprintf(buf+bufpos, MAX_BUF_SIZE-bufpos, ", %s",
			val_to_str(flags & F_RCODE, rcode_vals, "Unknown error (%u)")));
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
  if (opcode == OPCODE_UPDATE)
    isupdate = TRUE;
  else
    isupdate = FALSE;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_dns, tvb, 0, -1,
      "Domain Name System (%s)", (flags & F_RESPONSE) ? "response" : "query");

    dns_tree = proto_item_add_subtree(ti, ett_dns);

    /*
     * Do we have a conversation for this connection?
     */
    conversation = find_conversation(pinfo->fd->num, 
			&pinfo->src, &pinfo->dst,
			pinfo->ptype, 
			pinfo->srcport, pinfo->destport, 0);
    if (conversation == NULL) {
      /* We don't yet have a conversation, so create one. */
      conversation = conversation_new(pinfo->fd->num, 
			&pinfo->src, &pinfo->dst,
			pinfo->ptype,
			pinfo->srcport, pinfo->destport, 0);
    }
    /*
     * Do we already have a state structure for this conv
     */
    dns_info = conversation_get_proto_data(conversation, proto_dns);
    if (!dns_info) {
      /* No.  Attach that information to the conversation, and add
       * it to the list of information structures.
       */
      dns_info = se_alloc(sizeof(dns_conv_info_t));
      dns_info->pdus=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "dns_pdus");
      conversation_add_proto_data(conversation, proto_dns, dns_info);
    }
    if(!pinfo->fd->flags.visited){
      if(!(flags&F_RESPONSE)){
        /* This is a request */
        dns_trans=se_alloc(sizeof(dns_transaction_t));
        dns_trans->req_frame=pinfo->fd->num;
        dns_trans->rep_frame=0;
        dns_trans->req_time=pinfo->fd->abs_ts;
        se_tree_insert32(dns_info->pdus, id, (void *)dns_trans);
      } else {
        dns_trans=se_tree_lookup32(dns_info->pdus, id);
        if(dns_trans){
          dns_trans->rep_frame=pinfo->fd->num;
        }
      }
    } else {
      dns_trans=se_tree_lookup32(dns_info->pdus, id);
    }
    if(!dns_trans){
      /* create a "fake" pana_trans structure */
      dns_trans=ep_alloc(sizeof(dns_transaction_t));
      dns_trans->req_frame=0;
      dns_trans->rep_frame=0;
      dns_trans->req_time=pinfo->fd->abs_ts;
    }

    /* print state tracking in the tree */
    if(!(flags&F_RESPONSE)){
      /* This is a request */
      if(dns_trans->rep_frame){
        proto_item *it;

        it=proto_tree_add_uint(dns_tree, hf_dns_response_in, tvb, 0, 0, dns_trans->rep_frame);
        PROTO_ITEM_SET_GENERATED(it);
      }
    } else {
      /* This is a reply */
      if(dns_trans->req_frame){
        proto_item *it;
        nstime_t ns;

        it=proto_tree_add_uint(dns_tree, hf_dns_response_to, tvb, 0, 0, dns_trans->req_frame);
        PROTO_ITEM_SET_GENERATED(it);

        nstime_delta(&ns, &pinfo->fd->abs_ts, &dns_trans->req_time);
        it=proto_tree_add_time(dns_tree, hf_dns_time, tvb, 0, 0, &ns);
        PROTO_ITEM_SET_GENERATED(it);
      }
    }              

    if (is_tcp) {
      /* Put the length indication into the tree. */
      proto_tree_add_item(dns_tree, hf_dns_length, tvb, offset - 2, 2, FALSE);
    }

    proto_tree_add_uint(dns_tree, hf_dns_transaction_id, tvb,
			offset + DNS_ID, 2, id);

    bufpos=0;
    bufpos+=MIN(MAX_BUF_SIZE-bufpos,
		g_snprintf(buf+bufpos, MAX_BUF_SIZE-bufpos, "%s",
			val_to_str(opcode, opcode_vals, "Unknown operation")));
    if (flags & F_RESPONSE) {
	    bufpos+=MIN(MAX_BUF_SIZE-bufpos,
			g_snprintf(buf+bufpos, MAX_BUF_SIZE-bufpos, " response, %s",
				val_to_str(flags & F_RCODE, rcode_vals, "Unknown error")));
    }
    tf = proto_tree_add_uint_format(dns_tree, hf_dns_flags, tvb,
				    offset + DNS_FLAGS, 2,
				    flags,
				    "Flags: 0x%04x (%s)",
				    flags, buf);
    field_tree = proto_item_add_subtree(tf, ett_dns_flags);
    proto_tree_add_item(field_tree, hf_dns_flags_response,
			tvb, offset + DNS_FLAGS, 2, FALSE);
    proto_tree_add_item(field_tree, hf_dns_flags_opcode,
			tvb, offset + DNS_FLAGS, 2, FALSE);
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_authoritative,
			  tvb, offset + DNS_FLAGS, 2, FALSE);
    }
    proto_tree_add_item(field_tree, hf_dns_flags_truncated,
			tvb, offset + DNS_FLAGS, 2, FALSE);
    proto_tree_add_item(field_tree, hf_dns_flags_recdesired,
			tvb, offset + DNS_FLAGS, 2, FALSE);
    if (flags & F_RESPONSE) {
      proto_tree_add_item(field_tree, hf_dns_flags_recavail,
			  tvb, offset + DNS_FLAGS, 2, FALSE);
      proto_tree_add_item(field_tree, hf_dns_flags_z,
			 tvb, offset + DNS_FLAGS, 2, FALSE);
      proto_tree_add_item(field_tree, hf_dns_flags_authenticated,
			  tvb, offset + DNS_FLAGS, 2, FALSE);
      proto_tree_add_item(field_tree, hf_dns_flags_rcode,
			  tvb, offset + DNS_FLAGS, 2, FALSE);
    } else {
      proto_tree_add_item(field_tree, hf_dns_flags_z,
                           tvb, offset + DNS_FLAGS, 2, FALSE);
      proto_tree_add_item(field_tree, hf_dns_flags_checkdisable,
			  tvb, offset + DNS_FLAGS, 2, FALSE);
    }
  }
  quest = tvb_get_ntohs(tvb, offset + DNS_QUEST);
  if (tree) {
    if (isupdate) {
      proto_tree_add_uint(dns_tree, hf_dns_count_zones, tvb,
			  offset + DNS_QUEST, 2, quest);
    } else {
      proto_tree_add_uint(dns_tree, hf_dns_count_questions, tvb,
			  offset + DNS_QUEST, 2, quest);
    }
  }
  ans = tvb_get_ntohs(tvb, offset + DNS_ANS);
  if (tree) {
    if (isupdate) {
      proto_tree_add_uint(dns_tree, hf_dns_count_prerequisites, tvb,
			  offset + DNS_ANS, 2, ans);
    } else {
      proto_tree_add_uint(dns_tree, hf_dns_count_answers, tvb,
			  offset + DNS_ANS, 2, ans);
    }
  }
  auth = tvb_get_ntohs(tvb, offset + DNS_AUTH);
  if (tree) {
    if (isupdate) {
      proto_tree_add_uint(dns_tree, hf_dns_count_updates, tvb,
			  offset + DNS_AUTH, 2, auth);
    } else {
      proto_tree_add_uint(dns_tree, hf_dns_count_auth_rr, tvb,
			  offset + DNS_AUTH, 2, auth);
    }
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
				     dns_tree, isupdate, is_mdns);
  }

  if (ans > 0) {
    /* If this is a request, don't add information about the answers
       to the summary, just add information about the queries. */
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, ans,
				      ((flags & F_RESPONSE) ? cinfo : NULL),
				      dns_tree, (isupdate ?
						 "Prerequisites" : "Answers"),
				      pinfo, is_mdns);
  }

  /* Don't add information about the authoritative name servers, or the
     additional records, to the summary. */
  if (auth > 0) {
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, auth,
				      NULL, dns_tree,
				      (isupdate ? "Updates" : 
				       "Authoritative nameservers"),
				      pinfo, is_mdns);
  }

  if (add > 0) {
    cur_off += dissect_answer_records(tvb, cur_off, dns_data_offset, add,
				      NULL, dns_tree, "Additional records",
				      pinfo, is_mdns);
  }
}

static void
dissect_dns_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNS");

  dissect_dns_common(tvb, pinfo, tree, FALSE, FALSE);
}

static void
dissect_mdns_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MDNS");

  dissect_dns_common(tvb, pinfo, tree, FALSE, TRUE);
}


static guint
get_dns_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint16 plen;

  /*
   * Get the length of the DNS packet.
   */
  plen = tvb_get_ntohs(tvb, offset);

  /*
   * That length doesn't include the length field itself; add that in.
   */
  return plen + 2;
}

static void
dissect_dns_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNS");

  dissect_dns_common(tvb, pinfo, tree, TRUE, FALSE);
}

static void
dissect_dns_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tcp_dissect_pdus(tvb, pinfo, tree, dns_desegment, 2, get_dns_pdu_len,
	dissect_dns_tcp_pdu);
}

void
proto_register_dns(void)
{
  static hf_register_info hf[] = {
    { &hf_dns_length,
      { "Length",		"dns.length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Length of DNS-over-TCP request or response", HFILL }},
    { &hf_dns_flags,
      { "Flags",		"dns.flags",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"", HFILL }},
    { &hf_dns_flags_response,
      { "Response",		"dns.flags.response",
	FT_BOOLEAN, 16, TFS(&tfs_flags_response), F_RESPONSE,
	"Is the message a response?", HFILL }},
    { &hf_dns_flags_opcode,
      { "Opcode",		"dns.flags.opcode",
	FT_UINT16, BASE_DEC, VALS(opcode_vals), F_OPCODE,
	"Operation code", HFILL }},
    { &hf_dns_flags_authoritative,
      { "Authoritative",	"dns.flags.authoritative",
	FT_BOOLEAN, 16, TFS(&tfs_flags_authoritative), F_AUTHORITATIVE,
	"Is the server is an authority for the domain?", HFILL }},
    { &hf_dns_flags_truncated,
      { "Truncated",	"dns.flags.truncated",
	FT_BOOLEAN, 16, TFS(&tfs_flags_truncated), F_TRUNCATED,
	"Is the message truncated?", HFILL }},
    { &hf_dns_flags_recdesired,
      { "Recursion desired",	"dns.flags.recdesired",
	FT_BOOLEAN, 16, TFS(&tfs_flags_recdesired), F_RECDESIRED,
	"Do query recursively?", HFILL }},
    { &hf_dns_flags_recavail,
      { "Recursion available",	"dns.flags.recavail",
	FT_BOOLEAN, 16, TFS(&tfs_flags_recavail), F_RECAVAIL,
	"Can the server do recursive queries?", HFILL }},
    { &hf_dns_flags_z,
      { "Z", "dns.flags.z",
	FT_BOOLEAN, 16, TFS(&tfs_flags_z), F_Z,
	"Z flag", HFILL }},
    { &hf_dns_flags_authenticated,
      { "Answer authenticated",	"dns.flags.authenticated",
	FT_BOOLEAN, 16, TFS(&tfs_flags_authenticated), F_AUTHENTIC,
	"Was the reply data authenticated by the server?", HFILL }},
    { &hf_dns_flags_checkdisable,
      { "Non-authenticated data OK",	"dns.flags.checkdisable",
	FT_BOOLEAN, 16, TFS(&tfs_flags_checkdisable), F_CHECKDISABLE,
	"Is non-authenticated data acceptable?", HFILL }},
    { &hf_dns_flags_rcode,
      { "Reply code",		"dns.flags.rcode",
	FT_UINT16, BASE_DEC, VALS(rcode_vals), F_RCODE,
	"Reply code", HFILL }},
    { &hf_dns_transaction_id,
      { "Transaction ID",      	"dns.id",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Identification of transaction", HFILL }},
    { &hf_dns_qry_type,
      { "Type",      	"dns.qry.type",
	FT_UINT16, BASE_HEX, VALS(dns_types), 0x0,
	"Query Type", HFILL }},
    { &hf_dns_qry_class,
      { "Class",      	"dns.qry.class",
	FT_UINT16, BASE_HEX, VALS(dns_classes), 0x0,
	"Query Class", HFILL }},
    { &hf_dns_qry_class_mdns,
      { "Class",      	"dns.qry.class",
	FT_UINT16, BASE_HEX, VALS(dns_classes), 0x7FFF,
	"Query Class", HFILL }},
    { &hf_dns_qry_qu,
      { "\"QU\" question", 	"dns.qry.qu",
	FT_BOOLEAN, 16, NULL, C_QU,
	"QU flag", HFILL }},
    { &hf_dns_qry_name,
      { "Name",      	"dns.qry.name",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"Query Name", HFILL }},
    { &hf_dns_rr_type,
      { "Type",      	"dns.resp.type",
	FT_UINT16, BASE_HEX, VALS(dns_types), 0x0,
	"Response Type", HFILL }},
    { &hf_dns_rr_class,
      { "Class",      	"dns.resp.class",
	FT_UINT16, BASE_HEX, VALS(dns_classes), 0x0,
	"Response Class", HFILL }},
    { &hf_dns_rr_class_mdns,
      { "Class",      	"dns.resp.class",
	FT_UINT16, BASE_HEX, VALS(dns_classes), 0x7FFF,
	"Response Class", HFILL }},
    { &hf_dns_rr_cache_flush,
      { "Cache flush", 	"dns.resp.cache_flush",
	FT_BOOLEAN, 16, NULL, C_FLUSH,
	"Cache flush flag", HFILL }},
    { &hf_dns_rr_name,
      { "Name",      	"dns.resp.name",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"Response Name", HFILL }},  
    { &hf_dns_rr_ttl,
      { "Time to live", "dns.resp.ttl",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Response TTL", HFILL }},
    { &hf_dns_rr_len,
      { "Data length",  "dns.resp.len",
	FT_UINT32, BASE_DEC, NULL, 0x0,
	"Response Length", HFILL }},
    { &hf_dns_count_questions,
      { "Questions",		"dns.count.queries",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of queries in packet", HFILL }},
    { &hf_dns_count_zones,
      { "Zones",		"dns.count.zones",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of zones in packet", HFILL }},
    { &hf_dns_count_answers,
      { "Answer RRs",		"dns.count.answers",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of answers in packet", HFILL }},
    { &hf_dns_count_prerequisites,
      { "Prerequisites",		"dns.count.prerequisites",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of prerequisites in packet", HFILL }},
    { &hf_dns_count_auth_rr,
      { "Authority RRs",       	"dns.count.auth_rr",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of authoritative records in packet", HFILL }},
    { &hf_dns_count_updates,
      { "Updates",       	"dns.count.updates",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of updates records in packet", HFILL }},
    { &hf_dns_tsig_original_id,
      { "Original Id",       	"dns.tsig.original_id",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Original Id", HFILL }},
    { &hf_dns_tsig_error,
      { "Error",       	"dns.tsig.error",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Expanded RCODE for TSIG", HFILL }},
    { &hf_dns_tsig_fudge,
      { "Fudge",       	"dns.tsig.fudge",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of bytes for the MAC", HFILL }},
    { &hf_dns_tsig_mac_size,
      { "MAC Size",       	"dns.tsig.mac_size",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of bytes for the MAC", HFILL }},
    { &hf_dns_tsig_other_len,
      { "Other Len",       	"dns.tsig.other_len",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Number of bytes for Other Data", HFILL }},
    { &hf_dns_tsig_mac,
      { "MAC",       	"dns.tsig.mac",
	FT_NONE, BASE_NONE, NULL, 0x0,
	"MAC", HFILL }},
    { &hf_dns_tsig_other_data,
      { "Other Data",       	"dns.tsig.other_data",
	FT_BYTES, BASE_HEX, NULL, 0x0,
	"Other Data", HFILL }},
    { &hf_dns_tsig_algorithm_name,
      { "Algorithm Name",      	"dns.tsig.algorithm_name",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"Name of algorithm used for the MAC", HFILL }},
    { &hf_dns_response_in,
      { "Response In", "dns.response_in",
        FT_FRAMENUM, BASE_DEC, NULL, 0x0,
        "The response to this DNS query is in this frame", HFILL }},
    { &hf_dns_response_to,
      { "Request In", "dns.response_to",
        FT_FRAMENUM, BASE_DEC, NULL, 0x0,
        "This is a response to the DNS query in this frame", HFILL }},
    { &hf_dns_time,
      { "Time", "dns.time",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Query and the Response", HFILL }},
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
    &ett_t_key,
    &ett_dns_mac,
  };
  module_t *dns_module;

  proto_dns = proto_register_protocol("Domain Name Service", "DNS", "dns");
  proto_register_field_array(proto_dns, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dns_module = prefs_register_protocol(proto_dns, NULL);
  prefs_register_bool_preference(dns_module, "desegment_dns_messages",
    "Reassemble DNS messages spanning multiple TCP segments",
    "Whether the DNS dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &dns_desegment);

  dns_tsig_dissector_table = register_dissector_table("dns.tsig.mac", "DNS TSIG MAC Dissectors", FT_STRING, BASE_NONE);
}

void
proto_reg_handoff_dns(void)
{
  dissector_handle_t dns_udp_handle;
  dissector_handle_t dns_tcp_handle;
  dissector_handle_t mdns_udp_handle;

  dns_udp_handle = create_dissector_handle(dissect_dns_udp, proto_dns);
  dns_tcp_handle = create_dissector_handle(dissect_dns_tcp, proto_dns);
  mdns_udp_handle = create_dissector_handle(dissect_mdns_udp, proto_dns);

  dissector_add("udp.port", UDP_PORT_DNS, dns_udp_handle);
  dissector_add("tcp.port", TCP_PORT_DNS, dns_tcp_handle);
  dissector_add("udp.port", UDP_PORT_MDNS, mdns_udp_handle);
  dissector_add("tcp.port", TCP_PORT_MDNS, dns_tcp_handle);

  gssapi_handle = find_dissector("gssapi");
  ntlmssp_handle = find_dissector("ntlmssp");

}
