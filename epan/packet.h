/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet.h,v 1.20 2001/01/18 07:44:41 guy Exp $
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


#ifndef __PACKET_H__
#define __PACKET_H__

#include "wiretap/wtap.h"
#include "proto.h"
#include "tvbuff.h"
#include "pint.h"

#define hi_nibble(b) (((b) & 0xf0) >> 4)
#define lo_nibble(b) ((b) & 0x0f)

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x)	(sizeof x / sizeof x[0])

/* Useful when highlighting regions inside a dissect_*() function. With this
 * macro, you can highlight from an arbitrary offset to the end of the
 * packet (which may come before the end of the frame).
 * See old_dissect_data() for an example.
 */
#define END_OF_FRAME	(pi.captured_len - offset)

/* Check whether the "len" bytes of data starting at "offset" is
 * entirely inside the captured data for this packet. */
#define	BYTES_ARE_IN_FRAME(offset, len)	((offset) + (len) <= pi.captured_len)

/* Check whether there's any data at all starting at "offset". */
#define	IS_DATA_IN_FRAME(offset)	((offset) < pi.captured_len)
		
/* To pass one of two strings, singular or plural */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

typedef struct _column_info {
  gint       num_cols;  /* Number of columns */
  gint      *col_fmt;   /* Format of column */
  gboolean **fmt_matx;  /* Specifies which formats apply to a column */
  gint      *col_width; /* Column widths to use during a "-S" capture */
  gchar    **col_title; /* Column titles */
  gchar    **col_data;  /* Column data */
  gchar    **col_buf;   /* Buffer into which to copy data for column */
  gboolean   writable;  /* Are we stil writing to the columns? */
} column_info;

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void                 col_init(column_info *, gint);

typedef struct _packet_counts {
  gint           sctp;
  gint           tcp;
  gint           udp;
  gint           icmp;
  gint           ospf;
  gint           gre;
  gint           netbios;
  gint           ipx;
  gint           vines;
  gint           other;
  gint           total;
} packet_counts;

/* Types of character encodings */
typedef enum {
	CHAR_ASCII	 = 0,	/* ASCII */
	CHAR_EBCDIC	 = 1	/* EBCDIC */
} char_enc;

/* XXX - some of this stuff is used only while a packet is being dissected;
   should we keep that stuff in the "packet_info" structure, instead, to
   save memory? */
typedef struct _frame_data {
  struct _frame_data *next; /* Next element in list */
  struct _frame_data *prev; /* Previous element in list */
  GSList *pfd;              /* Per frame proto data */
  guint32      num;       /* Frame number */
  guint32      pkt_len;   /* Packet length */
  guint32      cap_len;   /* Amount actually captured */
  gint32       rel_secs;  /* Relative seconds (yes, it can be negative) */
  gint32       rel_usecs; /* Relative microseconds (yes, it can be negative) */
  guint32      abs_secs;  /* Absolute seconds */
  guint32      abs_usecs; /* Absolute microseconds */
  gint32       del_secs;  /* Delta seconds (yes, it can be negative) */
  gint32       del_usecs; /* Delta microseconds (yes, it can be negative) */
  long         file_off;  /* File offset */
  column_info *cinfo;     /* Column formatting information */
  int          lnk_t;     /* Per-packet encapsulation/data-link type */
  struct {
	unsigned int passed_dfilter	: 1; /* 1 = display, 0 = no display */
  	unsigned int encoding		: 2; /* Character encoding (ASCII, EBCDIC...) */
	unsigned int visited		: 1; /* Has this packet been visited yet? 1=Yes,0=No*/
	unsigned int marked             : 1; /* 1 = marked by user, 0 = normal */
  } flags;
} frame_data;

/* Types of addresses Ethereal knows about. */
typedef enum {
  AT_NONE,		/* no link-layer address */
  AT_ETHER,		/* MAC (Ethernet, 802.x, FDDI) address */
  AT_IPv4,		/* IPv4 */
  AT_IPv6,		/* IPv6 */
  AT_IPX,		/* IPX */
  AT_SNA,		/* SNA */
  AT_ATALK,		/* Appletalk DDP */
  AT_VINES		/* Banyan Vines */
} address_type;

typedef struct _address {
  address_type  type;		/* type of address */
  int           len;		/* length of address, in bytes */
  const guint8 *data;		/* bytes that constitute address */
} address;

#define	SET_ADDRESS(addr, addr_type, addr_len, addr_data) { \
	(addr)->type = (addr_type); \
	(addr)->len = (addr_len); \
	(addr)->data = (addr_data); \
	}

/* Types of port numbers Ethereal knows about. */
typedef enum {
  PT_NONE,		/* no port number */
  PT_SCTP,              /* SCTP */
  PT_TCP,		/* TCP */
  PT_UDP,		/* UDP */
  PT_NCP		/* NCP connection */
} port_type;

#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

typedef struct _packet_info {
  const char *current_proto;	/* name of protocol currently being dissected */
  frame_data *fd;
  tvbuff_t *compat_top_tvb;	/* only needed while converting Ethereal to use tvbuffs */
  union wtap_pseudo_header *pseudo_header;
  int     len;
  int     captured_len;
  address dl_src;		/* link-layer source address */
  address dl_dst;		/* link-layer destination address */
  address net_src;		/* network-layer source address */
  address net_dst;		/* network-layer destination address */
  address src;			/* source address (net if present, DL otherwise )*/
  address dst;			/* destination address (net if present, DL otherwise )*/
  guint32 ipproto;		/* IP protocol, if this is an IP packet */
  gboolean fragmented;		/* TRUE if the protocol is only a fragment */
  port_type ptype;		/* type of the following two port numbers */
  guint32 srcport;		/* source port */
  guint32 destport;		/* destination port */
  guint32 match_port;
  int     iplen;
  int     iphdrlen;
  int	  p2p_dir;
} packet_info;

extern packet_info pi;

/* Struct for the match_strval function */

typedef struct _value_string {
  guint32  value;
  gchar   *strptr;
} value_string;

/* Struct for boolean enumerations */
typedef struct true_false_string {
	char	*true_string;
	char	*false_string;
} true_false_string;

void packet_init(void);
void packet_cleanup(void);

/* Hash table for matching port numbers and dissectors */
typedef GHashTable* dissector_table_t;

/* types for sub-dissector lookup */
typedef void (*old_dissector_t)(const u_char *, int, frame_data *, proto_tree *);
typedef void (*dissector_t)(tvbuff_t *, packet_info *, proto_tree *);

/* a protocol uses the function to register a sub-dissector table */
dissector_table_t register_dissector_table(const char *name);

/* Add a sub-dissector to a dissector table.  Called by the protocol routine */
/* that wants to register a sub-dissector.  */
void old_dissector_add(const char *abbrev, guint32 pattern,
    old_dissector_t dissector, int proto);
void dissector_add(const char *abbrev, guint32 pattern,
    dissector_t dissector, int proto);

/* Add a sub-dissector to a dissector table.  Called by the protocol routine */
/* that wants to de-register a sub-dissector.  */
void old_dissector_delete(const char *name, guint32 pattern, old_dissector_t dissector);
void dissector_delete(const char *name, guint32 pattern, dissector_t dissector);

/* Look for a given port in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return TRUE, otherwise
   return FALSE. */
gboolean old_dissector_try_port(dissector_table_t sub_dissectors, guint32 port,
    const u_char *pd, int offset, frame_data *fd, proto_tree *tree);
gboolean dissector_try_port(dissector_table_t sub_dissectors, guint32 port,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* List of "heuristic" dissectors (which get handed a packet, look at it,
   and either recognize it as being for their protocol, dissect it, and
   return TRUE, or don't recognize it and return FALSE) to be called
   by another dissector. */
typedef GSList *heur_dissector_list_t;

/* Type of a heuristic dissector */
typedef gboolean (*old_heur_dissector_t)(const u_char *, int, frame_data *,
	proto_tree *);
typedef gboolean (*heur_dissector_t)(tvbuff_t *, packet_info *,
	proto_tree *);

/* A protocol uses this function to register a heuristic dissector list */
void register_heur_dissector_list(const char *name, heur_dissector_list_t *list);

/* Add a sub-dissector to a heuristic dissector list.  Called by the
   protocol routine that wants to register a sub-dissector.  */
void old_heur_dissector_add(const char *name, old_heur_dissector_t dissector,
    int proto);
void heur_dissector_add(const char *name, heur_dissector_t dissector,
    int proto);

/* Try all the dissectors in a given heuristic dissector list until
   we find one that recognizes the protocol, in which case we return
   TRUE, or we run out of dissectors, in which case we return FALSE. */
gboolean dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* List of "conversation" dissectors (they're not heuristic, but are
   assigned to a conversation if some other dissector sees some traffic
   saying "traffic between these hosts on these ports will be of type
   XXX", e.g. RTSP traffic doing so).

   These lists are for use by the UI, which, for a given conversation,
   would offer a list of dissectors that could be used with it; this
   would include dissectors on the conversation dissector list for
   the transport-layer protocol for the conversation, as well as
   dissectors for any port-based lists for that protocol (as a conversation
   between two ports, both of which have dissectors associated with them,
   might have been given to the wrong one of those dissectors). */
typedef GSList *conv_dissector_list_t;

/* A protocol uses this function to register a conversation dissector list */
void register_conv_dissector_list(const char *name, conv_dissector_list_t *list);

/* Add a sub-dissector to a conversation dissector list.  Called by the
   protocol routine that wants to register a sub-dissector.  */
void old_conv_dissector_add(const char *name, old_dissector_t dissector,
    int proto);
void conv_dissector_add(const char *name, dissector_t dissector,
    int proto);

/* Handle for dissectors you call directly.
   This handle is opaque outside of "packet.c". */
struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;

/* Register a dissector. */
void register_dissector(const char *name, dissector_t dissector, int proto);

/* Find a dissector by name. */
dissector_handle_t find_dissector(const char *name);

/* Call a dissector through a handle. */
void call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);

/* Utility routines used by packet*.c */
gchar*     ether_to_str(const guint8 *);
gchar*     ether_to_str_punct(const guint8 *, char);
gchar*     ip_to_str(const guint8 *);
void       ip_to_str_buf(const guint8 *, gchar *);
struct e_in6_addr;
gchar*     ip6_to_str(struct e_in6_addr *);
gchar*     ipx_addr_to_str(guint32, const guint8 *);
gchar*	   abs_time_to_str(struct timeval*);
gchar*	   rel_time_to_str(struct timeval*);
gchar*     time_secs_to_str(guint32);
gchar*     val_to_str(guint32, const value_string *, const char *);
gchar*     match_strval(guint32, const value_string*);
char * decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width);
const char *decode_boolean_bitfield(guint32 val, guint32 mask, int width,
  const char *truedesc, const char *falsedesc);
const char *decode_enumerated_bitfield(guint32 val, guint32 mask, int width,
  const value_string *tab, const char *fmt);
const char *decode_numeric_bitfield(guint32 val, guint32 mask, int width,
  const char *fmt);

void	   col_set_writable(frame_data *fd, gboolean writable);
gint       check_col(frame_data *, gint);
void       col_clear(frame_data *, gint);
void       col_set_str(frame_data *, gint, gchar *);
#if __GNUC__ == 2
void       col_add_fstr(frame_data *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
void       col_append_fstr(frame_data *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
#else
void       col_add_fstr(frame_data *, gint, gchar *, ...);
void       col_append_fstr(frame_data *, gint, gchar *, ...);
#endif
void       col_add_str(frame_data *, gint, const gchar *);
void       col_append_str(frame_data *, gint, gchar *);
void       col_set_cls_time(frame_data *, int);
void       fill_in_columns(frame_data *);

void       p_add_proto_data(frame_data *, int, void *);
void       *p_get_proto_data(frame_data *, int);

void blank_packetinfo(void);

/* Do all one-time initialization. */
void dissect_init(void);

void dissect_cleanup(void);

/* Allow protocols to register "init" routines, which are called before
   we make a pass through a capture file and dissect all its packets
   (e.g., when we read in a new capture file, or run a "filter packets"
   or "colorize packets" pass over the current capture file). */
void register_init_routine(void (*func)(void));

/* Call all the registered "init" routines. */
void init_all_protocols(void);

/*
 * Dissectors should never modify the packet data.
 */
void dissect_packet(tvbuff_t **p_tvb, union wtap_pseudo_header *pseudo_header,
		const u_char *pd, frame_data *fd, proto_tree *tree);
void old_dissect_data(const u_char *, int, frame_data *, proto_tree *);
void dissect_data(tvbuff_t *tvb, int, packet_info *pinfo, proto_tree *tree);


/* These functions are in packet-ethertype.c */
void capture_ethertype(guint16 etype, int offset,
		const u_char *pd, packet_counts *ld);
void ethertype(guint16 etype, tvbuff_t *tvb, int offset_after_ethertype,
		packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
		int etype_id, int trailer_id);
extern const value_string etype_vals[];

/* ipproto.c */
extern const char *ipprotostr(int proto);

/*
 * All of the possible columns in summary listing.
 *
 * NOTE: The SRC and DST entries MUST remain in this order, or else you
 * need to fix the offset #defines before get_column_format!
 */
enum {
  COL_NUMBER,         /* Packet list item number */
  COL_CLS_TIME,       /* Command line-specified time (default relative) */
  COL_REL_TIME,       /* Relative time */
  COL_ABS_TIME,       /* Absolute time */
  COL_ABS_DATE_TIME,  /* Absolute date and time */
  COL_DELTA_TIME,     /* Delta time */
  COL_DEF_SRC,        /* Source address */
  COL_RES_SRC,        /* Resolved source */
  COL_UNRES_SRC,      /* Unresolved source */
  COL_DEF_DL_SRC,     /* Data link layer source address */
  COL_RES_DL_SRC,     /* Resolved DL source */
  COL_UNRES_DL_SRC,   /* Unresolved DL source */
  COL_DEF_NET_SRC,    /* Network layer source address */
  COL_RES_NET_SRC,    /* Resolved net source */
  COL_UNRES_NET_SRC,  /* Unresolved net source */
  COL_DEF_DST,        /* Destination address */
  COL_RES_DST,        /* Resolved dest */
  COL_UNRES_DST,      /* Unresolved dest */
  COL_DEF_DL_DST,     /* Data link layer dest address */
  COL_RES_DL_DST,     /* Resolved DL dest */
  COL_UNRES_DL_DST,   /* Unresolved DL dest */
  COL_DEF_NET_DST,    /* Network layer dest address */
  COL_RES_NET_DST,    /* Resolved net dest */
  COL_UNRES_NET_DST,  /* Unresolved net dest */
  COL_DEF_SRC_PORT,   /* Source port */
  COL_RES_SRC_PORT,   /* Resolved source port */
  COL_UNRES_SRC_PORT, /* Unresolved source port */
  COL_DEF_DST_PORT,   /* Destination port */
  COL_RES_DST_PORT,   /* Resolved dest port */
  COL_UNRES_DST_PORT, /* Unresolved dest port */
  COL_PROTOCOL,       /* Protocol */
  COL_INFO,           /* Description */
  COL_PACKET_LENGTH,  /* Packet length in bytes */
  NUM_COL_FMTS        /* Should always be last */
};

#endif /* packet.h */
