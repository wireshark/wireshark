/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet.h,v 1.172 2000/02/15 21:03:35 gram Exp $
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

#ifndef __WTAP_H__
#include "wiretap/wtap.h"
#endif

#ifndef __PROTO_H__
#include "proto.h"
#endif

/* Pointer versions of ntohs and ntohl.  Given a pointer to a member of a
 * byte array, returns the value of the two or four bytes at the pointer.
 * The pletoh[sl] versions return the little-endian representation.
 */

#define pntohs(p)  ((guint16)                       \
                    ((guint16)*((guint8 *)p+0)<<8|  \
                     (guint16)*((guint8 *)p+1)<<0))

#define pntohl(p)  ((guint32)*((guint8 *)p+0)<<24|  \
                    (guint32)*((guint8 *)p+1)<<16|  \
                    (guint32)*((guint8 *)p+2)<<8|   \
                    (guint32)*((guint8 *)p+3)<<0)

#define pletohs(p) ((guint16)                       \
                    ((guint16)*((guint8 *)p+1)<<8|  \
                     (guint16)*((guint8 *)p+0)<<0))

#define pletohl(p) ((guint32)*((guint8 *)p+3)<<24|  \
                    (guint32)*((guint8 *)p+2)<<16|  \
                    (guint32)*((guint8 *)p+1)<<8|   \
                    (guint32)*((guint8 *)p+0)<<0)


#define hi_nibble(b) ((b & 0xf0) >> 4)
#define lo_nibble(b) (b & 0x0f)

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x)	(sizeof x / sizeof x[0])


/* Useful when highlighting regions inside a dissect_*() function. With this
 * macro, you can highlight from an arbitrary offset to the end of the
 * packet (which may come before the end of the frame).
 * See dissect_data() for an example.
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
} column_info;

#define COL_MAX_LEN 256
#define COL_MAX_INFO_LEN 4096

typedef struct _packet_counts {
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
	CHAR_ASCII,	/* ASCII */
	CHAR_EBCDIC	/* EBCDIC */
} char_enc;

/* XXX - some of this stuff is used only while a packet is being dissected;
   should we keep around a separate data structure for that, to save
   memory?

   Also, should the pseudo-header be supplied by Wiretap when you do a
   seek-and-read, so that we don't have to save it for all frames? */
typedef struct _frame_data {
  struct _frame_data *next; /* Next element in list */
  struct _frame_data *prev; /* Previous element in list */
  guint32      num;       /* Frame number */
  guint32      pkt_len;   /* Packet length */
  guint32      cap_len;   /* Amount actually captured */
  guint32      rel_secs;  /* Relative seconds */
  guint32      rel_usecs; /* Relative microseconds */
  guint32      abs_secs;  /* Absolute seconds */
  guint32      abs_usecs; /* Absolute microseconds */
  guint32      del_secs;  /* Delta seconds */
  guint32      del_usecs; /* Delta microseconds */
  long         file_off;  /* File offset */
  column_info *cinfo;     /* Column formatting information */
  gint         row;       /* Row number for this packet in the display */
  int          lnk_t;     /* Per-packet encapsulation/data-link type */
  gboolean     passed_dfilter; /* TRUE = display, FALSE = no display */
  char_enc     encoding;  /* Character encoding (ASCII, EBCDIC...) */
  union pseudo_header pseudo_header; /* "pseudo-header" from wiretap */
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
  PT_TCP,		/* TCP */
  PT_UDP		/* UDP */
} port_type;

typedef struct _packet_info {
  int     len;
  int     captured_len;
  address dl_src;		/* link-layer source address */
  address dl_dst;		/* link-layer destination address */
  address net_src;		/* network-layer source address */
  address net_dst;		/* network-layer destination address */
  address src;			/* source address (net if present, DL otherwise )*/
  address dst;			/* destination address (net if present, DL otherwise )*/
  guint32 ipproto;
  port_type ptype;		/* type of the following two port numbers */
  guint32 srcport;		/* source port */
  guint32 destport;		/* destination port */
  guint32 match_port;
  int     iplen;
  int     iphdrlen;
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


/* Many of the structs and definitions below and in packet-*.c files
 * were taken from include files in the Linux distribution. */

typedef struct tcp_extra_data {
  int match_port;
  int sport;
  int dport;
} tcp_extra_data;

/* Utility routines used by packet*.c */
gchar*     ether_to_str(const guint8 *);
gchar*     ether_to_str_punct(const guint8 *, char);
gchar*     ip_to_str(const guint8 *);
struct e_in6_addr;
gchar*     ip6_to_str(struct e_in6_addr *);
gchar*     ipx_addr_to_str(guint32, const guint8 *);
gchar*	   abs_time_to_str(struct timeval*);
gchar*	   rel_time_to_str(struct timeval*);
gchar*     time_secs_to_str(guint32);
gchar*     bytes_to_str(const guint8 *, int);
const u_char *find_line_end(const u_char *data, const u_char *dataend,
    const u_char **eol);
int        get_token_len(const u_char *linep, const u_char *lineend,
    const u_char **next_token);
gchar*     format_text(const u_char *line, int len);
gchar*     val_to_str(guint32, const value_string *, const char *);
gchar*     match_strval(guint32, const value_string*);
char * decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width);
const char *decode_boolean_bitfield(guint32 val, guint32 mask, int width,
  const char *truedesc, const char *falsedesc);
const char *decode_enumerated_bitfield(guint32 val, guint32 mask, int width,
  const value_string *tab, const char *fmt);
const char *decode_numeric_bitfield(guint32 val, guint32 mask, int width,
  const char *fmt);
gint       check_col(frame_data *, gint);
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

void blank_packetinfo(void);

/* Allow protocols to register "init" routines, which are called before
   we make a pass through a capture file and dissect all its packets
   (e.g., when we read in a new capture file, or run a "filter packets"
   or "colorize packets" pass over the current capture file). */
void register_init_routine(void (*func)(void));

/* Call all the registered "init" routines. */
void init_all_protocols(void);

void init_dissect_rpc(void);
void init_dissect_udp(void);
void init_dissect_x25(void);

typedef void	(*DissectFunc)	(const u_char*, int, frame_data*, proto_tree*);

/*
 * Routines should take four args: packet data *, offset, frame_data *,
 * tree *
 * They should never modify the packet data.
 */
void dissect_packet(const u_char *, frame_data *, proto_tree *);
void dissect_data(const u_char *, int, frame_data *, proto_tree *);


/* These functions are in ethertype.c */
void capture_ethertype(guint16 etype, int offset,
		const u_char *pd, packet_counts *ld);
void ethertype(guint16 etype, int offset,
		const u_char *pd, frame_data *fd, proto_tree *tree,
		proto_tree *fh_tree, int item_id);
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
