/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet.h,v 1.93 1999/09/03 00:38:49 guy Exp $
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

/* Byte ordering */
#ifndef BYTE_ORDER
  #define LITTLE_ENDIAN 4321
  #define BIG_ENDIAN 1234
  #ifdef WORDS_BIGENDIAN
    #define BYTE_ORDER BIG_ENDIAN
  #else
    #define BYTE_ORDER LITTLE_ENDIAN
  #endif
#endif

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x)	(sizeof x / sizeof x[0])


/* Useful when highlighting regions inside a dissect_*() function. With this
 * macro, you can highlight from an arbitrary offset to the end of the
 * packet (which may come before the end of the frame).
 * See dissect_data() for an example.
 */
#define END_OF_FRAME	(pi.captured_len - offset)
		
/* To pass one of two strings, singular or plural */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

typedef struct _column_info {
  gint       num_cols;  /* Number of columns */
  gint      *col_fmt;   /* Format of column */
  gboolean **fmt_matx;  /* Specifies which formats apply to a column */
  gint      *col_width; /* Column widths to use during a "-S" capture */
  gchar    **col_data;  /* Column data */
} column_info;

#define COL_MAX_LEN 256

typedef struct _packet_counts {
  gint           tcp;
  gint           udp;
  gint           icmp;
  gint           ospf;
  gint           gre;
  gint           netbios;
  gint           other;
  gint           total;
} packet_counts;

typedef struct _frame_data {
  struct _frame_data *next; /* Next element in list */
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
  union pseudo_header pseudo_header; /* "pseudo-header" from wiretap */
} frame_data;

typedef struct _packet_info {
  int len;
  int captured_len;
  guint32 ip_src;
  guint32 ip_dst;
  guint32 ipproto;
  guint32 srcport;
  guint32 destport;
  guint32 match_port;
  int iplen;
  int iphdrlen;
} packet_info;

extern packet_info pi;

/* Struct for the match_strval function */

typedef struct _value_string {
  guint32  value;
  gchar   *strptr;
} value_string;

/* Many of the structs and definitions below and in packet-*.c files
 * were taken from include files in the Linux distribution. */

typedef struct tcp_extra_data {
  int match_port;
  int sport;
  int dport;
} tcp_extra_data;

/* Tree types.  Each dissect_* routine should have one for each
   add_subtree() call. */

enum {
	ETT_NONE,
	ETT_FRAME,
	ETT_IEEE8023,
	ETT_ETHER2,
	ETT_LLC,
	ETT_TOKEN_RING,
	ETT_TOKEN_RING_AC,
	ETT_TOKEN_RING_FC,
	ETT_TR_IERR_CNT,
	ETT_TR_NERR_CNT,
	ETT_TR_MAC,
	ETT_PPP,
	ETT_ARP,
	ETT_FDDI,
	ETT_NULL,
	ETT_IP,
	ETT_IP_OPTIONS,
	ETT_IP_OPTION_SEC,
	ETT_IP_OPTION_ROUTE,
	ETT_IP_OPTION_TIMESTAMP,
	ETT_IP_TOS,
	ETT_IP_OFF,
	ETT_UDP,
	ETT_TCP,
	ETT_TCP_OPTIONS,
	ETT_TCP_OPTION_SACK,
	ETT_TCP_FLAGS,
	ETT_ICMP,
	ETT_IGMP,
	ETT_IPX,
	ETT_SPX,
	ETT_NCP,
	ETT_NCP_REQUEST_FIELDS,
	ETT_NCP_REPLY_FIELDS,
	ETT_DNS,
	ETT_DNS_FLAGS,
	ETT_DNS_QRY,
	ETT_DNS_QD,
	ETT_DNS_ANS,
	ETT_DNS_RR,
	ETT_ISAKMP,
	ETT_ISAKMP_FLAGS,
	ETT_ISAKMP_PAYLOAD,
	ETT_RIP,
	ETT_RIP_VEC,
	ETT_OSPF,
	ETT_OSPF_HDR,
	ETT_OSPF_HELLO,
	ETT_OSPF_DESC,
	ETT_OSPF_LSR,
	ETT_OSPF_LSA_UPD,
	ETT_OSPF_LSA,
	ETT_LPD,
	ETT_RAW,
	ETT_CLIP,
	ETT_BOOTP,
	ETT_BOOTP_OPTION,
	ETT_IPv6,
	ETT_CLNP,
	ETT_COTP,
	ETT_VINES_FRP,
	ETT_VINES,
	ETT_VINES_ARP,
	ETT_VINES_ICP,
	ETT_VINES_IPC,
	ETT_VINES_RTP,
	ETT_VINES_SPP,
	ETT_IPXRIP,
	ETT_IPXSAP,
	ETT_IPXSAP_SERVER,
	ETT_NBNS,
	ETT_NBNS_FLAGS,
	ETT_NBNS_NB_FLAGS,
	ETT_NBNS_NAME_FLAGS,
	ETT_NBNS_QRY,
	ETT_NBNS_QD,
	ETT_NETB,
	ETT_NETB_FLAGS,
	ETT_NETB_NAME,
	ETT_NBNS_ANS,
	ETT_NBNS_RR,
	ETT_NBIPX,
	ETT_NBIPX_NAME_TYPE_FLAGS,
	ETT_AARP,
	ETT_GIOP,
	ETT_NBDGM,
	ETT_CDP,
	ETT_CDP_TLV,
	ETT_HTTP,
	ETT_TFTP,
 	ETT_AH,
 	ETT_ESP,
 	ETT_ICMPv6,
 	ETT_ICMPv6OPT,
 	ETT_ICMPv6FLAG,
	ETT_POP,
	ETT_FTP,
	ETT_TELNET,
	ETT_TELNET_SUBOPT,
	ETT_NNTP,
	ETT_SNMP,
	ETT_NBSS,
	ETT_NBSS_FLAGS,
	ETT_SMB,
	ETT_SMB_FLAGS,
	ETT_SMB_FLAGS2,
	ETT_SMB_DIALECTS,
	ETT_SMB_MODE,
	ETT_SMB_CAPABILITIES,
	ETT_SMB_RAWMODE,
	ETT_SMB_AFLAGS,
	ETT_SMB_DESIREDACCESS,
	ETT_SMB_SEARCH,
	ETT_SMB_FILE,
	ETT_SMB_OPENFUNCTION,
	ETT_SMB_FILEATTRIBUTES,
	ETT_SMB_FILETYPE,
	ETT_SMB_ACTION,
	ETT_PPTP,
	ETT_GRE,
	ETT_GRE_FLAGS,
 	ETT_PPPOED,
 	ETT_PPPOED_TAGS,
 	ETT_PPPOES,
 	ETT_LCP,
 	ETT_LCP_OPTIONS,
 	ETT_LCP_MRU_OPT,
 	ETT_LCP_ASYNC_MAP_OPT,
 	ETT_LCP_AUTHPROT_OPT,
 	ETT_LCP_QUALPROT_OPT,
 	ETT_LCP_MAGICNUM_OPT,
 	ETT_LCP_FCS_ALTERNATIVES_OPT,
 	ETT_LCP_NUMBERED_MODE_OPT,
 	ETT_LCP_CALLBACK_OPT,
 	ETT_LCP_MULTILINK_EP_DISC_OPT,
 	ETT_LCP_INTERNATIONALIZATION_OPT,
 	ETT_IPCP,
 	ETT_IPCP_OPTIONS,
 	ETT_IPCP_IPADDRS_OPT,
 	ETT_IPCP_COMPRESSPROT_OPT,
        ETT_RSVP,
        ETT_RSVP_UNKNOWN_CLASS,
        ETT_RSVP_HDR,
        ETT_RSVP_SESSION,
        ETT_RSVP_SGROUP,
        ETT_RSVP_HOP,
        ETT_RSVP_INTEGRITY,
        ETT_RSVP_TIME_VALUES,
        ETT_RSVP_ERROR,
        ETT_RSVP_SCOPE,
        ETT_RSVP_STYLE,
        ETT_RSVP_FLOWSPEC,
        ETT_RSVP_FILTER_SPEC,
        ETT_RSVP_SENDER_TEMPLATE,
        ETT_RSVP_SENDER_TSPEC,
        ETT_RSVP_ADSPEC,
        ETT_RSVP_POLICY,
        ETT_RSVP_CONFIRM,
        ETT_RSVP_ADSPEC_SUBTREE1,
        ETT_RSVP_ADSPEC_SUBTREE2,
        ETT_RSVP_ADSPEC_SUBTREE3,
	ETT_RTSP,
	ETT_SDP,
	ETT_RADIUS,
	ETT_RADIUS_AVP,
	ETT_LAPB,
	ETT_X25,
	ETT_XDLC_CONTROL,
	ETT_ATM,
	ETT_ATM_LANE,
	ETT_ATM_LANE_LC_FLAGS,
	ETT_ATM_LANE_LC_LAN_DEST,
	ETT_ATM_LANE_LC_LAN_DEST_RD,
	NUM_TREE_TYPES	/* last item number plus one */
};


/* Utility routines used by packet*.c */
gchar*     ether_to_str(const guint8 *);
gchar*     ip_to_str(const guint8 *);
gchar*	   abs_time_to_str(struct timeval*);
gchar*     time_secs_to_str(guint32);
gchar*     bytes_to_str(const guint8 *, int);
const u_char *find_line_end(const u_char *data, const u_char *dataend,
    const u_char **eol);
int        get_token_len(const u_char *linep, const u_char *lineend,
    const u_char **next_token);
gchar*     format_text(const u_char *line, int len);
gchar*     val_to_str(guint32, const value_string *, const char *);
gchar*     match_strval(guint32, const value_string*);
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


void dissect_packet(const u_char *, frame_data *, proto_tree *);
/*
 * Routines in packet-*.c
 * Routines should take three args: packet data *, cap_len, packet_counts *
 * They should never modify the packet data.
 */
void capture_clip(const u_char *, guint32, packet_counts *);
void capture_eth(const u_char *, guint32, packet_counts *);
void capture_fddi(const u_char *, guint32, packet_counts *);
void capture_null(const u_char *, guint32, packet_counts *);
void capture_ppp(const u_char *, guint32, packet_counts *);
void capture_raw(const u_char *, guint32, packet_counts *);
void capture_tr(const u_char *, guint32, packet_counts *);

/*
 * Routines in packet-*.c
 * Routines should take four args: packet data *, offset, cap_len,
 * packet_counts *
 * They should never modify the packet data.
 */
void capture_netbios(const u_char *, int, guint32, packet_counts *);
void capture_llc(const u_char *, int, guint32, packet_counts *);
void capture_ip(const u_char *, int, guint32, packet_counts *);

/*
 * Routines in packet-*.c
 * Routines should take three args: packet data *, frame_data *, tree *
 * They should never modify the packet data.
 */
void dissect_atm(const u_char *, frame_data *, proto_tree *);
void dissect_clip(const u_char *, frame_data *, proto_tree *);
void dissect_lapb(const u_char *, frame_data *, proto_tree *);
void dissect_null(const u_char *, frame_data *, proto_tree *);
void dissect_ppp(const u_char *, frame_data *, proto_tree *);
void dissect_raw(const u_char *, frame_data *, proto_tree *);

/*
 * Routines in packet-*.c
 * Routines should take four args: packet data *, frame_data *, tree *,
 * gboolean
 * They should never modify the packet data.
 */
void dissect_fddi(const u_char *, frame_data *, proto_tree *, gboolean);

/*
 * Routines in packet-*.c
 * Routines should take four args: packet data *, offset, frame_data *,
 * tree *
 * They should never modify the packet data.
 */
int dissect_ah(const u_char *, int, frame_data *, proto_tree *);
void dissect_aarp(const u_char *, int, frame_data *, proto_tree *);
void dissect_arp(const u_char *, int, frame_data *, proto_tree *);
void dissect_bootp(const u_char *, int, frame_data *, proto_tree *);
void dissect_cdp(const u_char *, int, frame_data *, proto_tree *);
void dissect_cotp(const u_char *, int, frame_data *, proto_tree *);
void dissect_data(const u_char *, int, frame_data *, proto_tree *);
void dissect_ddp(const u_char *, int, frame_data *, proto_tree *);
void dissect_dns(const u_char *, int, frame_data *, proto_tree *);
void dissect_esp(const u_char *, int, frame_data *, proto_tree *);
void dissect_eth(const u_char *, int, frame_data *, proto_tree *);
void dissect_ftp(const u_char *, int, frame_data *, proto_tree *);
void dissect_ftpdata(const u_char *, int, frame_data *, proto_tree *);
void dissect_giop(const u_char *, int, frame_data *, proto_tree *);
void dissect_http(const u_char *, int, frame_data *, proto_tree *);
void dissect_icmp(const u_char *, int, frame_data *, proto_tree *);
void dissect_icmpv6(const u_char *, int, frame_data *, proto_tree *);
void dissect_igmp(const u_char *, int, frame_data *, proto_tree *);
void dissect_ip(const u_char *, int, frame_data *, proto_tree *);
void dissect_ipv6(const u_char *, int, frame_data *, proto_tree *);
void dissect_ipx(const u_char *, int, frame_data *, proto_tree *);
void dissect_llc(const u_char *, int, frame_data *, proto_tree *);
void dissect_lpd(const u_char *, int, frame_data *, proto_tree *);
void dissect_nbdgm(const u_char *, int, frame_data *, proto_tree *);
void dissect_netbios(const u_char *, int, frame_data *, proto_tree *);
void dissect_nbipx(const u_char *, int, frame_data *, proto_tree *);
void dissect_nbns(const u_char *, int, frame_data *, proto_tree *);
void dissect_nbss(const u_char *, int, frame_data *, proto_tree *);
void dissect_ncp(const u_char *, int, frame_data *, proto_tree *);
void dissect_nntp(const u_char *, int, frame_data *, proto_tree *);
void dissect_nwlink_dg(const u_char *, int, frame_data *, proto_tree *);
void dissect_osi(const u_char *, int, frame_data *, proto_tree *);
void dissect_ospf(const u_char *, int, frame_data *, proto_tree *);
void dissect_ospf_hello(const u_char *, int, frame_data *, proto_tree *);
void dissect_pop(const u_char *, int, frame_data *, proto_tree *);
void dissect_pppoed(const u_char *, int, frame_data *, proto_tree *);
void dissect_pppoes(const u_char *, int, frame_data *, proto_tree *);
void dissect_isakmp(const u_char *, int, frame_data *, proto_tree *);
void dissect_radius(const u_char *, int, frame_data *, proto_tree *);
void dissect_rip(const u_char *, int, frame_data *, proto_tree *);
void dissect_rsvp(const u_char *, int, frame_data *, proto_tree *);
void dissect_rtsp(const u_char *, int, frame_data *, proto_tree *);
void dissect_sdp(const u_char *, int, frame_data *, proto_tree *);
void dissect_snmp(const u_char *, int, frame_data *, proto_tree *);
void dissect_tcp(const u_char *, int, frame_data *, proto_tree *);
void dissect_telnet(const u_char *, int, frame_data *, proto_tree *);
void dissect_tftp(const u_char *, int, frame_data *, proto_tree *);
void dissect_tr(const u_char *, int, frame_data *, proto_tree *);
void dissect_trmac(const u_char *, int, frame_data *, proto_tree *);
void dissect_udp(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines_arp(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines_frp(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines_icp(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines_ipc(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines_rtp(const u_char *, int, frame_data *, proto_tree *);
void dissect_vines_spp(const u_char *, int, frame_data *, proto_tree *);
void dissect_payload_ppp(const u_char *, int, frame_data *, proto_tree *);
void dissect_x25(const u_char *, int, frame_data *, proto_tree *);

void dissect_smb(const u_char *, int, frame_data *, proto_tree *, int);
void dissect_pptp(const u_char *, int, frame_data *, proto_tree *);
void dissect_gre(const u_char *, int, frame_data *, proto_tree *);

void init_dissect_udp(void);
void init_dissect_x25(void);

/* These functions are in ethertype.c */
void capture_ethertype(guint16 etype, int offset,
		const u_char *pd, guint32 cap_len, packet_counts *ld);
void ethertype(guint16 etype, int offset,
		const u_char *pd, frame_data *fd, proto_tree *tree,
		proto_tree *fh_tree, int item_id);
extern const value_string etype_vals[];

/* These functions are in packet-arp.c */
gchar *arphrdaddr_to_str(guint8 *ad, int ad_len, guint16 type);
gchar *arphrdtype_to_str(guint16 hwtype, const char *fmt);

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
