/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet.h,v 1.31 1999/01/04 09:13:45 guy Exp $
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


/* Useful when highlighting regions inside a dissect_*() function. With this
 * macro, you can highlight from the start of the packet to the end of the
 * frame. See dissect_data() for an example.
 */
#define END_OF_FRAME	(fd->cap_len - offset)

#define IEEE_802_3_MAX_LEN 1500
#define BYTE_VIEW_WIDTH    16

typedef struct _column_info {
  gint       num_cols; /* Number of columns */
  gboolean **fmt_matx; /* Specifies which formats apply to a column */
  gchar    **col_data; /* Column data */
} column_info;

#define COL_MAX_LEN 256

typedef struct _frame_data {
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
#ifdef WITH_WIRETAP
  int		lnk_t;     /* Per-packet encapsulation/data-link type */
#endif
} frame_data;

typedef struct _packet_info {
  char *srcip;
  int ip_src;
  char *destip;
  int ipproto;
  int srcport;
  int destport;
  int iplen;
  int iphdrlen;
} packet_info;

/* Struct for the match_strval function */

typedef struct _value_string {
  guint32  value;
  gchar   *strptr;
} value_string;

/* Many of the structs and definitions below were taken from include files
 * in the Linux distribution. */

/* ARP / RARP structs and definitions */

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST  1       /* ARP request.  */
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY    2       /* ARP reply.  */
#endif
/* Some OSes have different names, or don't define these at all */
#ifndef ARPOP_RREQUEST
#define ARPOP_RREQUEST 3       /* RARP request.  */
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY   4       /* RARP reply.  */
#endif

/* ICMP structs and definitions */

typedef struct _e_icmp {
  guint8  icmp_type;
  guint8  icmp_code;
  guint16 icmp_cksum;
  union {
    struct {  /* Address mask request/reply */
      guint16 id;
      guint16 seq;
      guint32 sn_mask;
    } am;
    struct {  /* Timestap request/reply */
      guint16 id;
      guint16 seq;
      guint32 orig;
      guint32 recv;
      guint32 xmit;
    } ts;
    guint32 zero;  /* Unreachable */
  } opt;
} e_icmp;

#define ICMP_ECHOREPLY     0
#define ICMP_UNREACH       3
#define ICMP_SOURCEQUENCH  4
#define ICMP_REDIRECT      5
#define ICMP_ECHO          8
#define ICMP_TIMXCEED     11
#define ICMP_PARAMPROB    12
#define ICMP_TSTAMP       13
#define ICMP_TSTAMPREPLY  14
#define ICMP_IREQ         15
#define ICMP_IREQREPLY    16
#define ICMP_MASKREQ      17
#define ICMP_MASKREPLY    18

/* IGMP structs and definitions */

typedef struct _e_igmp {
#if BYTE_ORDER == BIG_ENDIAN
  guint8  igmp_v:4;
  guint8  igmp_t:4;
#else /* Little endian */
  guint8  igmp_t:4;
  guint8  igmp_v:4;
#endif
  guint8  igmp_unused;
  guint16 igmp_cksum;
  guint32 igmp_gaddr;
} e_igmp;

#define IGMP_M_QRY     0x01
#define IGMP_V1_M_RPT  0x02
#define IGMP_V2_LV_GRP 0x07
#define IGMP_DVMRP     0x03
#define IGMP_PIM       0x04
#define IGMP_V2_M_RPT  0x06
#define IGMP_MTRC_RESP 0x1e
#define IGMP_MTRC      0x1f

/* IP structs and definitions */

typedef struct _e_ip {
#if BYTE_ORDER == BIG_ENDIAN
  guint8  ip_v:4;
  guint8  ip_hl:4;
#else /* Little endian */
  guint8  ip_hl:4;
  guint8  ip_v:4;
#endif
  guint8  ip_tos;
  guint16 ip_len;
  guint16 ip_id;
  guint16 ip_off;
  guint8  ip_ttl;
  guint8  ip_p;
  guint16 ip_sum;
  guint32 ip_src;
  guint32 ip_dst;
} e_ip;

/* IP flags. */
#define IP_CE		0x8000		/* Flag: "Congestion"		*/
#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

#define IPTOS_TOS_MASK    0x1E
#define IPTOS_TOS(tos)    ((tos) & IPTOS_TOS_MASK)
#define IPTOS_NONE        0x00
#define IPTOS_LOWCOST     0x02
#define IPTOS_RELIABILITY 0x04
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_LOWDELAY    0x10
#define IPTOS_SECURITY    0x1E

#define IPTOS_PREC_MASK		0xE0
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00

/* IP options */
#define IPOPT_COPY		0x80

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

#define IPOPT_END	(0 |IPOPT_CONTROL)
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_RR	(7 |IPOPT_CONTROL)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

/* IP option lengths */
#define IPOLEN_SEC      11
#define IPOLEN_LSRR_MIN 3
#define IPOLEN_TIMESTAMP_MIN 5
#define IPOLEN_RR_MIN   3
#define IPOLEN_SID      4
#define IPOLEN_SSRR_MIN 3

#define IPSEC_UNCLASSIFIED	0x0000
#define	IPSEC_CONFIDENTIAL	0xF135
#define	IPSEC_EFTO		0x789A
#define	IPSEC_MMMM		0xBC4D
#define	IPSEC_RESTRICTED	0xAF13
#define	IPSEC_SECRET		0xD788
#define	IPSEC_TOPSECRET		0x6BC5
#define	IPSEC_RESERVED1		0x35E2
#define	IPSEC_RESERVED2		0x9AF1
#define	IPSEC_RESERVED3		0x4D78
#define	IPSEC_RESERVED4		0x24BD
#define	IPSEC_RESERVED5		0x135E
#define	IPSEC_RESERVED6		0x89AF
#define	IPSEC_RESERVED7		0xC4D6
#define	IPSEC_RESERVED8		0xE26B

#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */

#define IP_PROTO_ICMP  1
#define IP_PROTO_IGMP  2
#define IP_PROTO_TCP   6
#define IP_PROTO_UDP  17
#define IP_PROTO_OSPF 89

/* Null/loopback structs and definitions */

typedef struct _e_nullhdr {
  guint8  null_next;
  guint8  null_len;
  guint16 null_family;
} e_nullhdr;

/* PPP structs and definitions */

typedef struct _e_ppphdr {
  guint8  ppp_addr;
  guint8  ppp_ctl;
  guint16 ppp_prot;
} e_ppphdr;

/* TCP structs and definitions */

typedef struct _e_tcphdr {
  guint16 th_sport;
  guint16 th_dport;
  guint32 th_seq;
  guint32 th_ack;
#if BYTE_ORDER == LITTLE_ENDIAN
  guint8  th_x2:4;
  guint8  th_off:4;
#else
  guint8  th_off:4;
  guint8  th_x2:4;
#endif
  guint8  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
  guint16 th_win;
  guint16 th_sum;
  guint16 th_urp;
} e_tcphdr;

/*
 *	TCP option
 */
 
#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_ECHO             6
#define TCPOPT_ECHOREPLY        7
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_CC               11
#define TCPOPT_CCNEW            12
#define TCPOPT_CCECHO           13

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_SACK_MIN       2
#define TCPOLEN_ECHO           6
#define TCPOLEN_ECHOREPLY      6
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_CC             6
#define TCPOLEN_CCNEW          6
#define TCPOLEN_CCECHO         6

/* UDP structs and definitions */

typedef struct _e_udphdr {
  guint16 uh_sport;
  guint16 uh_dport;
  guint16 uh_ulen;
  guint16 uh_sum;
} e_udphdr;

/* UDP Ports -> should go in packet-udp.h */

#define UDP_PORT_DNS     53
#define UDP_PORT_BOOTPS  67
#define UDP_PORT_IPX    213
#define UDP_PORT_NBNS	137
#define UDP_PORT_NBDGM	138
#define UDP_PORT_RIP    520
#define UDP_PORT_VINES	573

/* TCP Ports */

#define TCP_PORT_PRINTER 515

/* Tree types.  Each dissect_* routine should have one for each
   add_subtree() call. */

enum {
	ETT_FRAME,
	ETT_IEEE8023,
	ETT_ETHER2,
	ETT_LLC,
	ETT_TOKEN_RING,
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
	ETT_DNS,
	ETT_DNS_FLAGS,
	ETT_DNS_QRY,
	ETT_DNS_QD,
	ETT_DNS_ANS,
	ETT_DNS_RR,
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
	ETT_NBNS_QRY,
	ETT_NBNS_QD,
	ETT_NBNS_ANS,
	ETT_NBNS_RR,
	ETT_NBIPX,
	ETT_AARP,
	ETT_GIOP,
	ETT_NBDGM,
	ETT_CDP,
	NUM_TREE_TYPES	/* last item number plus one */
};

/* The version of pcap.h that comes with some systems is missing these
 * #defines.
 */

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

#ifndef DLT_SLIP_BSDOS
#define DLT_SLIP_BSDOS 13
#endif

#ifndef DLT_PPP_BSDOS
#define DLT_PPP_BSDOS 14
#endif

typedef enum {
  NO_LENGTH,		/* option has no data, hence no length */
  FIXED_LENGTH,		/* option always has the same length */
  VARIABLE_LENGTH	/* option is variable-length - optlen is minimum */
} opt_len_type;

/* Member of table of IP or TCP options. */
typedef struct {
  int   optcode;	/* code for option */
  char *name;		/* name of option */
  opt_len_type len_type; /* type of option length field */
  int	optlen;		/* value length should be (minimum if VARIABLE) */
  void	(*dissect)(GtkWidget *, const char *, const u_char *, int, guint);
			/* routine to dissect option */
} ip_tcp_opt;

/* Routine to dissect IP or TCP options. */
void       dissect_ip_tcp_options(GtkWidget *, const u_char *, int, guint,
    ip_tcp_opt *, int, int);

/* Utility routines used by packet*.c */
gchar*     ether_to_str(guint8 *);
gchar*     ip_to_str(guint8 *);
void       packet_hex_print(GtkText *, guint8 *, gint, gint, gint);
#define E_TREEINFO_START_KEY "tree_info_start"
#define E_TREEINFO_LEN_KEY   "tree_info_len"
#if __GNUC__ == 2
GtkWidget* add_item_to_tree(GtkWidget *, gint, gint, gchar *, ...)
    __attribute__((format (printf, 4, 5)));
#else
GtkWidget* add_item_to_tree(GtkWidget *, gint, gint, gchar *, ...);
#endif
void       set_item_len(GtkWidget *, gint);
gchar*     val_to_str(guint32, const value_string *, const char *);
gchar*     match_strval(guint32, const value_string*);
gint       check_col(frame_data *, gint);
#if __GNUC__ == 2
void       col_add_fstr(frame_data *, gint, gchar *, ...)
    __attribute__((format (printf, 3, 4)));
#else
void       col_add_fstr(frame_data *, gint, gchar *, ...);
#endif
void       col_add_str(frame_data *, gint, gchar *);

/* Routines in packet.c */

void dissect_packet(const u_char *, frame_data *, GtkTree *);
void add_subtree(GtkWidget *, GtkWidget*, gint);
void expand_tree(GtkWidget *, gpointer);
void collapse_tree(GtkWidget *, gpointer);

/*
 * Routines in packet-*.c
 * Routines should take three args: packet data *, frame_data *, tree *
 * They should never modify the packet data.
 */
void dissect_eth(const u_char *, frame_data *, GtkTree *);
void dissect_fddi(const u_char *, frame_data *, GtkTree *);
void dissect_null(const u_char *, frame_data *, GtkTree *);
void dissect_ppp(const u_char *, frame_data *, GtkTree *);
void dissect_raw(const u_char *, frame_data *, GtkTree *);
void dissect_tr(const u_char *, frame_data *, GtkTree *);

/*
 * Routines in packet-*.c
 * Routines should take four args: packet data *, offset, frame_data *,
 * tree *
 * They should never modify the packet data.
 */
void dissect_aarp(const u_char *, int, frame_data *, GtkTree *);
void dissect_arp(const u_char *, int, frame_data *, GtkTree *);
void dissect_bootp(const u_char *, int, frame_data *, GtkTree *);
void dissect_cdp(const u_char *, int, frame_data *, GtkTree *);
void dissect_data(const u_char *, int, frame_data *, GtkTree *);
void dissect_ddp(const u_char *, int, frame_data *, GtkTree *);
void dissect_dns(const u_char *, int, frame_data *, GtkTree *);
void dissect_giop(const u_char *, int, frame_data *, GtkTree *);
void dissect_icmp(const u_char *, int, frame_data *, GtkTree *);
void dissect_igmp(const u_char *, int, frame_data *, GtkTree *);
void dissect_ip(const u_char *, int, frame_data *, GtkTree *);
void dissect_ipv6(const u_char *, int, frame_data *, GtkTree *);
void dissect_ipx(const u_char *, int, frame_data *, GtkTree *);
void dissect_llc(const u_char *, int, frame_data *, GtkTree *);
void dissect_lpd(const u_char *, int, frame_data *, GtkTree *);
void dissect_nbdgm(const u_char *, int, frame_data *, GtkTree *);
void dissect_nbipx_ns(const u_char *, int, frame_data *, GtkTree *);
void dissect_nbns(const u_char *, int, frame_data *, GtkTree *);
void dissect_ncp(const u_char *, int, frame_data *, GtkTree *);
void dissect_nwlink_dg(const u_char *, int, frame_data *, GtkTree *);
void dissect_osi(const u_char *, int, frame_data *, GtkTree *);
void dissect_ospf(const u_char *, int, frame_data *, GtkTree *);
void dissect_ospf_hello(const u_char *, int, frame_data *, GtkTree *);
void dissect_rip(const u_char *, int, frame_data *, GtkTree *);
void dissect_tcp(const u_char *, int, frame_data *, GtkTree *);
void dissect_trmac(const u_char *, int, frame_data *, GtkTree *);
void dissect_udp(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines_arp(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines_frp(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines_icp(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines_ipc(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines_rtp(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines_spp(const u_char *, int, frame_data *, GtkTree *);

/* These functions are in ethertype.c */
gchar *ethertype_to_str(guint16 etype, const char *fmt);
void ethertype(guint16 etype, int offset,
		const u_char *pd, frame_data *fd, GtkTree *tree,
		GtkWidget *fh_tree);

#endif /* packet.h */
