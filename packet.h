/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet.h,v 1.12 1998/10/12 01:40:53 gerald Exp $
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

typedef struct _frame_data {
  guint32  pkt_len;         /* Packet length */
  guint32  cap_len;         /* Amount actually captured */
  guint32  secs;            /* Seconds */
  guint32  usecs;           /* Microseconds */
  long     file_off;        /* File offset */
  gchar   *win_info[NUM_COLS]; /* Text for packet summary list fields */
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

typedef struct _e_ether_arp {
  guint16 ar_hrd;
  guint16 ar_pro;
  guint8  ar_hln;
  guint8  ar_pln;
  guint16 ar_op;
  guint8  arp_sha[6];
  guint8  arp_spa[4];
  guint8  arp_tha[6];
  guint8  arp_tpa[4];
} e_ether_arp;

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

#define IPTOS_TOS_MASK    0x1E
#define IPTOS_TOS(tos)    ((tos) & IPTOS_TOS_MASK)
#define IPTOS_NONE        0x00
#define IPTOS_LOWDELAY    0x10
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_RELIABILITY 0x04
#define IPTOS_LOWCOST     0x02

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
#define UDP_PORT_RIP    520

/* TCP Ports */

#define TCP_PORT_PRINTER 515

/* Tree types.  Each dissect_* routine should have one for each
   add_subtree() call. */

#define ETT_FRAME          0
#define ETT_IEEE8023       1
#define ETT_ETHER2         2
#define ETT_LLC            3
#define ETT_TOKEN_RING     4
#define ETT_TR_IERR_CNT    5
#define ETT_TR_NERR_CNT    6
#define ETT_TR_MAC         7
#define ETT_PPP            8
#define ETT_ARP            9
#define ETT_IP            10
#define ETT_UDP           11
#define ETT_TCP           12
#define ETT_ICMP          13
#define ETT_IGMP          14
#define ETT_IPX           15
#define ETT_SPX           16
#define ETT_NCP           17
#define ETT_DNS           18
#define ETT_DNS_ANS       19
#define ETT_DNS_QRY       20
#define ETT_RIP           21
#define ETT_RIP_VEC       22
#define ETT_OSPF          23
#define ETT_OSPF_HDR      24
#define ETT_OSPF_HELLO    25
#define ETT_OSPF_DESC     26
#define ETT_OSPF_LSR      27
#define ETT_OSPF_LSA_UPD  28
#define ETT_OSPF_LSA      29
#define ETT_LPD           30
#define ETT_RAW           31
#define ETT_BOOTP         32
#define ETT_BOOTP_OPTION  33
#define ETT_IPv6	  34
#define ETT_CLNP          35
#define ETT_COTP          36
#define ETT_VINES         37
#define ETT_VSPP          38
#define ETT_IPXRIP        39
#define ETT_IPXSAP        40
#define ETT_IPXSAP_SERVER 41
#define ETT_NULL          42
#define ETT_FDDI          43

/* Should be the last item number plus one */
#define NUM_TREE_TYPES 44

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
gchar*     match_strval(guint32, value_string*, gint);

/* Routines in packet.c */

void dissect_packet(const u_char *, guint32 ts_secs, guint32 ts_usecs,
  frame_data *, GtkTree *);
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
void dissect_arp(const u_char *, int, frame_data *, GtkTree *);
void dissect_bootp(const u_char *, int, frame_data *, GtkTree *);
void dissect_data(const u_char *, int, frame_data *, GtkTree *);
void dissect_dns(const u_char *, int, frame_data *, GtkTree *);
void dissect_icmp(const u_char *, int, frame_data *, GtkTree *);
void dissect_igmp(const u_char *, int, frame_data *, GtkTree *);
void dissect_ip(const u_char *, int, frame_data *, GtkTree *);
void dissect_ipv6(const u_char *, int, frame_data *, GtkTree *);
void dissect_ipx(const u_char *, int, frame_data *, GtkTree *);
void dissect_llc(const u_char *, int, frame_data *, GtkTree *);
void dissect_lpd(const u_char *, int, frame_data *, GtkTree *);
void dissect_ncp(const u_char *, int, frame_data *, GtkTree *);
void dissect_osi(const u_char *, int, frame_data *, GtkTree *);
void dissect_ospf(const u_char *, int, frame_data *, GtkTree *);
void dissect_ospf_hello(const u_char *, int, frame_data *, GtkTree *);
void dissect_rip(const u_char *, int, frame_data *, GtkTree *);
void dissect_tcp(const u_char *, int, frame_data *, GtkTree *);
void dissect_trmac(const u_char *, int, frame_data *, GtkTree *);
void dissect_udp(const u_char *, int, frame_data *, GtkTree *);
void dissect_vines(const u_char *, int, frame_data *, GtkTree *);
void dissect_vspp(const u_char *, int, frame_data *, GtkTree *);

/* This function is in ethertype.c */
void ethertype(guint16 etype, int offset,
		const u_char *pd, frame_data *fd, GtkTree *tree,
		GtkWidget *fh_tree);

#endif /* packet.h */
