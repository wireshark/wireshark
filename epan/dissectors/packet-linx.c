/* packet-linx.c
 * Routines for LINX packet dissection
 *
 * Copyright 2006, Martin Peylo <martin.peylo@siemens.com>
 *
 * $Id$
 *
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

/* The used document is:
 * ENEA Link Protocol Specification available at
 * http://linx.sourceforge.net
 *
 * Fits currently to
 * Enea LINX for Linux
 * Version: 2.5.0, May 16, 2011
 *
 * Added support for LINX ETHCM version 3 and LINX RLNH version 2.
 * Mattias Wallin, linx@enea.com, September 23, 2007
 *
 * Added support for LINX TCP CM.
 * Dejan Bucar, linx@enea.com, June 21, 2011
 *
 * Added support for LINX ETHCM Multicore header.
 * Dejan Bucar, linx@enea.com, June 21, 2011
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/etypes.h>

/* forward reference */
static void dissect_linx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int proto_linx     = -1;
static int proto_linx_tcp = -1;

/* ALL */
static int hf_linx_nexthdr         = -1;

/* MULTICORE */
static int hf_linx_multicore_scoreid   = -1;
static int hf_linx_multicore_dcoreid   = -1;
static int hf_linx_multicore_reserved  = -1;
static int hf_linx_multicore_reserved1 = -1;


/* MAIN */
static int hf_linx_main_version    = -1;
static int hf_linx_main_reserved   = -1;
static int hf_linx_main_connection = -1;
static int hf_linx_main_bundle     = -1;
static int hf_linx_main_pkgsize    = -1;

/* UDATA */
static int hf_linx_udata_reserved  = -1;
static int hf_linx_udata_morefrags = -1;
static int hf_linx_udata_fragno    = -1;
static int hf_linx_udata_signo     = -1;
static int hf_linx_udata_dstaddr16 = -1;
static int hf_linx_udata_dstaddr32 = -1;
static int hf_linx_udata_srcaddr16 = -1;
static int hf_linx_udata_srcaddr32 = -1;

/* ACK */
static int hf_linx_ack_reserved    = -1;
static int hf_linx_ack_request     = -1;
static int hf_linx_ack_ackno       = -1;
static int hf_linx_ack_seqno       = -1;

/* CONN */
static int hf_linx_conn_cmd          = -1;
static int hf_linx_conn_size         = -1;
static int hf_linx_conn_reserved     = -1;
static int hf_linx_conn_srcmac       = -1;
static int hf_linx_conn_dstmac       = -1;
static int hf_linx_conn_winsize      = -1;
static int hf_linx_conn_publcid      = -1;
static int hf_linx_conn_feat_neg_str = -1;
/* FRAG */
static int hf_linx_frag_reserved   = -1;
static int hf_linx_frag_morefrags  = -1;
static int hf_linx_frag_fragno     = -1;

/* NACK */
static int hf_linx_nack_reserv1    = -1;
static int hf_linx_nack_reserv2    = -1;
static int hf_linx_nack_count      = -1;
static int hf_linx_nack_seqno      = -1;

/* RLNH */
static int hf_linx_rlnh_msg_type32    = -1;
static int hf_linx_rlnh_msg_type8     = -1;
static int hf_linx_rlnh_linkaddr      = -1;
static int hf_linx_rlnh_src_linkaddr  = -1;
static int hf_linx_rlnh_version       = -1;
static int hf_linx_rlnh_status        = -1;
static int hf_linx_rlnh_name          = -1;
static int hf_linx_rlnh_peer_linkaddr = -1;
static int hf_linx_rlnh_feat_neg_str  = -1;
static int hf_linx_rlnh_msg_reserved  = -1;

/* TCP CM */
static int hf_linx_tcp_reserved           = -1;
static int hf_linx_tcp_oob                = -1;
static int hf_linx_tcp_version            = -1;
static int hf_linx_tcp_type               = -1;
static int hf_linx_tcp_src                = -1;
static int hf_linx_tcp_dst                = -1;
static int hf_linx_tcp_size               = -1;
static int hf_linx_tcp_rlnh_msg_type32    = -1;
static int hf_linx_tcp_rlnh_msg_type8     = -1;
static int hf_linx_tcp_rlnh_linkaddr      = -1;
static int hf_linx_tcp_rlnh_src_linkaddr  = -1;
static int hf_linx_tcp_rlnh_version       = -1;
static int hf_linx_tcp_rlnh_status        = -1;
static int hf_linx_tcp_rlnh_name          = -1;
static int hf_linx_tcp_rlnh_peer_linkaddr = -1;
static int hf_linx_tcp_rlnh_feat_neg_str  = -1;
static int hf_linx_tcp_rlnh_msg_reserved  = -1;


static int rlnh_version = 0;

static gint ett_linx           = -1;
static gint ett_linx_multicore = -1;
static gint ett_linx_main      = -1;
static gint ett_linx_error     = -1;
static gint ett_linx_udata     = -1;
static gint ett_linx_ack       = -1;
static gint ett_linx_tcp       = -1;

/* Definition and Names */

#define ETHCM_MAIN  0x0
#define ETHCM_CONN  0x1
#define ETHCM_UDATA 0x2
#define ETHCM_FRAG  0x3
#define ETHCM_ACK   0x4
#define ETHCM_NACK  0x5
#define ETHCM_NONE  0xf

static const value_string linx_short_header_names[]={
	{ ETHCM_MAIN,  "MAIN"},
	{ ETHCM_CONN,  "CONN"},
	{ ETHCM_UDATA, "UDATA"},
	{ ETHCM_FRAG,  "FRAG"},
	{ ETHCM_ACK,   "ACK"},
	{ ETHCM_NACK,  "NACK"},
	{ ETHCM_NONE,  "NONE"},
	{ 0,	NULL}
};

static const value_string linx_long_header_names[] = {
	{ ETHCM_MAIN,  "Main"},
	{ ETHCM_CONN,  "Connection"},
	{ ETHCM_UDATA, "Udata"},
	{ ETHCM_FRAG,  "Fragmentation"},
	{ ETHCM_ACK,   "Ack"},
	{ ETHCM_NACK,  "Nack"},
	{ ETHCM_NONE,  "None"},
	{ 0,	NULL}
};

#define TCP_CM_CONN  0x43
#define TCP_CM_UDATA 0x55
#define TCP_CM_PING  0x50
#define TCP_CM_PONG  0x51

static const value_string linx_short_tcp_names[] = {
	{TCP_CM_CONN,  "conn"},
	{TCP_CM_UDATA, "udata"},
	{TCP_CM_PING,  "ping"},
	{TCP_CM_PONG,  "pong"},
	{0,     NULL}
};

static const value_string linx_long_tcp_names[] = {
	{TCP_CM_CONN,  "Connection msg"},
	{TCP_CM_UDATA, "User data"},
	{TCP_CM_PING,  "Ping msg"},
	{TCP_CM_PONG,  "Pong msg"},
	{0,     NULL}
};

/* RLNH version 1 */
#define RLNH_LINK_ADDR     0
#define RLNH_QUERY_NAME	   1
#define RLNH_PUBLISH       2
#define RLNH_UNPUBLISH     3
#define RLNH_UNPUBLISH_ACK 4
#define RLNH_INIT          5
#define RLNH_INIT_REPLY    6
#define RLNH_PUBLISH_PEER  7

static const value_string linx_short_rlnh_names[]={
	{ RLNH_LINK_ADDR,     "link_addr"},
	{ RLNH_QUERY_NAME,    "query_name"},
	{ RLNH_PUBLISH,       "publish"},
	{ RLNH_UNPUBLISH,     "unpublish"},
	{ RLNH_UNPUBLISH_ACK, "unpublish_ack"},
	{ RLNH_INIT,          "init"},
	{ RLNH_INIT_REPLY,    "init_reply"},
	{ RLNH_PUBLISH_PEER,  "publish_peer"},
	{ 0,	NULL}
};

static const value_string linx_long_rlnh_names[]={
	{ RLNH_LINK_ADDR,     "Link Address"},
	{ RLNH_QUERY_NAME,    "Query Name"},
	{ RLNH_PUBLISH,       "Publish"},
	{ RLNH_UNPUBLISH,     "Unpublish"},
	{ RLNH_UNPUBLISH_ACK, "Unpublish Ack"},
	{ RLNH_INIT,          "Init"},
	{ RLNH_INIT_REPLY,    "Init Reply"},
	{ RLNH_PUBLISH_PEER,  "Publish Peer"},
	{ 0,	NULL}
};

static const value_string linx_rlnh_reply[] = {
        { 0, "Version supported"},
        { 1, "Version NOT supported"},
        { 0, NULL}
};

static const value_string linx_boolean[] = {
	{ 0, "No"},
	{ 1, "Yes"},
	{ 0,	NULL}
};

static const value_string linx_nofragment[] = {
	{ 0x7fff, "No Fragment"},
	{ 0,	NULL}
};

static const value_string linx_coreid[]= {
	{0xff, "None"},
	{0,     NULL}
};

#define CONN_RESET       1
#define CONN_CONNECT     2
#define CONN_CONNECT_ACK 3
#define CONN_ACK         4

static const value_string linx_conn_cmd[] = {
	{ CONN_RESET,       "Reset"},
	{ CONN_CONNECT,     "Connect"},
	{ CONN_CONNECT_ACK, "Connect_Ack"},
	{ CONN_ACK,         "Ack"},
	{ 0,	NULL}
};

static void
dissect_linx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 dword;
	int	offset = 0;
	int	nexthdr;
	int	thishdr;
	int	size;
	int	pkgsize;
	int	payloadsize;
	int	version;
	int     conntype;
	proto_item *item;
	proto_tree *multicore_header_tree;
	proto_tree *main_header_tree;
	proto_tree *conn_header_tree;
	proto_tree *ack_header_tree;
	proto_tree *udata_header_tree;
	proto_tree *nack_header_tree;
	proto_tree *frag_header_tree;
	proto_tree *rlnh_header_tree;
	tvbuff_t *linx_tvb;

	/* Show name in protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINX");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	{ /* Work out the details */
		proto_item *ti        = NULL;
		proto_tree *linx_tree = NULL;

		ti = proto_tree_add_item(tree, proto_linx, tvb, 0, -1, ENC_NA);
		linx_tree = proto_item_add_subtree(ti, ett_linx);

		dword   = tvb_get_ntohl(tvb, offset);
		nexthdr = (dword >> 28) & 0xf;

		/* check if we have multicore header*/
		if (nexthdr == ETHCM_MAIN)
		{
			item = proto_tree_add_text(linx_tree, tvb, 0, 4, "Multicore Header");
			multicore_header_tree = proto_item_add_subtree(item, ett_linx_multicore);

			/* Multicore header */
			/*
			   0                   1                   2                   3
			   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   | Next  |   R   |  Dest Coreid  | Source Coreid |      R        |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			 */
			proto_tree_add_item(multicore_header_tree, hf_linx_nexthdr,             tvb, 0, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(multicore_header_tree, hf_linx_multicore_reserved,  tvb, 0, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(multicore_header_tree, hf_linx_multicore_dcoreid,   tvb, 0, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(multicore_header_tree, hf_linx_multicore_scoreid,   tvb, 0, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(multicore_header_tree, hf_linx_multicore_reserved1, tvb, 0, 4, ENC_BIG_ENDIAN);

			offset += 4;
			/* read main header*/
			dword = tvb_get_ntohl(tvb, offset);
		}

		version = (dword >> 25) & 0x7;
		nexthdr = (dword >> 28) & 0xf;
		pkgsize = dword & 0x3fff;
		linx_tvb = tvb_new_subset(tvb, 0, pkgsize, pkgsize);
		tvb_set_reported_length(tvb, pkgsize);

		/* Supports version 2 and 3 so far */
		if (version < 2 || version > 3) {
			proto_tree_add_text(linx_tree, linx_tvb, offset, 0, "Version %u in not yet supported and might be dissected incorrectly!", version);
		}

		/* main header */
		item = proto_tree_add_text(linx_tree, linx_tvb, offset, 4, "Main Header");
		main_header_tree = proto_item_add_subtree(item, ett_linx_main);

		/* Main header */
		/*
		0                   1                   2                   3
		 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		| Next  | Ver | R |   Connection  |R|        Packet size        |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/

		proto_tree_add_item(main_header_tree, hf_linx_nexthdr        , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(main_header_tree, hf_linx_main_version   , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(main_header_tree, hf_linx_main_reserved  , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(main_header_tree, hf_linx_main_connection, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(main_header_tree, hf_linx_main_bundle    , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(main_header_tree, hf_linx_main_pkgsize   , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		while (nexthdr != ETHCM_NONE) {

			dword    = tvb_get_ntohl(linx_tvb, offset);
			thishdr  = nexthdr;
			nexthdr  = (dword >>28) & 0xf;
			conntype = (dword >>24) & 0xf;
			/* Write non trivial header name to info column */
			if ((thishdr != ETHCM_NONE) && (thishdr != ETHCM_MAIN)) {
			        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(thishdr, linx_short_header_names, "unknown"));
				if(thishdr == ETHCM_CONN)
				        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(conntype, linx_conn_cmd, "unknown"));
			}

			switch (thishdr) {

				case ETHCM_CONN:
					/* Connect header */
					/*
					   0                   1                   2                   3
					   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  | Type  |Size |Winsize|    Reserved     |Publish conn id|
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  :                                                               :
					  :              dst hw addr followed by src hw addr              :
					  :                                                               :
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  					  :                                                               :
					  :         Feature negotiation string (null terminated)          :
					  :                                                               :
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					*/

					size = (dword >>21) & 0x7;
					item = proto_tree_add_text(linx_tree, linx_tvb, offset, (4+2*size), "Connection Header");
					conn_header_tree = proto_item_add_subtree(item, ett_linx_main);
					proto_tree_add_item(conn_header_tree, hf_linx_nexthdr      , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(conn_header_tree, hf_linx_conn_cmd     , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(conn_header_tree, hf_linx_conn_size    , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(conn_header_tree, hf_linx_conn_winsize , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(conn_header_tree, hf_linx_conn_reserved, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(conn_header_tree, hf_linx_conn_publcid , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					/* MEDIA ADDRESS */
					if (size == 6) {
						/* Most likely ETHERNET */
						proto_tree_add_item(conn_header_tree, hf_linx_conn_dstmac, linx_tvb, offset, 6, ENC_NA);
						proto_tree_add_item(conn_header_tree, hf_linx_conn_srcmac, linx_tvb, offset + 6, 6, ENC_NA);
					}

					offset += (2*size);
					/* Feature Negotiation String */
					if(version > 2) {
					        proto_tree_add_item(conn_header_tree, hf_linx_conn_feat_neg_str, linx_tvb, offset, -1, ENC_ASCII|ENC_NA);
						offset += tvb_strnlen(linx_tvb, offset, -1);
					}
					break;

				case ETHCM_NACK:
					/* Nack header */
					/*
					   0                   1                   2                   3
					   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  |  Res  |     Count     |  Res  |         Seqno         |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					*/

					dword     = tvb_get_ntohl(linx_tvb, offset);
					/* how many sequence numbers will be there? */
					/* this is not implemented due to a lack of documentation with */
					/* longer seqence numbers. */
					/* guess there will be padding if the Seqno doesn't reach */
					/* a 32bit boundary */

					item = proto_tree_add_text(linx_tree, linx_tvb, offset, 4, "NACK Header");
					nack_header_tree = proto_item_add_subtree(item, ett_linx_main);
					proto_tree_add_item(nack_header_tree, hf_linx_nexthdr     , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(nack_header_tree, hf_linx_nack_reserv1, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(nack_header_tree, hf_linx_nack_count  , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(nack_header_tree, hf_linx_nack_reserv2, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(nack_header_tree, hf_linx_nack_seqno  , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				case ETHCM_UDATA:
					/* User data / fragment header => Version 3 */
					/*
					  0		      1			  2		      3
					  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  |	 Reserved	  |M|	       Frag no		  |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  |                          Destination                          |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  |                             Source                            |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

					  * User data / fragment header => Version 2

					  0		      1			  2		      3
					  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  |	 Reserved	  |M|	       Frag no		  |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  |                           Reserved                            |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  |		  Dst		  |		  Src		  |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

					  - fragments (not first fragment)

					  0		      1			  2		      3
					  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  |	 Reserved	  |M|	       Frag no		  |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					*/


					item = proto_tree_add_text(linx_tree, linx_tvb, offset, 12, "Udata Header");
					udata_header_tree = proto_item_add_subtree(item, ett_linx_main);
					proto_tree_add_item(udata_header_tree, hf_linx_nexthdr, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(udata_header_tree, hf_linx_udata_reserved , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(udata_header_tree, hf_linx_udata_morefrags, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(udata_header_tree, hf_linx_udata_fragno   , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					/* signo removed in version 3 and linkaddresses extended to 32 bits */
					if(version == 2) {
					     proto_tree_add_item(udata_header_tree, hf_linx_udata_signo    , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					     offset += 4;
					     proto_tree_add_item(udata_header_tree, hf_linx_udata_dstaddr16, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					     proto_tree_add_item(udata_header_tree, hf_linx_udata_srcaddr16, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					     dword = tvb_get_ntohl(linx_tvb, offset);
					} else {
					     proto_tree_add_item(udata_header_tree, hf_linx_udata_dstaddr32, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					     dword = tvb_get_ntohl(linx_tvb, offset);
					     offset += 4;
					     proto_tree_add_item(udata_header_tree, hf_linx_udata_srcaddr32, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					     if(dword == 0 && tvb_get_ntohl(linx_tvb, offset) == 0) {
						     dword = 0;
					     } else {
						     dword = 1;
					     }
					}
					offset += 4;
					if (dword == 0) {
						/* (dstaddr == srcaddr == 0) -> RLNH Protocol Message */

					        dword = tvb_get_ntohl(linx_tvb, offset);

						/* Write to info column */
						col_append_fstr(pinfo->cinfo, COL_INFO, "rlnh:%s ", val_to_str(dword, linx_short_rlnh_names, "unknown"));

						/* create new paragraph for RLNH */
						item = proto_tree_add_text(linx_tree, linx_tvb, offset, 4, "RLNH");
						rlnh_header_tree = proto_item_add_subtree(item, ett_linx_main);

						if(version == 1) {
							proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_msg_type32, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
							offset += 4;
						} else {
							/* in version 2 of the rlnh protocol the length of the message type is restricted to 8 bits */
							proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_msg_reserved, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
							proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_msg_type8, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
							offset += 4;
						}

						switch (dword) {
							case RLNH_LINK_ADDR:
							  /* XXX what is this? */
								break;
							case RLNH_QUERY_NAME:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_src_linkaddr, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									offset += 4;
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_name, linx_tvb, offset, -1, ENC_ASCII|ENC_NA);
									offset += tvb_strnlen(linx_tvb, offset, -1);
								break;
							case RLNH_PUBLISH:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_src_linkaddr, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									offset += 4;
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_name, linx_tvb, offset, -1, ENC_ASCII|ENC_NA);
									offset += tvb_strnlen(linx_tvb, offset, -1);
								break;
							case RLNH_UNPUBLISH:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_src_linkaddr, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									offset += 4;
								break;
							case RLNH_UNPUBLISH_ACK:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_src_linkaddr, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									offset += 4;
								break;
							case RLNH_INIT:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_version, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									/* This is not working if nodes are at different versions. Only the latest value will be saved in rlnh_version */
									rlnh_version = tvb_get_ntohl(linx_tvb, offset);
									offset += 4;
								break;
							case RLNH_INIT_REPLY:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_status, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									offset += 4;
									if(rlnh_version > 1) {
									        proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_feat_neg_str, linx_tvb, offset, -1, ENC_ASCII|ENC_NA);
										offset += tvb_strnlen(linx_tvb, offset, -1);
									}
								break;
							case RLNH_PUBLISH_PEER:
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_src_linkaddr, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
									offset += 4;
									proto_tree_add_item(rlnh_header_tree, hf_linx_rlnh_peer_linkaddr, linx_tvb, offset, -1, ENC_BIG_ENDIAN);
									offset += tvb_strnlen(linx_tvb, offset, -1);
								break;
							default:
									/* no known Message type... */
									/* this could be done better */
									proto_tree_add_text(rlnh_header_tree, linx_tvb, offset, 0,"ERROR: Header \"%u\" not recognized", dword);
								break;
						}
					} else {
						/* Is there payload? */
						/* anything better to do with that? */
						payloadsize = pkgsize-offset;
						if (payloadsize) {
							proto_tree_add_text(linx_tree, linx_tvb, offset, payloadsize,"%u bytes data", payloadsize);
						}
					}
					break;

				case ETHCM_ACK:
					/* Reliable header */
					/*
					   0                   1                   2                   3
					   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  |R| Res.|         Ackno         |         Seqno         |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					*/
					item = proto_tree_add_text(linx_tree, linx_tvb, offset, 4, "Ack Header");
					ack_header_tree = proto_item_add_subtree(item, ett_linx_main);
					proto_tree_add_item(ack_header_tree, hf_linx_nexthdr     , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(ack_header_tree, hf_linx_ack_request , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(ack_header_tree, hf_linx_ack_reserved, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(ack_header_tree, hf_linx_ack_ackno   , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(ack_header_tree, hf_linx_ack_seqno   , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				case ETHCM_FRAG:
					/*
					  - fragments (not first fragment)

					   0                   1                   2                   3
					   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					  | Next  |      Reserved         |M|          Frag no            |
					  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
					 */

					item = proto_tree_add_text(linx_tree, linx_tvb, offset, 4, "Fragmentation Header");
					frag_header_tree = proto_item_add_subtree(item, ett_linx_main);
					proto_tree_add_item(frag_header_tree, hf_linx_nexthdr       , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(frag_header_tree, hf_linx_frag_reserved , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(frag_header_tree, hf_linx_frag_morefrags, linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					proto_tree_add_item(frag_header_tree, hf_linx_frag_fragno   , linx_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;

				default:
					proto_tree_add_text(linx_tree, linx_tvb, offset, 4,"ERROR: Header \"%u\" not recognized", thishdr);
					nexthdr = ETHCM_NONE; /* avoid endless loop with faulty packages */
					break;
			}
		}

	}
}


/* Protocol Initialisation */
void
proto_register_linx(void)
{

	/* Registering Data Structures */

	static hf_register_info hf[] = {
		{ &hf_linx_nexthdr,
			{ "Next Header", "linx.nexthdr", FT_UINT32, BASE_DEC, VALS(linx_long_header_names), 0xf0000000, NULL, HFILL },
		},
		{ &hf_linx_multicore_scoreid, /* in ETHCM_MULTICORE */
			{ "Source coreid", "linx.scoreid", FT_UINT32, BASE_DEC, VALS(linx_coreid), 0x0000ff00, "Multicore source core id", HFILL },
		},
		{ &hf_linx_multicore_dcoreid, /* in ETHCM_MULTICORE */
			{ "Destination coreid", "linx.dcoreid", FT_UINT32, BASE_DEC, VALS(linx_coreid), 0x00ff0000, "Multicore destination core id", HFILL},
		},
		{ &hf_linx_multicore_reserved, /* in ETHCM_MULTICORE */
			{ "Reserved", "linx.reserved8", FT_UINT32, BASE_DEC, NULL, 0x0f000000, "Multicore Hdr Reserved", HFILL},
		},
		{ &hf_linx_multicore_reserved1, /* in ETHCM_MULTICORE */
			{ "Reserved", "linx.reserved9", FT_UINT32, BASE_DEC, NULL, 0x000000ff, "Multicore Hdr Reserved", HFILL},
		},
		{ &hf_linx_main_version, /* in ETHCM_MAIN */
			{ "Version", "linx.version", FT_UINT32, BASE_DEC, NULL, 0x0e000000, "LINX Version", HFILL },
		},
		{ &hf_linx_main_reserved, /* in ETHCM_MAIN */
			{ "Reserved", "linx.reserved1", FT_UINT32, BASE_DEC, NULL, 0x01800000, "Main Hdr Reserved", HFILL },
		},
		{ &hf_linx_main_connection, /* in ETHCM_MAIN */
			{ "Connection", "linx.connection", FT_UINT32, BASE_DEC, NULL, 0x007f8000, NULL, HFILL },
		},
		{ &hf_linx_main_bundle, /* in ETHCM_MAIN */
			{ "Bundle", "linx.bundle", FT_UINT32, BASE_DEC, VALS(linx_boolean), 0x00004000, NULL, HFILL },
		},
		{ &hf_linx_main_pkgsize, /* in ETHCM_MAIN */
			{ "Package Size", "linx.pcksize", FT_UINT32, BASE_DEC, NULL, 0x00003fff, NULL, HFILL },
		},
		{ &hf_linx_udata_reserved, /* in ETHCM_UDATA */
			{ "Reserved", "linx.reserved5", FT_UINT32, BASE_DEC, NULL, 0x0fff0000, "Udata Hdr Reserved", HFILL },
		},
		{ &hf_linx_udata_morefrags, /* in ETHCM_UDATA */
			{ "More Fragments", "linx.morefra", FT_UINT32, BASE_DEC, VALS(linx_boolean), 0x00008000, "More fragments follow", HFILL },
		},
		{ &hf_linx_udata_fragno, /* in ETHCM_UDATA */
			{ "Fragment Number", "linx.fragno", FT_UINT32, BASE_DEC, VALS(linx_nofragment), 0x00007fff, NULL, HFILL },
		},
		{ &hf_linx_udata_signo, /* in ETHCM_UDATA */
			{ "Signal Number", "linx.signo", FT_UINT32, BASE_DEC, NULL, 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_udata_dstaddr16, /* in ETHCM_UDATA - protocol version 2 */
			{ "Receiver Address", "linx.dstaddr", FT_UINT32, BASE_DEC, NULL, 0xffff0000, NULL, HFILL },
		},
		{ &hf_linx_udata_dstaddr32, /* in ETHCM_UDATA - protocol version 3 */
			{ "Receiver Address", "linx.dstaddr32", FT_UINT32, BASE_DEC, NULL, 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_udata_srcaddr16, /* in ETHCM_UDATA - protocol version 2 */
			{ "Sender Address", "linx.srcaddr", FT_UINT32, BASE_DEC, NULL, 0x0000ffff, NULL, HFILL },
		},
		{ &hf_linx_udata_srcaddr32, /* in ETHCM_UDATA - protocol version 3 */
			{ "Sender Address", "linx.srcaddr32", FT_UINT32, BASE_DEC, NULL, 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_ack_request, /* in ETHCM_ACK */
			{ "ACK-request", "linx.ackreq", FT_UINT32, BASE_DEC, VALS(linx_boolean), 0x08000000, NULL, HFILL },
		},
		{ &hf_linx_ack_reserved, /* in ETHCM_ACK */
			{ "Reserved", "linx.reserved7", FT_UINT32, BASE_DEC, NULL, 0x07000000, "ACK Hdr Reserved", HFILL },
		},
		{ &hf_linx_ack_ackno, /* in ETHCM_ACK */
			{ "ACK Number", "linx.ackno", FT_UINT32, BASE_DEC, NULL, 0x00fff000, NULL, HFILL },
		},
		{ &hf_linx_ack_seqno, /* in ETHCM_ACK */
			{ "Sequence Number", "linx.seqno", FT_UINT32, BASE_DEC, NULL, 0x00000fff, NULL, HFILL },
		},
		{ &hf_linx_conn_cmd, /* in ETHCM_CONN */
			{ "Command", "linx.cmd", FT_UINT32, BASE_DEC, VALS(linx_conn_cmd), 0x0f000000, NULL, HFILL },
		},
		{ &hf_linx_conn_size, /* in ETHCM_CONN */
			{ "Size", "linx.size", FT_UINT32, BASE_DEC, NULL, 0x00e00000, NULL, HFILL },
		},
		{ &hf_linx_conn_winsize, /* in ETHCM_CONN */
			{ "WinSize", "linx.winsize", FT_UINT32, BASE_DEC, NULL, 0x001e0000, "Window Size", HFILL },
		},
		{ &hf_linx_conn_reserved, /* in ETHCM_CONN */
			{ "Reserved", "linx.reserved3", FT_UINT32, BASE_DEC, NULL, 0x0001ff00, "Conn Hdr Reserved", HFILL },
		},
		{ &hf_linx_conn_publcid, /* in ETHCM_CONN */
			{ "Publish Conn ID", "linx.publcid", FT_UINT32, BASE_DEC, NULL, 0x000000ff, NULL, HFILL },
		},
		{ &hf_linx_conn_srcmac, /* in ETHCM_CONN */
			{ "Source", "linx.srcmaddr_ether", FT_ETHER, BASE_NONE, NULL, 0x0, "Source Media Address (ethernet)", HFILL },
		},
		{ &hf_linx_conn_dstmac, /* in ETHCM_CONN */
			{ "Destination", "linx.destmaddr_ether", FT_ETHER, BASE_NONE, NULL, 0x0, "Destination Media Address (ethernet)", HFILL },
		},
		{ &hf_linx_conn_feat_neg_str, /* in ETHCM_CONN */
		        { "Feature Negotiation String", "linx.feat_neg_str", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_linx_frag_reserved, /* in ETHCM_FRAG */
			{ "Reserved", "linx.reserved6", FT_UINT32, BASE_DEC, NULL, 0x0fff0000, "Frag Hdr Reserved", HFILL },
		},
		{ &hf_linx_frag_morefrags, /* in ETHCM_FRAG */
			{ "More Fragments", "linx.morefr2", FT_UINT32, BASE_DEC, VALS(linx_boolean), 0x00008000, NULL, HFILL },
		},
		{ &hf_linx_frag_fragno, /* in ETHCM_FRAG */
			{ "Fragment Number", "linx.fragno2", FT_UINT32, BASE_DEC, NULL, 0x00007fff, NULL, HFILL },
		},
		{ &hf_linx_nack_reserv1, /* in ETHCM_NACK */
			{ "Reserved", "linx.nack_reserv", FT_UINT32, BASE_DEC, NULL, 0x0f000000, "Nack Hdr Reserved", HFILL },
		},
		{ &hf_linx_nack_count, /* in ETHCM_NACK */
			{ "Count", "linx.nack_count", FT_UINT32, BASE_DEC, NULL, 0x00ff0000, NULL, HFILL },
		},
		{ &hf_linx_nack_reserv2, /* in ETHCM_NACK */
			{ "Reserved", "linx.nack_reserv", FT_UINT32, BASE_DEC, NULL, 0x0000f000, "Nack Hdr Reserved", HFILL },
		},
		{ &hf_linx_nack_seqno, /* in ETHCM_NACK */
			{ "Sequence Number", "linx.nack_seqno", FT_UINT32, BASE_DEC, NULL, 0x00000fff, NULL, HFILL },
		},

	  /* RLNH */
		{ &hf_linx_rlnh_msg_type32, /* in RLNH */
			{ "RLNH msg type", "linx.rlnh_msg_type", FT_UINT32, BASE_DEC, VALS(linx_long_rlnh_names), 0xffffffff, "RLNH message type", HFILL },
		},
		{ &hf_linx_rlnh_msg_type8, /* in RLNH */
			{ "RLNH msg type", "linx.rlnh_msg_type8", FT_UINT32, BASE_DEC, VALS(linx_long_rlnh_names), 0x000000ff, "RLNH message type", HFILL },
		},
		{ &hf_linx_rlnh_msg_reserved, /* in RLNH */
		        { "RLNH msg reserved", "linx.rlnh_msg_reserved", FT_UINT32, BASE_DEC, NULL, 0xffffff00, "RLNH message reserved", HFILL },
		},
		{ &hf_linx_rlnh_linkaddr, /* in RLNH */
			{ "RLNH linkaddr", "linx.rlnh_linkaddr", FT_UINT32, BASE_DEC, NULL, 0xffffffff, "RLNH linkaddress", HFILL },
		},
		{ &hf_linx_rlnh_src_linkaddr, /* in RLNH */
			{ "RLNH src linkaddr", "linx.rlnh_src_linkaddr", FT_UINT32, BASE_DEC, NULL, 0xffffffff, "RLNH source linkaddress", HFILL },
		},
		{ &hf_linx_rlnh_peer_linkaddr, /* in RLNH */
			{ "RLNH peer linkaddr", "linx.rlnh_peer_linkaddr", FT_UINT32, BASE_DEC, NULL, 0xffffffff, "RLNH peer linkaddress", HFILL },
		},
		{ &hf_linx_rlnh_version, /* in RLNH */
			{ "RLNH version", "linx.rlnh_version", FT_UINT32, BASE_DEC, NULL, 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_rlnh_status, /* in RLNH */
			{ "RLNH reply", "linx.rlnh_status", FT_UINT32, BASE_DEC, VALS(linx_rlnh_reply), 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_rlnh_name, /* in RLNH */
			{ "RLNH name", "linx.rlnh_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_linx_rlnh_feat_neg_str, /* in RLNH */
		        { "RLNH Feature Negotiation String", "linx.rlnh_feat_neg_str", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_linx,
		&ett_linx_multicore,
		&ett_linx_main,
		&ett_linx_error,
		&ett_linx_udata,
		&ett_linx_ack
	};

	proto_linx = proto_register_protocol (
		"ENEA LINX",	/* name */
		"LINX",		/* short name */
		"linx"		/* abbrev */
		);

	/* Protocol Registering data structures. */
	proto_register_field_array(proto_linx, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* Protocol Handoff */
void
proto_reg_handoff_linx(void)
{
	dissector_handle_t linx_handle;

	linx_handle = create_dissector_handle(dissect_linx, proto_linx);
	dissector_add_uint("ethertype", ETHERTYPE_LINX, linx_handle);
}

/************ TCP CM **************/

#define TCP_PORT_LINX 19790

static void
dissect_linx_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 dword;
	tvbuff_t *linx_tcp_tvb;
	int offset = 0;
	proto_item *item;
	proto_item *ti;
	proto_tree *linx_tcp_tree;
	proto_tree *tcp_header_tree;
	proto_tree *rlnh_header_tree;
	int payloadsize;
	int version;
	int size;
	int type;

	/* Show name in protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LINX/TCP");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	dword   = tvb_get_ntohl(tvb, 0);
	version = (dword >> 16) & 0xFF;
	type    = (dword >> 24) & 0xFF;

	/* size of linx tcp cm header */
	size    = 16;

	if (type == 0x55) {
		dword  = tvb_get_ntohl(tvb, 12);
		size  += (dword & 0xFFFFFFFF);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, "tcpcm:%s ", val_to_str(type, linx_short_tcp_names, "unknown"));

	tvb_set_reported_length(tvb, size);
	linx_tcp_tvb = tvb_new_subset(tvb, 0, size, size);

	ti = proto_tree_add_item(tree, proto_linx_tcp, linx_tcp_tvb, 0, -1, ENC_NA);
	linx_tcp_tree = proto_item_add_subtree(ti, ett_linx_tcp);

	if (version != 3) {
		proto_tree_add_text(linx_tcp_tree, linx_tcp_tvb, 0, 0, "Version %u not yet supported and might be dissected incorrectly!", version);
	}

	item = proto_tree_add_text(linx_tcp_tree, linx_tcp_tvb, 0, 16, "TCP CM Header");
	tcp_header_tree = proto_item_add_subtree(item, ett_linx_tcp);

	proto_tree_add_item(tcp_header_tree, hf_linx_tcp_type, linx_tcp_tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tcp_header_tree, hf_linx_tcp_version, linx_tcp_tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tcp_header_tree, hf_linx_tcp_oob, linx_tcp_tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tcp_header_tree, hf_linx_tcp_src, linx_tcp_tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tcp_header_tree, hf_linx_tcp_dst, linx_tcp_tvb, 8, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tcp_header_tree, hf_linx_tcp_size, linx_tcp_tvb, 12, 4, 	ENC_BIG_ENDIAN);

	offset += 16;

	if (type == 0x55) { /* UDATA */
		dword = tvb_get_ntohl(linx_tcp_tvb, 8);
		if (dword == 0) { /* RLNH Message*/

			dword = tvb_get_ntohl(linx_tcp_tvb, offset);

			/* Write to info column */
			col_append_fstr(pinfo->cinfo, COL_INFO, "rlnh:%s ", val_to_str(dword, linx_short_rlnh_names, "unknown"));

			/* create new paragraph for RLNH */
			item = proto_tree_add_text(linx_tcp_tree, linx_tcp_tvb, offset, 4, "RLNH");
			rlnh_header_tree = proto_item_add_subtree(item, ett_linx_tcp);

			if(version == 1) {
				proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_msg_type32, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			} else {
				/*
				 * In version 2 of the rlnh protocol the length of the message type is
				 * restricted to 8 bits.
				 */
				proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_msg_reserved, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_msg_type8, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

			switch (dword) {
				case RLNH_LINK_ADDR:
					break;
				case RLNH_QUERY_NAME:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_src_linkaddr, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_name, linx_tcp_tvb, offset, -1, ENC_ASCII|ENC_NA);
					offset += tvb_strnlen(linx_tcp_tvb, offset, -1);
					break;
				case RLNH_PUBLISH:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_src_linkaddr, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_name, linx_tcp_tvb, offset, -1, ENC_ASCII|ENC_NA);
					offset += tvb_strnlen(linx_tcp_tvb, offset, -1);
					break;
				case RLNH_UNPUBLISH:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_src_linkaddr, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;
				case RLNH_UNPUBLISH_ACK:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_src_linkaddr, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					break;
				case RLNH_INIT:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_version, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					rlnh_version = tvb_get_ntohl(linx_tcp_tvb, offset);
					offset += 4;
					break;
				case RLNH_INIT_REPLY:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_status, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					if(rlnh_version > 1) {
						proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_feat_neg_str, linx_tcp_tvb, offset, -1, ENC_ASCII|ENC_NA);
						offset += tvb_strnlen(linx_tcp_tvb, offset, -1);
					}
					break;
				case RLNH_PUBLISH_PEER:
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_src_linkaddr, linx_tcp_tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					proto_tree_add_item(rlnh_header_tree, hf_linx_tcp_rlnh_peer_linkaddr, linx_tcp_tvb, offset, -1, ENC_BIG_ENDIAN);
					offset += tvb_strnlen(linx_tcp_tvb, offset, -1);
					break;
				default:
					/* No known Message type */
					proto_tree_add_text(rlnh_header_tree, linx_tcp_tvb, offset, 0, "ERROR: Header \"%u\" not recognized", dword);
					break;
			}
		} else {
			/* User payload */
			payloadsize = size-offset;
			if (payloadsize) {
				proto_tree_add_text(linx_tcp_tree, linx_tcp_tvb, offset, payloadsize, "%u bytes data", payloadsize);
			}
		}
	}
}

	void
proto_register_linx_tcp(void)
{
	static hf_register_info hf[] = {
		{ &hf_linx_tcp_reserved,
			{ "Reserved", "linx_tcp.reserved", FT_UINT32, BASE_DEC, NULL, 0x00007FFF, "TCP CM reserved", HFILL },
		},
		{ &hf_linx_tcp_oob,
			{ "Out-of-band", "linx_tcp.oob", FT_UINT32, BASE_DEC, NULL, 0x00008000, "TCP CM oob", HFILL },
		},
		{ &hf_linx_tcp_version,
			{ "Version", "linx_tcp.version", FT_UINT32, BASE_DEC, NULL, 0x00FF0000, "TCP CM version", HFILL },
		},
		{ &hf_linx_tcp_type,
			{ "Type", "linx_tcp.type", FT_UINT32, BASE_HEX, VALS(linx_long_tcp_names), 0xFF000000, "TCP CM type", HFILL },
		},
		{ &hf_linx_tcp_src,
			{ "Source", "linx_tcp.src", FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF, "TCP CM source", HFILL },
		},
		{ &hf_linx_tcp_dst,
			{ "Destination", "linx_tcp.dst", FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF, "TCP CM destination", HFILL },
		},
		{ &hf_linx_tcp_size,
			{ "Size", "linx_tcp.size", FT_UINT32, BASE_DEC, NULL, 0xFFFFFFFF, "TCP CM size", HFILL },
		},

		/* RLNH */
		{ &hf_linx_tcp_rlnh_msg_type32,
			{ "RLNH msg type", "linx_tcp.rlnh_msg_type", FT_UINT32, BASE_DEC, VALS(linx_long_rlnh_names), 0xffffffff, "RLNH message type", HFILL },
		},
		{ &hf_linx_tcp_rlnh_msg_type8,
			{ "RLNH msg type", "linx_tcp.rlnh_msg_type8", FT_UINT32, BASE_DEC, VALS(linx_long_rlnh_names), 0x000000ff, "RLNH message type", HFILL },
		},
		{ &hf_linx_tcp_rlnh_msg_reserved,
			{ "RLNH msg reserved", "linx_tcp.rlnh_msg_reserved", FT_UINT32, BASE_DEC, NULL, 0xffffff00, "RLNH message reserved", HFILL },
		},
		{ &hf_linx_tcp_rlnh_linkaddr,
			{ "RLNH linkaddr", "linx_tcp.rlnh_linkaddr", FT_UINT32, BASE_DEC, NULL, 0xffffffff, "RLNH linkaddress", HFILL },
		},
		{ &hf_linx_tcp_rlnh_src_linkaddr,
		        { "RLNH src linkaddr", "linx_tcp.rlnh_src_linkaddr", FT_UINT32, BASE_DEC, NULL, 0xffffffff, "RLNH source linkaddress", HFILL },
		},
		{ &hf_linx_tcp_rlnh_peer_linkaddr,
			{ "RLNH peer linkaddr", "linx_tcp.rlnh_peer_linkaddr", FT_UINT32,
				BASE_DEC, NULL, 0xffffffff, "RLNH peer linkaddress", HFILL },
		},
		{ &hf_linx_tcp_rlnh_version,
			{ "RLNH version", "linx_tcp.rlnh_version", FT_UINT32, BASE_DEC, NULL, 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_tcp_rlnh_status,
			{ "RLNH reply", "linx_tcp.rlnh_status", FT_UINT32, BASE_DEC, VALS(linx_rlnh_reply), 0xffffffff, NULL, HFILL },
		},
		{ &hf_linx_tcp_rlnh_name,
			{ "RLNH name", "linx_tcp.rlnh_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_linx_tcp_rlnh_feat_neg_str,
			{ "RLNH Feature Negotiation String", "linx_tcp.rlnh_feat_neg_str", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
		}
	};

	static gint *ett[] = {
		&ett_linx_tcp,
	};
	proto_linx_tcp = proto_register_protocol("ENEA LINX over TCP", "LINX/TCP", "linxtcp");
	proto_register_field_array(proto_linx_tcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_linx_tcp(void)
{
	dissector_handle_t linx_tcp_handle;
	linx_tcp_handle = create_dissector_handle(dissect_linx_tcp, proto_linx_tcp);
	dissector_add_uint("tcp.port", TCP_PORT_LINX, linx_tcp_handle);
}
