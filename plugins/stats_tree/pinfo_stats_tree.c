/* eth-stat_tree.c
* Stats tree for ethernet frames
*
*  (c) 2005, Luis E. G. Ontanon <luis.ontanon@gmail.com>
*
* $Id:  $
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
#include "config.h"
#endif

#include <epan/stats_tree.h>

static int st_node_pinfo_dl_src = -1;
static gchar* st_str_pinfo_dl_src = "link-layer source address";

static int st_node_pinfo_dl_dst = -1;
static gchar* st_str_pinfo_dl_dst = "link-layer destination address";

static int st_node_pinfo_net_src = -1;
static gchar* st_str_pinfo_net_src = "network-layer source address";

static int st_node_pinfo_net_dst = -1;
static gchar* st_str_pinfo_net_dst = "network-layer destination address";

static int st_node_pinfo_src = -1;
static gchar* st_str_pinfo_src = "source address (net if present, DL otherwise )";

static int st_node_pinfo_dst = -1;
static gchar* st_str_pinfo_dst = "destination address (net if present, DL otherwise )";

static int st_node_pinfo_ethertype = -1;
static gchar* st_str_pinfo_ethertype = "Ethernet Type Code, if this is an Ethernet packet";

static int st_node_pinfo_ipproto = -1;
static gchar* st_str_pinfo_ipproto = "IP protocol, if this is an IP packet";

static int st_node_pinfo_ipxptype = -1;
static gchar* st_str_pinfo_ipxptype = "IPX packet type, if this is an IPX packet";

static int st_node_pinfo_circuit_id = -1;
static gchar* st_str_pinfo_circuit_id = "circuit ID, for protocols with a VC identifier";

static int st_node_pinfo_srcport = -1;
static gchar* st_str_pinfo_srcport = "source port";

static int st_node_pinfo_destport = -1;
static gchar* st_str_pinfo_destport = "destination port";


static const gchar* port_type_to_str (port_type type) {
	switch (type) {
		case PT_NONE:   return NULL;
		case PT_SCTP:   return "SCTP";
		case PT_TCP:	return "TCP";
		case PT_UDP:	return "UDP";
		case PT_IPX:	return "IPX";
		case PT_NCP:	return "NCP";
		case PT_EXCHG: return "FC EXCHG";
		case PT_DDP: return "DDP";
		case PT_SBCCS: return "FICON SBCCS";
	}
	
	g_assert_not_reached();
	
	return NULL;
}

extern void pinfo_stats_tree_init(stats_tree* st)
{
	st_node_pinfo_dl_src = create_node(st, st_str_pinfo_dl_src, 0, TRUE);
	st_node_pinfo_dl_dst = create_node(st, st_str_pinfo_dl_dst, 0, TRUE);
	st_node_pinfo_net_src = create_node(st, st_str_pinfo_net_src, 0, TRUE);
	st_node_pinfo_net_dst = create_node(st, st_str_pinfo_net_dst, 0, TRUE);
	st_node_pinfo_src = create_node(st, st_str_pinfo_src, 0, TRUE);
	st_node_pinfo_dst = create_node(st, st_str_pinfo_dst, 0, TRUE);
	st_node_pinfo_ethertype = create_node(st, st_str_pinfo_ethertype, 0, TRUE);
	st_node_pinfo_ipproto = create_node(st, st_str_pinfo_ipproto, 0, TRUE);
	st_node_pinfo_ipxptype = create_node(st, st_str_pinfo_ipxptype, 0, TRUE);
	st_node_pinfo_circuit_id = create_node(st, st_str_pinfo_circuit_id, 0, TRUE);
	st_node_pinfo_srcport = create_node(st, st_str_pinfo_srcport, 0, TRUE);
	st_node_pinfo_destport = create_node(st, st_str_pinfo_destport, 0, TRUE);
}

extern int pinfo_stats_tree_packet(stats_tree *st  , packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_) {
	static guint8 str[128];
	const gchar* ptype;
	
	if (pinfo->dl_src.data) {
		tick_stat_node(st, st_str_pinfo_dl_src, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s",address_to_str(&pinfo->dl_src));
		tick_stat_node(st, str, st_node_pinfo_dl_src, FALSE);
	}
	
	if (pinfo->dl_dst.data) {
		tick_stat_node(st, st_str_pinfo_dl_dst, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s",address_to_str(&pinfo->dl_dst));
		tick_stat_node(st, str, st_node_pinfo_dl_dst, FALSE);
	}
	
	if (pinfo->net_src.data) {
		tick_stat_node(st, st_str_pinfo_net_src, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s",address_to_str(&pinfo->net_src));
		tick_stat_node(st, str, st_node_pinfo_net_src, FALSE);
	}
	
	if (pinfo->net_dst.data) {
		tick_stat_node(st, st_str_pinfo_net_dst, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s",address_to_str(&pinfo->net_dst));
		tick_stat_node(st, str, st_node_pinfo_net_dst, FALSE);
	}
	
	if (pinfo->src.data) {
		tick_stat_node(st, st_str_pinfo_src, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s",address_to_str(&pinfo->src));
		tick_stat_node(st, str, st_node_pinfo_src, FALSE);
	}
	
	if (pinfo->dst.data) {
		tick_stat_node(st, st_str_pinfo_dst, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s",address_to_str(&pinfo->dst));
		tick_stat_node(st, str, st_node_pinfo_dst, FALSE);
	}
	
	if (pinfo->ethertype) {
		tick_stat_node(st, st_str_pinfo_ethertype, 0, FALSE);
		g_snprintf(str, sizeof(str),"%u",pinfo->ethertype);
		tick_stat_node(st, str, st_node_pinfo_ethertype, FALSE);
	}
	
	if (pinfo->ipproto) {
		tick_stat_node(st, st_str_pinfo_ipproto, 0, FALSE);
		g_snprintf(str, sizeof(str),"%u",pinfo->ipproto);
		tick_stat_node(st, str, st_node_pinfo_ipproto, FALSE);
	}
	
	if (pinfo->ipxptype) {
		tick_stat_node(st, st_str_pinfo_ipxptype, 0, FALSE);
		g_snprintf(str, sizeof(str),"%u",pinfo->ipxptype);
		tick_stat_node(st, str, st_node_pinfo_ipxptype, FALSE);
	}
	
	if (pinfo->circuit_id) {
		tick_stat_node(st, st_str_pinfo_circuit_id, 0, FALSE);
		g_snprintf(str, sizeof(str),"%u",pinfo->circuit_id);
		tick_stat_node(st, str, st_node_pinfo_circuit_id, FALSE);
	}
	
	if (( ptype = port_type_to_str(pinfo->ptype) )) {
		tick_stat_node(st, st_str_pinfo_srcport, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s:%u",ptype,pinfo->srcport);
		tick_stat_node(st, str, st_node_pinfo_srcport, FALSE);
	
		tick_stat_node(st, st_str_pinfo_destport, 0, FALSE);
		g_snprintf(str, sizeof(str),"%s:%u",ptype,pinfo->destport);
		tick_stat_node(st, str, st_node_pinfo_destport, FALSE);
	}
	
	return 1;
}


