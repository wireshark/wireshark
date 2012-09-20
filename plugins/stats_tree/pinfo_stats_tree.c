/* pinfo_stats_tree.c
* Stats tree for ethernet frames
*
*  (c) 2005, Luis E. G. Ontanon <luis@ontanon.org>
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include <epan/stats_tree.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/uat-int.h>

#include "pinfo_stats_tree.h"

/* XXX: this belongs to to_str.c */
static const gchar* port_type_to_str (port_type type) {
	switch (type) {
		case PT_NONE:   return "NONE";
		case PT_SCTP:   return "SCTP";
		case PT_TCP:	return "TCP";
		case PT_UDP:	return "UDP";
		case PT_IPX:	return "IPX";
		case PT_NCP:	return "NCP";
		case PT_EXCHG:	return "FC EXCHG";
		case PT_DDP:	return "DDP";
		case PT_SBCCS:	return "FICON SBCCS";
		case PT_IDP:	return "IDP";
		default:	return "[Unknown]";
	}
}

/*-------------------------------------
 * UAT for Packet Lengths
 *-------------------------------------
 */
typedef struct {
  range_t *packet_range;
} uat_plen_record_t;

static range_t default_range[10] = {
	{1, {{0, 19}}},
	{1, {{20, 39}}},
	{1, {{40, 79}}},
	{1, {{80, 159}}},
	{1, {{160, 319}}},
	{1, {{320, 639}}},
	{1, {{640, 1279}}},
	{1, {{1280, 2559}}},
	{1, {{2560, 5119}}},
	{1, {{5120, 0xFFFFFFFF}}}
};
static uat_plen_record_t *uat_plen_records = NULL;
static uat_t * plen_uat = NULL;
static guint num_plen_uat = 0;

static void* uat_plen_record_copy_cb(void* n, const void* o, size_t siz _U_) {
	const uat_plen_record_t *r = o;
	uat_plen_record_t *rn = n;

	if (r->packet_range)
		rn->packet_range = range_copy(r->packet_range);

	return n;
}

static void uat_plen_record_free_cb(void*r) {
    uat_plen_record_t* record = (uat_plen_record_t*)r;

	if (record->packet_range) 
		g_free(record->packet_range);
}

static void uat_plen_record_post_update_cb(void) {
	guint i, num_default;
	uat_plen_record_t rec;

	/* If there are no records, create default list */
	if (num_plen_uat == 0) {
		num_default = sizeof(default_range)/sizeof(range_t);

		/* default values for packet lengths */
		for (i = 0; i < num_default; i++)
		{
			rec.packet_range = &default_range[i];
			uat_add_record(plen_uat, &rec);
		}
	}
}

UAT_RANGE_CB_DEF(uat_plen_records, packet_range, uat_plen_record_t)

/* ip host stats_tree -- basic test */
static int st_node_ip = -1;
static const gchar* st_str_ip = "IP Addresses";

static void ip_hosts_stats_tree_init(stats_tree* st) {
	st_node_ip = stats_tree_create_node(st, st_str_ip, 0, TRUE);
}

static int ip_hosts_stats_tree_packet(stats_tree *st  , packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_) {
	tick_stat_node(st, st_str_ip, 0, FALSE);
	tick_stat_node(st, ep_address_to_str(&pinfo->net_src), st_node_ip, FALSE);
	tick_stat_node(st, ep_address_to_str(&pinfo->net_dst), st_node_ip, FALSE);

	return 1;
}

/* packet type stats_tree -- test pivot node */
static int st_node_ptype = -1;
static const gchar* st_str_ptype = "IP Protocol Types";

static void ptype_stats_tree_init(stats_tree* st) {
	st_node_ptype = stats_tree_create_pivot(st, st_str_ptype, 0);
}

static int ptype_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t *edt _U_, const void *p _U_) {
	const gchar* ptype;

	ptype = port_type_to_str(pinfo->ptype);

	stats_tree_tick_pivot(st,st_node_ptype,ptype);

	return 1;
}

/* packet length stats_tree -- test range node */
static int st_node_plen = -1;
static const gchar* st_str_plen = "Packet Lengths";

static void plen_stats_tree_init(stats_tree* st) {
	guint i;
	char **str_range_array = ep_alloc(num_plen_uat*sizeof(char*));

	/* Convert the ranges to strings for the stats tree API */
	for (i = 0; i < num_plen_uat; i++) {
		str_range_array[i] = range_convert_range(uat_plen_records[i].packet_range);
	}

	st_node_plen = stats_tree_create_range_node_string(st, st_str_plen, 0, num_plen_uat, str_range_array);
}

static int plen_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t *edt _U_, const void *p _U_) {
	tick_stat_node(st, st_str_plen, 0, FALSE);
	stats_tree_tick_range(st, st_str_plen, 0, pinfo->fd->pkt_len);

	return 1;
}

/* a tree example
 - IP
    - PROTO
	   - PORT

*/
static int st_node_dsts = -1;
static const gchar* st_str_dsts = "IP Destinations";

static void dsts_stats_tree_init(stats_tree* st) {
	st_node_dsts = stats_tree_create_node(st, st_str_dsts, 0, TRUE);
}

static int dsts_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t *edt _U_, const void *p _U_) {
	static gchar str[128];
	int ip_dst_node;
	int protocol_node;

	tick_stat_node(st, st_str_dsts, 0, FALSE);

	ip_dst_node = tick_stat_node(st, ep_address_to_str(&pinfo->net_src), st_node_dsts, TRUE);

	protocol_node = tick_stat_node(st,port_type_to_str(pinfo->ptype),ip_dst_node,TRUE);

	g_snprintf(str, sizeof(str),"%u",pinfo->destport);
	tick_stat_node(st,str,protocol_node,TRUE);

	return 1;
}

/* register all pinfo trees */
void register_pinfo_stat_trees(void) {
	module_t *stat_module;

	static uat_field_t plen_uat_flds[] = {
		UAT_FLD_RANGE(uat_plen_records, packet_range, "Packet Range", 0xFFFFFFFF, "Range of packet sizes to count"),
		UAT_END_FIELDS
	};

    stats_tree_register_plugin("ip","ip_hosts",st_str_ip, 0, ip_hosts_stats_tree_packet, ip_hosts_stats_tree_init, NULL );
	stats_tree_register_plugin("ip","ptype",st_str_ptype, 0, ptype_stats_tree_packet, ptype_stats_tree_init, NULL );
	stats_tree_register_with_group("frame","plen",st_str_plen, 0, plen_stats_tree_packet, plen_stats_tree_init, NULL, REGISTER_STAT_GROUP_GENERIC );
	stats_tree_register_plugin("ip","dests",st_str_dsts, 0, dsts_stats_tree_packet, dsts_stats_tree_init, NULL );

	stat_module = prefs_register_stat("stat_tree", "Stats Tree", "Stats Tree", NULL);

	plen_uat = uat_new("Packet Lengths",
			sizeof(uat_plen_record_t),  /* record size */
			"packet_lengths",           /* filename */
			TRUE,                       /* from_profile */
			(void*) &uat_plen_records,  /* data_ptr */
			&num_plen_uat,              /* numitems_ptr */
			0,                          /* not a dissector, so affects neither dissection nor fields */
			NULL,                       /* help */
			uat_plen_record_copy_cb,    /* copy callback */
			NULL,                       /* update callback */
			uat_plen_record_free_cb,    /* free callback */
			uat_plen_record_post_update_cb, /* post update callback */
			plen_uat_flds);             /* UAT field definitions */

	prefs_register_uat_preference(stat_module, "packet_lengths",
		"Packet Lengths", "Delineated packet sizes to count", plen_uat);
}
